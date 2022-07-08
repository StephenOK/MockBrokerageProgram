#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

//define array maximum
#define ECHOMAX 255

//define RSA key parameters
#define prime1 227
#define prime2 401
#define publicE 77
#define privateD 44613

//structure to hold known public keys
struct externalKey{
    unsigned long int id, publicKey[3];
}
//list of all known public keys
contacts[ECHOMAX];

//length of public key list
int numContacts;

/**
 * Searches through the contact list for the indicated item
 *
 * param: idNum     Identification number of the desired contact
 * return:          Index of the desired item in contacts
 */
int findPrincipalID(unsigned long int idNum){
    //initialize output at unfound value
    int keyIndex = -1;

    //search each index of the contacts list
    for(int i = 0; i < numContacts; ++i)
        if(contacts[i].id == idNum){
            //set output to index if found
            keyIndex = i;
            break;
        }

    //return final output
    return keyIndex;
}

//message structure for message to the key manager
struct toKeyManager{
    //indicated action to key manager
    enum{register_key, request_key} requestType;

    //principal identifier
    unsigned long int principalID;

    //principal's public key
    unsigned long int publicKey[3];
}
//initialize message to key manager
sendKM;

//initialize length of key manager message
unsigned int sendKMSize;

//message structure for message from the key manger
struct fromKeyManager{
    //principal identifier
    unsigned long int principalID;

    //principal's public key
    unsigned long int publicKey[3];
}
//initialize message from key manager
recvKM;

//initialize length of message from key manager
unsigned int recvKMSize;

//message structure for message to the broker
struct toBroker{
    //indicated action to broker
    enum{buy, sell, verify} requestType;

    //identifier with the key manager
    unsigned long int clientID;

    //transaction identifier
    unsigned long int transactionID;

    //number of stocks for transaction
    unsigned long int numStocks;
}
//initialize message to broker
sendBroker;

//initialize length of message to broker
unsigned int sendBrSize;

//message structure for message from broker
struct fromBroker{
    //indicated action from broker
    enum{confirm, done} requestType;

    //identifier with the key manager
    unsigned long int clientID;

    //transaction identifier
    unsigned long int transactionID;

    //number of stocks for the transaction
    unsigned long int numStocks;
}
//initialize message from broker
recvBroker;

//initialize length of message from broker
unsigned int recvBrSize;

/**
 * Encrypts the sendBroker message with the given contact's public key
 *
 * param: serverIndex       Index of item in the contacts array
 */
void encryptBr(int serverIndex){
    //get initial values of sendBroker message
    unsigned int rtOriginal = sendBroker.requestType;
    unsigned long int idOriginal = sendBroker.clientID;
    unsigned long int tIDOriginal = sendBroker.transactionID;
    unsigned long int numOriginal = sendBroker.numStocks;

    //determine encryption n-value
    unsigned long int sid = contacts[serverIndex].publicKey[0] * contacts[serverIndex].publicKey[1];

    //get remainder of exponential value of each of the message attributes
    for(int i = 1; i < contacts[serverIndex].publicKey[2]; ++i){
        sendBroker.requestType *= rtOriginal;
        sendBroker.requestType %= sid;

        sendBroker.clientID *= idOriginal;
        sendBroker.clientID %= sid;

        sendBroker.transactionID *= tIDOriginal;
        sendBroker.transactionID %= sid;

        sendBroker.numStocks *= numOriginal;
        sendBroker.numStocks %= sid;
    }
}

/**
 * Decrypts the recvBroker message
 */
void decryptBr(){
    //get initial values of recvBroker message
    unsigned int rtOriginal = recvBroker.requestType;
    unsigned long int idOriginal = recvBroker.clientID;
    unsigned long int tIDOriginal = recvBroker.transactionID;
    unsigned long int numOriginal = recvBroker.numStocks;

    //determine decryption n-value
    unsigned long int n = prime1 * prime2;

    //get remainder of exponential value of each of the message attributes
    for(int i = 1; i < privateD; ++i){
        recvBroker.requestType *= rtOriginal;
        recvBroker.requestType %= n;

        recvBroker.clientID *= idOriginal;
        recvBroker.clientID %= n;

        recvBroker.transactionID *= tIDOriginal;
        recvBroker.transactionID %= n;

        recvBroker.numStocks *= numOriginal;
        recvBroker.numStocks %= n;
    }
}






int main(int argc, char * argv[]){
    //initialize sending socket identifier
    int sock;

    //initialize output address parameters
    struct sockaddr_in outAddr;
    char * outIP;
    unsigned short outPort;
    int outAddrLen;

    //initialize receiving address parameters
    struct sockaddr_in fromAddr;
    unsigned int fromSize;

    //initialize message receiver length
    unsigned int recvLen;

    //initialize user input string
    char instruction[ECHOMAX];

    //check if appropriate number of arguments used
    if((argc < 2) || (argc > 3)){
        //notify user of action failure
        fprintf(stderr, "Usage: %s <Key Manager IP> [Echo Port>]\n", argv[0]);
        exit(1);
    }

    //notify user of startup
    printf("Booting brokerage client program...\n");

    //set key manager's IP
    outIP = argv[1];

    //if key manager port given
    if(argc == 3)
        //set key manager's port number
        outPort = atoi(argv[2]);
    else
        //otherwise, default to port 7
        outPort = 7;

    //create socket
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
        perror("Failed to establish key manager socket");
        exit(1);
    }

    //define output address as key manager's address
    memset(&outAddr, 0, sizeof(outAddr));
    outAddr.sin_family = AF_INET;
    outAddr.sin_addr.s_addr = inet_addr(outIP);
    outAddr.sin_port = htons(outPort);

    //set address size
    outAddrLen = sizeof(outAddr);

    //set register key message parameters
    sendKM.requestType = register_key;
    sendKM.principalID = 0;
    sendKM.publicKey[0] = prime1;
    sendKM.publicKey[1] = prime2;
    sendKM.publicKey[2] = publicE;

    //set message size
    sendKMSize = sizeof(sendKM);

    //notify user of send action
    printf("Sending public key to manager...\n");

    //send register message to key manager
    if(sendto(sock, &sendKM, sendKMSize, 0, (struct sockaddr *) &outAddr, outAddrLen) != sendKMSize){
        perror("Failed to send register message");
        exit(1);
    }

    //set receive message size
    recvKMSize = sizeof(recvKM);

    //set from message size
    fromSize = sizeof(fromAddr);

    //wait to receive message
    if((recvLen = recvfrom(sock, &recvKM, recvKMSize, 0, (struct sockaddr *) &fromAddr, &fromSize)) < 0){
        perror("Key registration failed: received bad acknowledgement");
        exit(1);
    }

    //check that message is received from the contacted key manager
    if(outAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr){
        perror("Key registration failed: received a packet from unknown source!");
        exit(1);
    }

    //check that received key is identical
    if(recvKM.publicKey[0] != sendKM.publicKey[0] ||
        recvKM.publicKey[1] != sendKM.publicKey[1] ||
        recvKM.publicKey[2] != sendKM.publicKey[2]){
            //notify of failed process
            printf("Key registration failed: returned key does not match!\n");
            exit(1);
        }

    //notify of successful registration
    printf("Key successfully registered!\n");
    printf("PrincipalID: %lu\n", recvKM.principalID);

    //get registered value in key manger
    unsigned long int kmIndex = recvKM.principalID;

    //initialize contact list
    numContacts = 0;

    for(;;){
        //label to exit failed processes
        top:

        //prompt for user input
        printf("\nInput your next action:\n");
        scanf("%s", instruction);

        //user makes a request
        if(strcmp(instruction, "request") == 0){
            //get key manager's IP
            outIP = argv[1];

            //get key manager's port
            if(argc == 3)
                outPort = atoi(argv[2]);
            else
                outPort = 7;
            
            //set key manager's address
            memset(&outAddr, 0, sizeof(outAddr));
            outAddr.sin_family = AF_INET;
            outAddr.sin_addr.s_addr = inet_addr(outIP);
            outAddr.sin_port = htons(outPort);

            //set address length
            outAddrLen = sizeof(outAddr);

            //clear send message
            memset(&sendKM, 0, sizeof(sendKM));
            
            //declare message as request_key message
            sendKM.requestType = request_key;

            //get user's input for principal ID item
            scanf("%lu", &sendKM.principalID);

            //set message size
            sendKMSize = sizeof(sendKM);

            //notify user of request sent
            printf("\nRequesting key at index %d from key manager...\n", sendKM.principalID);

            //send request message to key manager
            if(sendto(sock, &sendKM, sendKMSize, 0, (struct sockaddr *) &outAddr, outAddrLen) != sendKMSize){
                perror("Failed to send request message");
                goto top;
            }

            //wait to receive message
            if((recvLen = recvfrom(sock, &recvKM, recvKMSize, 0, (struct sockaddr *) &fromAddr, &fromSize)) < 0){
                perror("Key request failed: received bad acknowledgement");
                goto top;
            }

            //check that message is received from contacted key manager
            if(outAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr){
                perror("Key requests failed: received a packet from unknown source!");
                goto top;
            }

            //check if requested item exists in key manager
            if(recvKM.publicKey[0] == 0){
                printf("No item found at index %lu\n", recvKM.principalID);
                goto top;
            }

            //add received item to contacts array
            contacts[numContacts].id = recvKM.principalID;
            contacts[numContacts].publicKey[0] = recvKM.publicKey[0];
            contacts[numContacts].publicKey[1] = recvKM.publicKey[1];
            contacts[numContacts].publicKey[2] = recvKM.publicKey[2];

            //notify user of added item
            printf("Received key %d for item [%d, %d]\n", contacts[numContacts].publicKey[2], contacts[numContacts].publicKey[0], contacts[numContacts].publicKey[1]);

            //increment contacts counter
            ++numContacts;
        }

        //user wants to make a stock transaction
        else if(strcmp(instruction, "buy") == 0 || strcmp(instruction, "sell") == 0){
            //initialize broker's key manager identification number
            unsigned long int servItem;

            //clear message to broker
            memset(&sendBroker, 0, sizeof(sendBroker));

            //get user's input for id
            scanf("%lu", &(servItem));

            //get user's input for broker IP
            scanf("%s", outIP);

            //get user's input for broker port
            scanf("%d", &outPort);

            //get user's input for stocks to 
            scanf("%d", &sendBroker.numStocks);

            //find key manager id in contacts list
            int servIndex;
            if((servIndex = findPrincipalID(servItem)) < 0){
                printf("\nServer item not found on record.\n");
                goto top;
            }

            //set out address to broker's address
            memset(&outAddr, 0, sizeof(outAddr));
            outAddr.sin_family = AF_INET;
            outAddr.sin_addr.s_addr = inet_addr(outIP);
            outAddr.sin_port = htons(outPort);

            //set out address' length
            outAddrLen = sizeof(outAddr);

            //set request type to buy or sell
            if(strcmp(instruction, "buy") == 0)
                sendBroker.requestType = buy;
            else
                sendBroker.requestType = sell;

            //set client's id in key manager
            sendBroker.clientID = kmIndex;

            //initialize transaction id to "new transaction" value
            sendBroker.transactionID = 0;

            //set message size
            sendBrSize = sizeof(sendBroker);

            printf("\nSending transaction request to broker...\n");

            //encrypt message
            encryptBr(servIndex);

            //send message to broker
            if(sendto(sock, &sendBroker, sendBrSize, 0, (struct sockaddr *) &outAddr, outAddrLen) != sendBrSize){
                perror("Failed to send transaction message");
                goto top;
            }

            //clear receiving message
            memset(&recvBroker, 0, sizeof(recvBroker));

            //set message size
            recvBrSize = sizeof(recvBroker);

            //await message from broker
            if((recvLen = recvfrom(sock, &recvBroker, recvBrSize, 0, (struct sockaddr *) &fromAddr, &fromSize)) < 0){
                perror("Received bad acknowledgement");
                goto top;
            }

            //check that response came from broker
            if(outAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr){
                perror("Received a packet from unknown source!");
                goto top;
            }

            //decrypt given message
            decryptBr();

            //check that process completed in broker
            if(recvBroker.requestType == done){
                printf("An error occured and the transaction was not instantiated.\n");
                goto top;
            }

            //clear message to broker
            memset(&sendBroker, 0, sizeof(sendBroker));

            //prepare values for verify message to broker
            sendBroker.requestType = verify;
            sendBroker.clientID = recvBroker.clientID;
            sendBroker.transactionID = recvBroker.transactionID;

            //create string to display confirm action
            char checkInstruction [ECHOMAX];
            if(recvBroker.requestType == buy)
                strcpy(checkInstruction, "buy");
            else
                strcpy(checkInstruction , "sell");

            for(;;){
                //prompt user for confirmation
                printf("Confirm order (Y/N): %s %lu stock(s)\n", checkInstruction, recvBroker.numStocks);

                //get user input
                char userInput[ECHOMAX];
                scanf("%s", userInput);

                //if user confirms transaction
                if(strcmp(userInput, "Y") == 0 || strcmp(userInput, "y") == 0){
                    //place transaction amount into verification message
                    sendBroker.numStocks = recvBroker.numStocks;
                    break;
                }
        
                //if user denies transaction
                else if(strcmp(userInput, "N") == 0 || strcmp(userInput, "n") == 0){
                    //clear transaction amount
                    sendBroker.numStocks = 0;
                    break;
                }

                //invalid input given
                else
                    printf("Invalid input.\n");
            }

            //encrypt verification message
            encryptBr(servIndex);

            //notify user of sent message
            printf("Sending verification...\n");

            //send broker verification message
            if(sendto(sock, &sendBroker, sendBrSize, 0, (struct sockaddr *) &outAddr, outAddrLen) != sendBrSize){
                perror("Failed to send verification message");
                goto top;
            }

            //clear message from broker
            memset(&recvBroker, 0, sizeof(recvBroker));
            recvBrSize = sizeof(recvBroker);

            //wait for response
            if((recvLen = recvfrom(sock, &recvBroker, recvBrSize, 0, (struct sockaddr *) &fromAddr, &fromSize)) < 0){
                perror("Received bad acknowledgement");
                goto top;
            }

            //check that response if from broker
            if(outAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr){
                perror("Received a packet from unknown source!");
                goto top;
            }

            //decrypt message
            decryptBr();

            printf("Message type: %d\n", recvBroker.requestType);

            //confirm that transaction is complete
            if(recvBroker.requestType == done)
                printf("Transfer complete!\n");
            else   
                printf("An error occured with transfer\n");
        }

        //if user wants to close program
        else if(strcmp(instruction, "exit") == 0){
            //notify user of process end
            printf("\nClosing program...\n");
            break;
        }

        //notify of invalid input given
        else{
            printf("\nNo command for %s\n", instruction);
        }
    }

    exit(0);
}