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
#define prime1 523
#define prime2 653
#define privateD 250607
#define publicE 311

//structure for a user's stock account
struct account{
    //id of a client with the key manager
    unsigned long int cliID;

    //client's RSA key
    unsigned long int publicKey[3];

    //number of stocks held by the client
    unsigned int heldStocks;
}
//initialize list of clients
members[ECHOMAX];

//initialize client list counter
unsigned int memberCount;

/**
 * Find the indicated key manager id in the broker's account list
 *
 * param: inputID       Key manager id to find
 * return:              Index of the account
 */
int findAccount(unsigned long int inputID){
    //initialize index at unfound value
    int index = -1;

    //check each index for the given id
    for(int i = 0; i < memberCount; ++i)
        //set output to index if found
        if(members[i].cliID == inputID){
            index = i;
            break;
        }
    
    //return final output
    return index;
}

//message structure for message to the key manager
struct toKeyManager{
    //indicated action to the key manager
    enum{register_key, request_key} requestType;

    //principal identifier
    unsigned long int principalID;

    //principal's public key
    unsigned long int publicKey[3];
}
//initialize message to key manager
sendKM;

//initialize length of the key manager message
unsigned int sendKMSize;

//message structure for message from the key maager
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

//message structure for message to client
struct toClient{
    //indicated action to the client
    enum{confirm, done} requestType;

    //identifier with the key manager
    unsigned long int clientID;

    //transaction identifier
    unsigned long int transactionID;

    //number of stocks for the transaction
    unsigned long int numStocks;
}
//initialize message to the client
sendClient;

//initialize length of message to client
unsigned int sendClSize;

//message structure for message from the client
struct fromClient{
    //indicated action from the client
    enum{buy, sell, verify} requestType;

    //identifier with the key manager
    unsigned long int clientID;

    //transaction identifier
    unsigned long int transactionID;

    //number of stocks for transaction
    unsigned long int numStocks;
}
//initialize message from client
recvClient,
//list of active transactions with clients
activeTransactions[ECHOMAX];

//initialize length of message from client
unsigned int recvClSize,
//initialize number of active transactions
numTransactions;

/**
 * Finds the location of a desired transaction in the activeTransactions list
 *
 * param: tID       Transaction ID number to find
 * return:          Index of the desired ID
 */
int findTID(int tID){
    //search for ID in activeTransactions array
    for(int i = 0; i < numTransactions; ++i)
        //if found, return index
        if(activeTransactions[i].transactionID == tID)
            return i;

    //return not found number
    return -1;
}

/**
 * Gets the next transactionID available for the list
 *
 * return:  Next available ID number
 */
int getNextTID(){
    //initialize index of give ID
    int tidIndex;

    //initialize output
    int i;

    //increment through viable ID's for the lsit
    for(i = 0; i < numTransactions; ++i){
        //if no ID with the given number found, return that number
        if((tidIndex = findTID(i)) < 0)
            return i;
    }

    //return highest number available
    return i;
}

/**
 * Remove a transaction from the active transactions list
 *
 * param: tID       ID of the transaction to be removed
 */
void closeTransaction(int tID){
    //starting at the index of the identified transaction
    for(int i = findTID(tID); i < numTransactions - 1; ++i){
        //shift active items to the next lowest index
        activeTransactions[i].requestType = activeTransactions[i+1].requestType;
        activeTransactions[i].clientID = activeTransactions[i+1].clientID;
        activeTransactions[i].transactionID = activeTransactions[i+1].transactionID;
        activeTransactions[i].numStocks = activeTransactions[i+1].numStocks;
    }

    //cut off the last item
    --numTransactions;
}

/**
 * Encrypts a message with a client's RSA key
 *
 * param: memberIndex       Index of the client to encrypt the message to
 */
void encryptCl(int memberIndex){
    //get initial values of sendClient message
    unsigned int rtOriginal = sendClient.requestType;
    unsigned long int idOriginal = sendClient.clientID;
    unsigned long int tIDOriginal = sendClient.transactionID;
    unsigned long int numOriginal = sendClient.numStocks;

    //determine encryption n-value
    unsigned long int cid = members[memberIndex].publicKey[0] * members[memberIndex].publicKey[1];

    //get remainder of exponential value of each of the message attributes
    for(int i = 1; i < members[memberIndex].publicKey[2]; ++i){
        sendClient.requestType *= rtOriginal;
        sendClient.requestType %= cid;

        sendClient.clientID *= idOriginal;
        sendClient.clientID %= cid;

        sendClient.transactionID *= tIDOriginal;
        sendClient.transactionID %= cid;

        sendClient.numStocks *= numOriginal;
        sendClient.numStocks %= cid;
    }
}

/**
 * Decrypts the recvClient message
 */
void decryptCl(){
    //get initial values of recvClient message
    unsigned long int rtOriginal = recvClient.requestType;
    unsigned long int idOriginal = recvClient.clientID;
    unsigned long int tIDOriginal = recvClient.transactionID;
    unsigned long int numOriginal = recvClient.numStocks;

    //give more memory to the enumeration outcome
    unsigned long int placeHolder = recvClient.requestType;

    //determine decryption n-value
    unsigned long int n = prime1 * prime2;

    //get remainder of exponential value of each of the message attributes
    for(int i = 1; i < privateD; ++i){
        placeHolder *= rtOriginal;
        placeHolder %= n;

        recvClient.clientID *= idOriginal;
        recvClient.clientID %= n;

        recvClient.transactionID *= tIDOriginal;
        recvClient.transactionID %= n;

        recvClient.numStocks *= numOriginal;
        recvClient.numStocks %= n;
    }

    //place decrypted request type into the received message
    recvClient.requestType = placeHolder;
}






int main(int argc, char * argv[]){
    //initialize socket identifiers
    int kmSock, cliSock;

    //initialize key manager output address parameters
    struct sockaddr_in outKMAddr;
    char * outKMIP;
    unsigned short outKMPort;
    int outKMAddrLen;

    //initialize own address and port
    struct sockaddr_in servAddr;
    unsigned short servPort;

    //initialize receiving address parameters
    struct sockaddr_in fromAddrKM, fromAddrC;
    unsigned int fromSizeKM, fromSizeC;

    //initialize message receiver length
    unsigned int recvLen;

    //check if appropriate number of arguments used
    if((argc < 3) || (argc > 4)){
        //notify user of action failure
        fprintf(stderr, "Usage: %s <UDP Server Port> <Key Manager IP> [<EchoPort>]\n", argv[0]);
        exit(1);
    }

    //notify user of startup
    printf("Booting brokerage server program...\n");

    //set key manager's IP
    outKMIP = argv[2];

    //if key manager port given
    if(argc == 4)
        //set key manager's port number
        outKMPort = atoi(argv[3]);
    else
        //otherwise, default to port 7
        outKMPort = 7;

    //create socket to key manager
    if((kmSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
        perror("socket() for KM failed");
        exit(1);
    }

    //create socket to client
    if((cliSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
        perror("socket() for client failed");
        exit(1);
    }

    //define key manager output address
    memset(&outKMAddr, 0, sizeof(outKMAddr));
    outKMAddr.sin_family = AF_INET;
    outKMAddr.sin_addr.s_addr = inet_addr(outKMIP);
    outKMAddr.sin_port = htons(outKMPort);

    //set address size
    outKMAddrLen = sizeof(outKMAddr);

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
    if(sendto(kmSock, &sendKM, sendKMSize, 0, (struct sockaddr *) &outKMAddr, outKMAddrLen) != sendKMSize){
        perror("Failed to send register message");
        exit(1);
    }

    //set receive message size
    recvKMSize = sizeof(recvKM);

    //set both from message sizes
    fromSizeKM = sizeof(fromAddrKM);
    fromSizeC = sizeof(fromAddrC);

    //wait to receive message
    if((recvLen = recvfrom(kmSock, &recvKM, recvKMSize, 0, (struct sockaddr *) &fromAddrKM, &fromSizeKM)) < 0){
        perror("Key registration failed: received bad acknowledgement");
        exit(1);
    }

    //check that message is received from the contacted key manager
    if(outKMAddr.sin_addr.s_addr != fromAddrKM.sin_addr.s_addr){
        perror("Key registration failed: received a packet from unknown source!");
        exit(1);
    }

    //check that received key is identical
    if(recvKM.publicKey[0] != sendKM.publicKey[0] ||
        recvKM.publicKey[1] != sendKM.publicKey[1] ||
        recvKM.publicKey[2] != sendKM.publicKey[2]){
            printf("Key registration failed: returned key does not match!\n");
            exit(1);
    }

    //notify of successful registration
    printf("Key successfully registered!\n");
    printf("PrincipalID: %lu\n", recvKM.principalID);

    //set server port
    servPort = atoi(argv[1]);

    //set broker address parameters
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(servPort);

    //bind broker address
    if(bind(cliSock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0){
        perror("Client socket bind failed");
        exit(1);
    }

    //set client message sizes
    recvClSize = sizeof(recvClient);
    sendClSize = sizeof(sendClient);

    //initialize member and transaction count
    memberCount = 0;
    numTransactions = 0;

    for(;;){
        //label to exit failed processes
        top:

        //clear messages to and from the client
        memset(&sendClient, 0, sizeof(sendClient));
        memset(&recvClient, 0, sizeof(recvClient));

        //notify user of ready state
        printf("\nReady and waiting for message...\n");

        //await message from a client
        if((recvLen = recvfrom(cliSock, &recvClient, recvClSize, 0, (struct sockaddr *) &fromAddrC, &fromSizeC)) < 0){
            perror("\nBad message received");
            goto top;
        }

        //decrypt received message
        decryptCl();

        //notify of message received
        printf("\nMessage received from client: ");

        //contacting client is making a new transaction
        if(recvClient.requestType == buy || recvClient.requestType == sell){
            //notify of transaction occuring
            printf("New transaction to be made...\n");

            //initialize member location in account array
            int cliIndex;

            //check if user has an account
            if((cliIndex = findAccount(recvClient.clientID)) < 0){
                //clear messages to and from key manager
                memset(&sendKM, 0, sizeof(sendKM));
                memset(&recvKM, 0, sizeof(recvKM));

                //fill data for key request
                sendKM.requestType = request_key;
                sendKM.principalID = recvClient.clientID;

                //send request to key manager
                if(sendto(kmSock, &sendKM, sendKMSize, 0, (struct sockaddr *) &outKMAddr, outKMAddrLen) != sendKMSize){
                    perror("Failed to send request to key manager");
                    
                    //set sent message to done
                    memset(&sendClient, 0, sizeof(sendClient));
                    sendClient.requestType = done;

                    //send message to client
                    if(sendto(cliSock, &sendClient, sendClSize, 0, (struct sockaddr *) &fromAddrC, fromSizeC) != sendClSize){
                        perror("Failed to send confirm to client");
                    }

                    goto top;
                }

                //await response from key manager
                if((recvLen = recvfrom(kmSock, &recvKM, recvKMSize, 0, (struct sockaddr *) &fromAddrKM, &fromSizeKM)) < 0){
                    perror("Received bad acknowledgement");

                    //set sent message to done
                    memset(&sendClient, 0, sizeof(sendClient));
                    sendClient.requestType = done;

                    //send message to client
                    if(sendto(cliSock, &sendClient, sendClSize, 0, (struct sockaddr *) &fromAddrC, fromSizeC) != sendClSize){
                        perror("Failed to send confirm to client");
                    }

                    goto top;
                }

                //check that message received from contacted key manager
                if(outKMAddr.sin_addr.s_addr != fromAddrKM.sin_addr.s_addr){
                    perror("Received a packet from unknown source!");

                    //set sent message to done
                    memset(&sendClient, 0, sizeof(sendClient));
                    sendClient.requestType = done;

                    //send message to client
                    if(sendto(cliSock, &sendClient, sendClSize, 0, (struct sockaddr *) &fromAddrC, fromSizeC) != sendClSize){
                        perror("Failed to send confirm to client");
                    }

                    goto top;
                }

                //client identifier number not found in key manager
                if(recvKM.publicKey[0] == 0){
                    printf("No item found for item %lu\n", recvKM.principalID);

                    //set sent message to done
                    memset(&sendClient, 0, sizeof(sendClient));
                    sendClient.requestType = done;

                    //send message to client
                    if(sendto(cliSock, &sendClient, sendClSize, 0, (struct sockaddr *) &fromAddrC, fromSizeC) != sendClSize){
                        perror("Failed to send confirm to client");
                    }

                    goto top;
                }

                //create member account with ID, RSA key, and new stock count
                members[memberCount].cliID = recvKM.principalID;
                members[memberCount].publicKey[0] = recvKM.publicKey[0];
                members[memberCount].publicKey[1] = recvKM.publicKey[1];
                members[memberCount].publicKey[2] = recvKM.publicKey[2];
                members[memberCount].heldStocks = 0;

                //set client index to new item
                cliIndex = memberCount;

                //increment member count
                ++memberCount;
            }

            //if stock sale, make sure quantity is available
            if(recvClient.requestType == sell && members[cliIndex].heldStocks < recvClient.numStocks){
                printf("Client has insufficient stocks to sell\n");

                //set sent message to done
                memset(&sendClient, 0, sizeof(sendClient));
                sendClient.requestType = done;

                //send message to client
                if(sendto(cliSock, &sendClient, sendClSize, 0, (struct sockaddr *) &fromAddrC, fromSizeC) != sendClSize){
                    perror("Failed to send confirm to client");
                }

                goto top;
            }

            //create a new active transaction
            activeTransactions[numTransactions].requestType = recvClient.requestType;
            activeTransactions[numTransactions].clientID = recvClient.clientID;
            activeTransactions[numTransactions].transactionID = getNextTID();
            activeTransactions[numTransactions].numStocks = recvClient.numStocks;

            //create send message for confirmation with active transaction properties
            sendClient.requestType = confirm;
            sendClient.clientID = activeTransactions[numTransactions].clientID;
            sendClient.transactionID = activeTransactions[numTransactions].transactionID;
            sendClient.numStocks = activeTransactions[numTransactions].numStocks;

            char saleType[ECHOMAX];
            if(activeTransactions[numTransactions].requestType == buy)
                strcpy(saleType, "buy");
            else
                strcpy(saleType, "sell");

            //notify of transaction created
            printf("New transaction created: %s %lu stock(s)\n", saleType, sendClient.numStocks);

            //increment number of active transactions
            ++numTransactions;

            //encrypt message
            encryptCl(cliIndex);

            //notify of message sent
            printf("Sending confirmation message to client...\n");

            //send confirmation message to client
            if(sendto(cliSock, &sendClient, sendClSize, 0, (struct sockaddr *) &fromAddrC, fromSizeC) != sendClSize){
                perror("Failed to send confirm to client");
            }            
        }

        //contacting client is verifying an active transaction
        else if (recvClient.requestType == verify){
            //notify of transaction verification
            printf("Transaction confirmed!\n");

            //find client and transaction identification
            int clientIndex = findAccount(recvClient.clientID);
            int transID = findTID(recvClient.transactionID);

            if(clientIndex < 0 || transID < 0){
                printf("Either client or transaction no longer exists. Can not commit action\n");

                //set sent message to done
                memset(&sendClient, 0, sizeof(sendClient));
                sendClient.requestType = confirm;

                //send message to client
                if(sendto(cliSock, &sendClient, sendClSize, 0, (struct sockaddr *) &fromAddrC, fromSizeC) != sendClSize){
                    perror("Failed to send confirm to client");
                }

                goto top;
            }

            //appropriately modify stocks as indicated
            if(activeTransactions[transID].requestType == buy)
                members[clientIndex].heldStocks = members[clientIndex].heldStocks + recvClient.numStocks;
            else
                members[clientIndex].heldStocks -= recvClient.numStocks;

            //notify of exchange occurance
            printf("Stocks for user %lu set to %lu\n", recvClient.clientID, members[clientIndex].heldStocks);

            //remove transaction from active list
            closeTransaction(recvClient.transactionID);

            //prepare done message for client
            sendClient.requestType = done;
            sendClient.clientID = recvClient.clientID;
            sendClient.transactionID = recvClient.transactionID;
            sendClient.numStocks = recvClient.numStocks;

            //encrypt message
            encryptCl(clientIndex);

            //notify of sent message
            printf("Notifying client of completion...\n");

            //send done message to client
            if(sendto(cliSock, &sendClient, sendClSize, 0, (struct sockaddr *) &fromAddrC, fromSizeC) != sendClSize){
                perror("Failed to send completion message to client");
                goto top;
            }            
        }

        //invalid argument from client given
        else{
            printf("Invalid message type received\n");
        }
    }
}