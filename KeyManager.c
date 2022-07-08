#include <stdio.h>
#include <math.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//define array maximum
#define ECHOMAX 255

//message structure for message from a principal
struct fromPrincipal{
    //indicated action from principal
    enum{register_key, request_key} requestType;

    //principal identifier
    unsigned long int principalID;

    //principal's public key
    unsigned long int publicKey[3];
}
//initialize message receiver
recvMessage,

//initialize list of public keys
contacts[ECHOMAX];

//track number of held public keys
unsigned int numContacts;

//message structure for message to a principal
struct toPrincipal{
    //principal identifier
    unsigned long int principalID;

    //principal's public key
    unsigned long int publicKey[3];
} 
//initialize message sender
sendMessage;






int main(int argc, char * argv[]){
    //initialize receiving socket identifier
    int sock;

    //initialize own address parameters
    struct sockaddr_in echoKMAddr;
    unsigned short echoKMPort;

    //initialize contact address parameters
    struct sockaddr_in echoClntAddr;
    int cliAddrLen = sizeof(echoClntAddr);

    //initialize message lengths
    unsigned int recvLen;
    unsigned int sendLen;

    //initialize structure sizes
    unsigned int recvStructSize = sizeof(struct fromPrincipal);
    unsigned int sendStructSize = sizeof(struct toPrincipal);

    //check if appropriate number of arguments used
    if(argc != 2){
        //notify user of action failure
        fprintf(stderr, "Usage: %s <UDP SERVER PORT>\n", argv[0]);
        exit(1);
    }

    //notify user of startup
    printf("Booting key manager program...\n");

    //set key manager's port
    echoKMPort = atoi(argv[1]);

    //create socket
    if((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
        fprintf(stderr, "socket() failed\n");
        exit(1);
    }

    //establish port parameters
    memset(&echoKMAddr, 0, sizeof(echoKMAddr));
    echoKMAddr.sin_family = AF_INET;
    echoKMAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    echoKMAddr.sin_port = htons(echoKMPort);

    //bind socket
    if(bind(sock, (struct sockaddr *) &echoKMAddr, sizeof(echoKMAddr)) < 0){
        perror("bind() failed");
        exit(1);
    }

    //initialize contact counter
    numContacts = 0;

    for(;;){
        //label to exit failed processes
        top:

        //clear message items
        memset(&recvMessage, 0, sizeof(recvMessage));
        memset(&sendMessage, 0, sizeof(sendMessage));

        //notify user of ready state
        printf("\nReady and waiting for message...\n");

        //receive message from a principal
        if((recvLen = recvfrom(sock, &recvMessage, recvStructSize, 0, (struct sockaddr *) &echoClntAddr, &cliAddrLen)) < 0){
            printf("\nBad message received!\n");
            goto top;
        }

        //notify of message received
        printf("\nMessage received from principal: ");

        //principal is registering their key with the manager
        if(recvMessage.requestType == register_key){
            //notify of registration occuring
            printf("Registering public key...\n");

            //put received key items in new contact index
            contacts[numContacts].principalID = numContacts;
            contacts[numContacts].publicKey[0] = recvMessage.publicKey[0];
            contacts[numContacts].publicKey[1] = recvMessage.publicKey[1];
            contacts[numContacts].publicKey[2] = recvMessage.publicKey[2];

            //notify and test for properly inputted values
            printf("Registered items [%lu, %lu] and %lu\n", contacts[numContacts].publicKey[0], contacts[numContacts].publicKey[1], contacts[numContacts].publicKey[2]);
            
            //prepare acknowledgement message
            sendMessage.principalID = contacts[numContacts].principalID;
            sendMessage.publicKey[0] = contacts[numContacts].publicKey[0];
            sendMessage.publicKey[1] = contacts[numContacts].publicKey[1];
            sendMessage.publicKey[2] = contacts[numContacts].publicKey[2];
            sendLen = sizeof(sendMessage);

            //notify user of confirmation sent
            printf("Sending acknowledgement to caller...\n");

            //send acknowledgement to original caller
            if(sendto(sock, &sendMessage, sendLen, 0, (struct sockaddr *) &echoClntAddr, cliAddrLen) < 0){
                perror("Confirm register failed");
                goto top;
            }

            //increment number of held keys
            ++numContacts;
        }

        //principal is requesting a public key
        else if(recvMessage.requestType == request_key){
            //notify of request occuring
            printf("Retreiving desired key...\n");

            //start return message
            sendMessage.principalID = recvMessage.principalID;

            //if desired object not in list
            if(recvMessage.principalID >= numContacts){
                //notify of failed request
                printf("Requested key not found!\n");

                //create failure message
                sendMessage.publicKey[0] = 0;
                sendMessage.publicKey[1] = 0;
                sendMessage.publicKey[2] = 0;
            }

            else{
                //retreive data from contact list
                sendMessage.publicKey[0] = contacts[recvMessage.principalID].publicKey[0];
                sendMessage.publicKey[1] = contacts[recvMessage.principalID].publicKey[1];
                sendMessage.publicKey[2] = contacts[recvMessage.principalID].publicKey[2];

                //notify of found item
                printf("Item found: [%lu, %lu], %lu\n", sendMessage.publicKey[0], sendMessage.publicKey[1], sendMessage.publicKey[2]);                
            }

            //notify user of sent message
            printf("Sending outcome to caller...\n");

            //send message to caller
            sendLen = sizeof(sendMessage);
            if(sendto(sock, &sendMessage, sendLen, 0, (struct sockaddr *) &echoClntAddr, cliAddrLen) < 0){
                perror("Failed to send request data: ");
            }
        }

        //catch invalid action
        else{
            printf("Message received has no acion.\n");
        }
    }
}