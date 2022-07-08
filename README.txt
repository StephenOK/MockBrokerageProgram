NOTE: Some elements of the code have been lifted from the Sample Socket Code from the COSC 439 files page, specifically the UDP files. These elements were copied:
	-include statements for each file
	-argument checker
	-port input
	-sockaddr_in definition statements
	-socket declarations
	-sendto format
	-recvfrom format
	-address check

All programs are compiled as:
	gcc -o <program name> <file name> -lm

To run key manager:
	<program name> <port number>

To run broker:
	<program name> <port number> <key manager IP> <key manager port>

To run client:
	<program name> <key manager IP> <key manager port>

	To make a request: request <principalID>

	To exchange stocks:
<buy/sell> <principalID> <broker IP> <broker port> <number>