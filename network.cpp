#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include "network.h"

using namespace std;

int sendMessageResolverClient(string serverIp){

	const char * ipStr = serverIp.c_str();
	uint16_t serverPort = 53;
	
	int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

  
	struct sockaddr_in remoteaddr;
	remoteaddr.sin_family = AF_INET;
	remoteaddr.sin_addr.s_addr = inet_addr(ipStr);
	remoteaddr.sin_port = htons(serverPort);
	
	if(connect(clientSocket, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr)) == -1){
	
		cout << "Cannot connect to server" << endl;
		close(clientSocket);
		return -1;
	
	}

	const char* message = "Hello, server!";
	send(clientSocket, message, strlen(message), 0);
	
	
	char buffer[2000];
	recv(clientSocket,&buffer,sizeof(buffer),0);
	cout << buffer << endl;
	
	
	close(clientSocket);
	return 0;

}
