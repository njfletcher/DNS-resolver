#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include "network.h"
#include <cstdio>

using namespace std;

int sendMessageResolverClient(string serverIp){

	const char * ipStr = serverIp.c_str();
	uint16_t serverPort = 53;
	
	int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

  
	struct sockaddr_in remoteaddr;
	remoteaddr.sin_family = AF_INET;
	remoteaddr.sin_addr.s_addr = inet_addr(ipStr);
	remoteaddr.sin_port = htons(serverPort);
	
	if(connect(clientSocket, (struct sockaddr *)&remoteaddr, sizeof(remoteaddr)) < 0){
	
		cout << "Cannot connect to server" << endl;
		close(clientSocket);
		return -1;
	
	}

	const char* message = "Hello, server!";
	send(clientSocket, message, strlen(message), 0);
	
	
	char buffer[2000] = {0};
	int bytes  = read(clientSocket,&buffer,sizeof(buffer) -1);
	cout << bytes << endl;
	if(bytes < 0){
	
		perror("read from server");
	}
	
	cout << "MESSAGE START=============================================" << endl;
	
	for(int i =0; i < 2000; i++){
		cout << (int)buffer[i] << " ";
	
	}
	
	cout << "MESSAGE END=============================================" << endl;
	//cout << buffer << endl;
	
	
	close(clientSocket);
	return 0;

}
