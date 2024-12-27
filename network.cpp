#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include "network.h"
#include <cstdio>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <bitset>
#include <netinet/tcp.h>

using namespace std;

#define responseSize 2000


int sendMessageResolverClient(string serverIp, vector<uint8_t>& msg, vector<uint8_t>& resp){

	const char * ipStr = serverIp.c_str();
	uint16_t serverPort = 53;
	
	int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
	

	if(clientSocket < 0){
		perror("cant create socket\n");
		return (int)NetworkErrors::socket;
	
	}

	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(serverPort);
	int success = inet_aton(ipStr, &(serverAddr.sin_addr));
	if(success == 0){
		cout << "invalid ip conversion" << endl;
		return (int)NetworkErrors::user;
	}
	
	if(msg.empty()){
		cout << "need a message to send" << endl;
		return (int)NetworkErrors::user;
	}
	
	uint16_t sz = msg.size();
	
	uint8_t* msgArr = &msg[0];
	msgArr[0] = ((sz -2) & 0xff00) >> 7;
	msgArr[1] = ((sz -2) & 0x00ff);
	
	
	if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0){
		cout << "failed to connect" << endl;
		return (int)NetworkErrors::socket;
	}
	
	int bytesSent = send(clientSocket, msgArr, sz, 0);
	
	if(bytesSent < 1){
		perror("cant send message\n");
		close(clientSocket);
		return (int)NetworkErrors::sending;
	
	}
	
	uint8_t buffer[responseSize] = {0};
	
	int bytesRec = recv(clientSocket, buffer, sizeof(buffer), 0);
	
	if(bytesRec < 1){
		cout << "failed to read message from server" << endl;
		close(clientSocket);
		return (int)NetworkErrors::recieving;
	}
	
	close(clientSocket);
	
	for(int i = 0; i < bytesRec; i++){
		resp.push_back(buffer[i]);
	
	}
	
	return (int)NetworkErrors::none;

}
