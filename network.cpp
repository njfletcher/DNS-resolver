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

using namespace std;

#define responseSize 2000

int sendMessageResolverClient(string serverIp, const vector<uint8_t>& msg, vector<uint8_t>& resp){

	const char * ipStr = serverIp.c_str();
	uint16_t serverPort = 53;
	
	int clientSocket = socket(AF_INET, SOCK_DGRAM, 0);
	
	if(clientSocket < 0){
		perror("cant create socket\n");
		return -1;
	
	}

	struct sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(serverPort);
	int success = inet_aton(ipStr, &(serverAddr.sin_addr));
	if(success == 0){
		cout << "invalid ip conversion" << endl;
		return -1;
	}
	
	cout << "sending to server" << inet_ntoa(serverAddr.sin_addr) << endl;
	
	if(msg.empty()){
		cout << "need a message to send" << endl;
		return -1;
	}
	
	const uint8_t* msgArr = &msg[0];
	cout << "MY MESSAGE START=============================================" << endl;
	for(int i =0; i < msg.size(); i++){
		cout << (unsigned int)msgArr[i] << " ";
	}
	cout << endl;
	cout << "MY MESSAGE END=============================================" << endl;
	
	int bytesSent = sendto(clientSocket, msgArr, msg.size(), MSG_CONFIRM, (struct sockaddr *) &serverAddr, sizeof(serverAddr)); 
	
	cout << "sent bytes " << bytesSent << endl;
	if(bytesSent < 0){
		perror("cant send message\n");
		return -1;
	
	}
	
	uint8_t buffer[responseSize] = {0};
	
	socklen_t outSize;
	int bytesRec = recvfrom(clientSocket, buffer, responseSize, 0, (struct sockaddr *) &serverAddr, &outSize); 
	
	cout << bytesRec << endl;
	if(bytesRec < 0){
		perror("read from server");
		return -1;
	}
	cout <<endl;
	cout << "SERVER MESSAGE START=============================================" << endl;
	for(int i =0; i < 2000; i++){
	
		cout << (unsigned int)buffer[i] << " ";
	
	}
	cout << "SERVER MESSAGE END=============================================" << endl;
	
	close(clientSocket);
	resp = vector<uint8_t>(buffer,buffer + (responseSize * sizeof(uint8_t)));
	
	return 0;

}
