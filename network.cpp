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
	cout << "sending to server " << inet_ntoa(serverAddr.sin_addr) << endl;
	
	if(msg.empty()){
		cout << "need a message to send" << endl;
		return (int)NetworkErrors::user;
	}
	
	uint16_t sz = msg.size();
	
	uint8_t* msgArr = &msg[0];
	msgArr[0] = ((sz -2) & 0xff00) >> 7;
	msgArr[1] = ((sz -2) & 0x00ff);
	/*cout << "MY MESSAGE START=============================================" << endl;
	for(size_t i =0; i < sz; i++){
		cout << (unsigned int)msgArr[i] << " ";
	}
	cout << endl;
	cout << "MY MESSAGE END=============================================" << endl;
	*/
	
	
	if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0){
		cout << "failed to connect" << endl;
		return (int)NetworkErrors::socket;
	}
	
	int bytesSent = send(clientSocket, msgArr, sz, 0);
	
	//cout << "sent bytes " << bytesSent << endl;
	if(bytesSent < 1){
		perror("cant send message\n");
		close(clientSocket);
		return (int)NetworkErrors::sending;
	
	}
	
	uint8_t buffer[responseSize] = {0};
	
	socklen_t outSize;
	int bytesRec = recv(clientSocket, buffer, sizeof(buffer), 0);
	
	//cout << bytesRec << endl;
	if(bytesRec < 1){
		cout << "failed to read message from server" << endl;
		close(clientSocket);
		return (int)NetworkErrors::recieving;
	}
	
	/*cout <<endl;
	cout << "SERVER MESSAGE START=============================================" << endl;
	for(int i =0; i < 2000; i++){
	
		cout << (unsigned int)buffer[i] << " ";
	
	}
	cout << "SERVER MESSAGE END=============================================" << endl;
	*/
	
	close(clientSocket);
	resp = vector<uint8_t>(buffer,buffer + (responseSize * sizeof(uint8_t)));
	
	return (int)NetworkErrors::none;

}
