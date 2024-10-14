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

using namespace std;

int sendMessageResolverClient(string serverIp, const vector<uint8_t>& msg){

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

	if(msg.empty()){
		cout << "need a message to send" << endl;
		return -1;
	}
	
	const uint8_t* msgArr = &msg[0];
	cout << "MY MESSAGE START=============================================" << endl;
	for(int i =0; i < msg.size(); i++){
		cout << (int)msgArr[i] << " ";
	}
	cout << endl;
	cout << "MY MESSAGE END=============================================" << endl;
	send(clientSocket, msgArr, msg.size(), 0);
	
	
	char buffer[2000] = {0};
	int bytes  = recv(clientSocket,&buffer,2000, 0);
	cout << bytes << endl;
	if(bytes < 0){
	
		perror("read from server");
	}
	cout <<endl;
	cout << "SERVER MESSAGE START=============================================" << endl;
	
	for(int i =0; i < 2000; i++){
		cout << (int)buffer[i] << " ";
	
	}
	
	cout << "SERVER MESSAGE END=============================================" << endl;
	//cout << buffer << endl;
	
	
	close(clientSocket);
	return 0;

}
