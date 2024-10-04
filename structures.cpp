#include "structures.h"
#include <vector>

using namespace std;


void DNSFlags::toBuffer(vector<char> & buffer){

	char firstByte =0;
	char secondByte =0;
	
	firstByte = firstByte | (qr & 0x1);
	firstByte = firstByte | ((opcode & 0xF) << 1);
	firstByte = firstByte | ((aa & 0x1) << 5);
	firstByte = firstByte | ((tc & 0x1) << 6);
	firstByte = firstByte | ((rd & 0x1) << 7);
	
	secondByte = secondByte | (ra & 0x1);
	secondByte = secondByte | ((rd & 0x7) << 1);
	secondByte = secondByte | ((rcode & 0xF) << 4);
	
	buffer.push_back(firstByte);
	buffer.push_back(secondByte);
	
}

void DNSHeader::toBuffer(vector<char> & buffer){

	buffer.push_back(transId & 0x00ff);
	buffer.push_back((transId & 0xff00) >> 8);

	flags->toBuffer(buffer);
	
	buffer.push_back(numQuestions & 0x00ff);
	buffer.push_back((numQuestions & 0xff00) >> 8);
	
	buffer.push_back(numAnswers & 0x00ff);
	buffer.push_back((numAnswers & 0xff00) >> 8);
	
	buffer.push_back(numAuthRR & 0x00ff);
	buffer.push_back((numAuthRR & 0xff00) >> 8);
	
	buffer.push_back(numAdditRR & 0x00ff);
	buffer.push_back((numAdditRR & 0xff00) >> 8);
	
}

void QuestionRecord::toBuffer(vector<char> & buffer){

	for(int i = 0; name[i] != 0; i++){
		
		buffer.push_back(name[i]);
	}
	//include the null term
	buffer.push_back(0);
	
	buffer.push_back(qType & 0x00ff);
	buffer.push_back((qType & 0xff00) >> 8);

	buffer.push_back(qClass & 0x00ff);
	buffer.push_back((qClass & 0xff00) >> 8);
		
}

void ResourceRecord::toBuffer(vector<char> & buffer){

	for(int i = 0; name[i] != 0; i++){
		
		buffer.push_back(name[i]);
	}
	//include the null term
	buffer.push_back(0);
	
	buffer.push_back(rType & 0x00ff);
	buffer.push_back((rType & 0xff00) >> 8);

	buffer.push_back(rClass & 0x00ff);
	buffer.push_back((rClass & 0xff00) >> 8);
	
	buffer.push_back(ttl & 0x000000ff);
	buffer.push_back((ttl & 0x0000ff00) >> 8);
	buffer.push_back((ttl & 0x00ff0000) >> 16);
	buffer.push_back((ttl & 0xff000000) >> 24);
	
	buffer.push_back(rdLength & 0x00ff);
	buffer.push_back((rdLength & 0xff00) >> 8);

	for(unsigned short i = 0; i < rdLength; i++){
		
		buffer.push_back(rData[i]);
	}
		
}

void DNSMessage::toBuffer(vector<char> & buffer){

	hdr->toBuffer(buffer);
	
	for(unsigned short i = 0; i < hdr->numQuestions; i++){
	
		question[i].to_buffer(buffer);
	}
	
	for(unsigned short i = 0; i < hdr->numAnswers; i++){
	
		answer[i].to_buffer(buffer);
	}
	
	for(unsigned short i = 0; i < hdr->numAuthRR; i++){
	
		authority[i].to_buffer(buffer);
	}
	
	for(unsigned short i = 0; i < hdr->numAdditRR; i++){
	
		additional[i].to_buffer(buffer);
	}
		
}



