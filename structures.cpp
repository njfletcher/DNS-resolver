#include "structures.h"
#include <vector>

using namespace std;


DNSFlags::DNSFlags(qrVals qr, opcodes opcode, unsigned char aa, unsigned char tc, unsigned char rd, unsigned char ra, unsigned char z, unsigned char rcode): _qr(qr), _opcode(opcode), _aa(aa), _tc(tc), _rd(rd), _z(z), _rcode(rcode){};


void DNSFlags::toBuffer(vector<char> & buffer){

	char firstByte =0;
	char secondByte =0;
	
	firstByte = firstByte | ((unsigned char)_qr & 0x1);
	firstByte = firstByte | (((unsigned char)_opcode & 0xF) << 1);
	firstByte = firstByte | ((_aa & 0x1) << 5);
	firstByte = firstByte | ((_tc & 0x1) << 6);
	firstByte = firstByte | ((_rd & 0x1) << 7);
	
	secondByte = secondByte | (_ra & 0x1);
	secondByte = secondByte | ((_rd & 0x7) << 1);
	secondByte = secondByte | ((_rcode & 0xF) << 4);
	
	buffer.push_back(firstByte);
	buffer.push_back(secondByte);
	
}

DNSHeader::DNSHeader(unsigned short transId, DNSFlags* flags, unsigned short numQuestions, unsigned short numAnswers, unsigned short numAuthRR, unsigned short numAdditRR): _transId(transId), _flags(flags), _numQuestions(numQuestions),_numAnswers(numAnswers), _numAuthRR(numAuthRR), _numAdditRR(numAdditRR){};

void DNSHeader::toBuffer(vector<char> & buffer){

	buffer.push_back(_transId & 0x00ff);
	buffer.push_back((_transId & 0xff00) >> 8);

	_flags->toBuffer(buffer);
	
	buffer.push_back(_numQuestions & 0x00ff);
	buffer.push_back((_numQuestions & 0xff00) >> 8);
	
	buffer.push_back(_numAnswers & 0x00ff);
	buffer.push_back((_numAnswers & 0xff00) >> 8);
	
	buffer.push_back(_numAuthRR & 0x00ff);
	buffer.push_back((_numAuthRR & 0xff00) >> 8);
	
	buffer.push_back(_numAdditRR & 0x00ff);
	buffer.push_back((_numAdditRR & 0xff00) >> 8);
	
}

QuestionRecord::QuestionRecord(const char * name, ResourceTypes qType, ResourceClasses qClass): _name(name), _qType(qType), _qClass(qClass) {};

void QuestionRecord::toBuffer(vector<char> & buffer){

	for(int i = 0; _name[i] != 0; i++){
		
		buffer.push_back(_name[i]);
	}
	//include the null term
	buffer.push_back(0);
	
	buffer.push_back((unsigned char)_qType & 0x00ff);
	buffer.push_back(((unsigned char)_qType & 0xff00) >> 8);

	buffer.push_back((unsigned char)_qClass & 0x00ff);
	buffer.push_back(((unsigned char)_qClass & 0xff00) >> 8);
		
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

DNSMessage::DNSMessage(DNSHeader* hdr, QuestionRecord* question, ResourceRecord* answer, ResourceRecord* authority, ResourceRecord* additional): _hdr(hdr), _question(question), _answer(answer), _authority(authority), _additional(additional){};

void DNSMessage::toBuffer(vector<char> & buffer){

	_hdr->toBuffer(buffer);
	
	for(unsigned short i = 0; i < _hdr->_numQuestions; i++){
	
		_question[i].toBuffer(buffer);
	}
	
	for(unsigned short i = 0; i < _hdr->_numAnswers; i++){
	
		_answer[i].toBuffer(buffer);
	}
	
	for(unsigned short i = 0; i < _hdr->_numAuthRR; i++){
	
		_authority[i].toBuffer(buffer);
	}
	
	for(unsigned short i = 0; i < _hdr->_numAdditRR; i++){
	
		_additional[i].toBuffer(buffer);
	}
		
}



