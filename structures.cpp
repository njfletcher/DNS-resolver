#include "structures.h"
#include <vector>
#include <cstdint>
#include <iostream>

using namespace std;


DNSFlags::DNSFlags(qrVals qr, opcodes opcode, uint8_t aa, uint8_t tc, uint8_t rd, uint8_t ra, uint8_t z, uint8_t rcode): _qr(qr), _opcode(opcode), _aa(aa), _tc(tc), _rd(rd), _z(z), _rcode(rcode){};


void DNSFlags::toBuffer(vector<uint8_t> & buffer){

	uint8_t firstByte =0;
	uint8_t secondByte =0;
	
	firstByte = firstByte | ((uint8_t)_qr & 0x1);
	firstByte = firstByte | (((uint8_t)_opcode & 0xF) << 1);
	firstByte = firstByte | ((_aa & 0x1) << 5);
	firstByte = firstByte | ((_tc & 0x1) << 6);
	firstByte = firstByte | ((_rd & 0x1) << 7);
	
	secondByte = secondByte | (_ra & 0x1);
	secondByte = secondByte | ((_rd & 0x7) << 1);
	secondByte = secondByte | ((_rcode & 0xF) << 4);
	
	buffer.push_back(firstByte);
	buffer.push_back(secondByte);
	
}

DNSHeader::DNSHeader(uint16_t transId, DNSFlags* flags, uint16_t numQuestions, uint16_t numAnswers, uint16_t numAuthRR, uint16_t numAdditRR): _transId(transId), _flags(flags), _numQuestions(numQuestions),_numAnswers(numAnswers), _numAuthRR(numAuthRR), _numAdditRR(numAdditRR){};

void DNSHeader::toBuffer(vector<uint8_t> & buffer){

	buffer.push_back((_transId & 0xff00) >> 8);
	buffer.push_back(_transId & 0x00ff);
	
	_flags->toBuffer(buffer);
	
	buffer.push_back((_numQuestions & 0xff00) >> 8);
	buffer.push_back(_numQuestions & 0x00ff);
	
	buffer.push_back((_numAnswers & 0xff00) >> 8);
	buffer.push_back(_numAnswers & 0x00ff);
	
	buffer.push_back((_numAuthRR & 0xff00) >> 8);
	buffer.push_back(_numAuthRR & 0x00ff);
	
	buffer.push_back((_numAdditRR & 0xff00) >> 8);
	buffer.push_back(_numAdditRR & 0x00ff);
	
}


void convertCStringToOctetForm(const char * name, vector<uint8_t>& buffer){
	
	string s(name);
	bool labelsLeft = true;
	string label;
	uint8_t labelLen;
	
	while(labelsLeft){
		
		size_t ind = s.find(".");
		if(ind == string::npos){
			labelsLeft = false;
			label = s;
			labelLen = s.length();
		}
		else{
			label = s.substr(0, ind);
			labelLen = label.length();
			s = s.substr(ind + 1);
		
		}
		
		buffer.push_back(labelLen);
		for(uint8_t i = 0; i < labelLen; i++){
			buffer.push_back(label[i]);
		}
		
	}


}

QuestionRecord::QuestionRecord(const char * name, ResourceTypes qType, ResourceClasses qClass): _qType(qType), _qClass(qClass) {

	convertCStringToOctetForm(name, _name);
};

void QuestionRecord::toBuffer(vector<uint8_t> & buffer){

	for(int i = 0; _name[i] != 0; i++){
		
		buffer.push_back(_name[i]);
	}
	//include the null term
	buffer.push_back(0);
	
	buffer.push_back(((uint8_t)_qType & 0xff00) >> 8);
	buffer.push_back((uint8_t)_qType & 0x00ff);

	buffer.push_back(((uint8_t)_qClass & 0xff00) >> 8);
	buffer.push_back((uint8_t)_qClass & 0x00ff);
		
}

void ResourceRecord::toBuffer(vector<uint8_t> & buffer){

	for(int i = 0; name[i] != 0; i++){
		
		buffer.push_back(name[i]);
	}
	
	//include the null term
	buffer.push_back(0);
	
	buffer.push_back((rType & 0xff00) >> 8);
	buffer.push_back(rType & 0x00ff);

	buffer.push_back((rClass & 0xff00) >> 8);
	buffer.push_back(rClass & 0x00ff);
	
	buffer.push_back((ttl & 0xff000000) >> 24);
	buffer.push_back((ttl & 0x00ff0000) >> 16);
	buffer.push_back((ttl & 0x0000ff00) >> 8);
	buffer.push_back(ttl & 0x000000ff);
	
	buffer.push_back((rdLength & 0xff00) >> 8);
	buffer.push_back(rdLength & 0x00ff);

	for(uint16_t i = 0; i < rdLength; i++){
		
		buffer.push_back(rData[i]);
	}
		
}

DNSMessage::DNSMessage(DNSHeader* hdr, QuestionRecord* question, ResourceRecord* answer, ResourceRecord* authority, ResourceRecord* additional): _hdr(hdr), _question(question), _answer(answer), _authority(authority), _additional(additional){};

void DNSMessage::toBuffer(vector<uint8_t> & buffer){

	_hdr->toBuffer(buffer);
	
	for(uint16_t i = 0; i < _hdr->_numQuestions; i++){
	
		_question[i].toBuffer(buffer);
	}
	
	for(uint16_t i = 0; i < _hdr->_numAnswers; i++){
	
		_answer[i].toBuffer(buffer);
	}
	
	for(uint16_t i = 0; i < _hdr->_numAuthRR; i++){
	
		_authority[i].toBuffer(buffer);
	}
	
	for(uint16_t i = 0; i < _hdr->_numAdditRR; i++){
	
		_additional[i].toBuffer(buffer);
	}
		
}



