#include "structures.h"
#include <vector>
#include <cstdint>
#include <iostream>
#include <iterator>

using namespace std;


DNSFlags::DNSFlags(qrVals qr, opcodes opcode, uint8_t aa, uint8_t tc, uint8_t rd, uint8_t ra, uint8_t z, uint8_t rcode): _qr(qr), _opcode(opcode), _aa(aa), _tc(tc), _rd(rd), _z(z), _rcode(rcode){};

//iter is assumed to point to the start of the flags section
//leaves iter at start of next section
DNSFlags::DNSFlags(vector<uint8_t>::iterator& iter, vector<uint8_t>::iterator end, bool& succeeded){
	
	uint8_t firstByte = 0;
	uint8_t secondByte = 0;
	
	
	if(!(distance(iter,end) < 2)){
		
		firstByte = *iter;
		secondByte = *(iter + 1);
		iter = iter + 2;
		succeeded = true;
	}
	else succeeded = false;	
	
	_qr = (firstByte & 0x1);
	_opcode = (firstByte & 0xF) >> 1;
	_aa = (firstByte & 0x1) >> 5;
	_tc = (firstByte & 0x1) >> 6;
	_rd = (firstByte & 0x1) >> 7;
	
	_ra = (secondByte & 0x1);
	_rd = (secondByte & 0x7) >> 1;
	_rcode = (secondByte & 0xF) >> 4;
	

}

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

void DNSFlags::print(){

	cout << "========================START DNS HEADER FLAGS==========================" << endl;
	cout << "qr(query or response): " << (+_qr) << endl; 
	cout << "opcode(type of query): " << (+_opcode) << endl; 
	cout << "aa(is this an authoritative answer?): " << (+_aa) << endl; 
	cout << "tc(was this message truncated?): " << (+_tc) << endl; 
	cout << "rd(should the name server recursively respond to the query?): " << (+_rd) << endl; 
	cout << "ra(can the name server support recursive query requests?): " << (+_ra) << endl; 
	cout << "z(reserved, must be 0): " << (+_z) << endl; 
	cout << "rcode(response code): " << (+_rcode) << endl; 
	cout << "========================END DNS HEADER FLAGS============================" << endl;

}

DNSHeader::DNSHeader(uint16_t transId, const DNSFlags& flags, uint16_t numQuestions, uint16_t numAnswers, uint16_t numAuthRR, uint16_t numAdditRR): _transId(transId), _flags(flags), _numQuestions(numQuestions),_numAnswers(numAnswers), _numAuthRR(numAuthRR), _numAdditRR(numAdditRR){};

//iter is assumed to point to the start of the header section
//leaves iter at start of next section
DNSHeader::DNSHeader(vector<uint8_t>::iterator & iter, vector<uint8_t>::iterator end, bool& succeeded){

	_transId = 0;
	if(!(distance(iter,end) < 2)){
		
		_transId = (((uint16_t)(*iter) & 0xff) << 8) | (((uint16_t) *(iter + 1) & 0xff);
		iter = iter + 2;
		succeeded = true;
	}
	
	bool flagsSucceeded = false;
	_flags(iter, end, flagsSucceeded);
	
	_numQuestions = 0;
	_numAnswers = 0;
	_numAuthRR = 0;
	_numAdditRR = 0;
	if(!(distance(iter,end) < 8 || !flagsSucceeded)){
		
		_numQuestions = (((uint16_t)(*iter) & 0xff) << 8) | (((uint16_t) *(iter + 1) & 0xff);
		iter = iter + 2;
		_numAnswers = (((uint16_t)(*iter) & 0xff) << 8) | (((uint16_t) *(iter + 1) & 0xff);
		iter = iter + 2;
		_numAuthRR = (((uint16_t)(*iter) & 0xff) << 8) | (((uint16_t) *(iter + 1) & 0xff);
		iter = iter + 2;
		_numAdditRR = ((uint16_t)(*iter) & 0xff) << 8) | (((uint16_t) *(iter + 1) & 0xff);
		iter = iter + 2;
		succeeded = true;
	}
	else suceeded = false;
	
}

void DNSHeader::toBuffer(vector<uint8_t> & buffer){

	buffer.push_back((_transId & 0xff00) >> 8);
	buffer.push_back(_transId & 0x00ff);
	
	_flags.toBuffer(buffer);
	
	buffer.push_back((_numQuestions & 0xff00) >> 8);
	buffer.push_back(_numQuestions & 0x00ff);
	
	buffer.push_back((_numAnswers & 0xff00) >> 8);
	buffer.push_back(_numAnswers & 0x00ff);
	
	buffer.push_back((_numAuthRR & 0xff00) >> 8);
	buffer.push_back(_numAuthRR & 0x00ff);
	
	buffer.push_back((_numAdditRR & 0xff00) >> 8);
	buffer.push_back(_numAdditRR & 0x00ff);
	
}

void DNSHeader::print(){

	cout << "++++++++++++++++++++++START DNS HEADER+++++++++++++++++++++++++++" << endl;
	cout << "transId(id of query/response): " << _transId << endl; 
	_flags->print();
	cout << "numQuestions(number of question records in body of message): " << _numQuestions << endl; 
	cout << "numAnswers(number of answer records in body of message): " << _numAnswers << endl; 
	cout << "numAuthRR(number of authoritative resource records in body of message): " << _numAuthRR << endl; 
	cout << "numAdditRR(number of additional(non answer) records in body of message): " << _numAdditRR << endl; 
	cout << "+++++++++++++++++++++END DNS HEADER++++++++++++++++++++++++++++++" << endl;

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
	
	//needs last null terminator
	buffer.push_back(0);


}

convertBufferNameToVector(vector<uint8_t>::iterator & iter, vector<uint8_t>::iterator end, vector<uint8_t> & vec){

	uint8_t currLength = 0;
	uint8_t currCounter = 0;
	for(; iter != end; iter++){
		
		//this byte should be a length byte
		if(currCounter >= currLength){
			
			vec.push_back(*iter);
			currCounter = 0;
			currLength = *iter;
			//0 length terminator
			if(currLength == 0) break;
		
		}
		//still reading a label
		else{
			currCounter = currCounter + 1;
			vec.push_back(*iter);

		}
	}


}

printOctetSeq(const vector<uint8_t> & nameSequence){


	uint8_t currLength = 0;
	uint8_t currCounter = 0;
	for(auto iter = nameSequence.begin(); iter != nameSequence.end(); iter++){
	
		//this byte should be a length byte
		if(currCounter >= currLength){
			
			currLength = *iter;
			cout << " len: " << (+currLength) << " label: ";
			currCounter = 0;
			//0 length terminator
			if(currLength == 0) break;
		
		}
		//still reading a label
		else{
			currCounter = currCounter + 1;
			cout << " " << (*iter);

		}
	
	}


}

QuestionRecord::QuestionRecord(const char * name, ResourceTypes qType, ResourceClasses qClass): _qType(qType), _qClass(qClass) {

	convertCStringToOctetForm(name, _name);
};

QuestionRecord::QuestionRecord(vector<uint8_t>::iterator & iter, vector<uint8_t>::iterator end, bool& succeeded){

	
	convertBufferNameToVector(iter, end, _name);
	
	_qType = 0;
	_qClass = 0;
	if(!(distance(iter,end) < 4)){
		
		_qType = (((uint16_t)(*iter) & 0xff) << 8) | (((uint16_t) *(iter + 1) & 0xff);
		iter = iter + 2;
		_qClass = (((uint16_t)(*iter) & 0xff) << 8) | (((uint16_t) *(iter + 1) & 0xff);
		iter = iter + 2;
		succeeded = true;
	}
	else succeeded = false;
	
}

void QuestionRecord::toBuffer(vector<uint8_t> & buffer){

	for(int i = 0; _name[i] != 0; i++){
		
		buffer.push_back(_name[i]);
	}
	
	buffer.push_back(((uint16_t)_qType & 0xff00) >> 8);
	buffer.push_back((uint16_t)_qType & 0xff);

	buffer.push_back(((uint16_t)_qClass & 0xff00) >> 8);
	buffer.push_back((uint16_t)_qClass & 0x00ff);
		
}

void QuestionRecord::print(uint16_t number = 0){

	cout << "------------------------START QUESTIONRECORD " << number << " ---------------------------------" << endl;
	cout << "name: [";
	printOctetSeq(_name); 
	cout << "]" << endl;
	
	cout << "qType(type of the question record): " << (+_qType) << endl; 
	cout << "qClass(class of the question record): " << (+_qClass) << endl; 
	cout << "------------------------END QUESTIONRECORD " << number << " ----------------------------------------" << endl;



}

ResourceRecord::ResourceRecord(const char * name, uint16_t rType, uint16_t rClass, uint32_t ttl, uint16_t rdLength, td::vector<uint8_t> rData): _rType(rType), _rClass(rClass), _ttl(ttl), _rdLength(rdLength){

	_rData = rData;
	convertCStringToOctetForm(name, _name);

}

ResourceRecord::ResourceRecord(vector<uint8_t>::iterator & iter, vector<uint8_t>::iterator end, bool& succeeded){

	convertBufferNameToVector(iter, end, _name);
	
	_rType = 0;
	_rClass = 0;
	_ttl = 0;
	_rdLength = 0;
	if(!(distance(iter,end) < 10)){
		
		_rType = (((uint16_t)(*iter) & 0xff) << 8) | (((uint16_t) *(iter + 1) & 0xff);
		iter = iter + 2;
		_rClass = (((uint16_t)(*iter) & 0xff) << 8) | (((uint16_t) *(iter + 1) & 0xff);
		iter = iter + 2;
		_ttl = (((uint32_t)(*iter) & 0xff) << 24) | (((uint32_t) *(iter + 1) & 0xff) << 16) | (((uint32_t) *(iter + 2) & 0xff) << 8) | (((uint32_t) *(iter + 3) & 0xff));
		iter = iter + 4;
		_rdLength = ((uint16_t)(*iter) & 0xff) << 8) | (((uint16_t) *(iter + 1) & 0xff);
		iter = iter + 2;
		succeeded = true;
	}
	else succeeded = false;
	
	
	for(uint16_t i = 0; (i < rdLength) && (iter != end); i++){
		
		_rData.push_back(*iter);
		iter = iter + 1;
	}

}

void ResourceRecord::toBuffer(vector<uint8_t> & buffer){

	for(int i = 0; name[i] != 0; i++){
		
		buffer.push_back(name[i]);
	}
	
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

void ResourceRecord::print(uint16_t number = 0){

	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^START RESOURCERECORD " << number << " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;
	cout << "name: [";
	printOctetSeq(_name); 
	cout << "]" << endl;
	
	cout << "rType(type of the resource record): " << _rType << endl; 
	cout << "rClass(class of the resource record): " << _rClass << endl; 
	cout << "ttl(time to live): " << _ttl << endl; 
	cout << "rdLength(length in octets of rdata section): " << _rdLength << endl; 
	cout << "rData(resource data): ["
	for(auto iter = _rData.begin(); iter != _rData.end(); iter++){
		cout << " " << +(*iter);
	}
	cout << "]" << endl;
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^END RESOURCERECORD " << number << " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;



}

DNSMessage::DNSMessage(const DNSHeader& hdr, vector<QuestionRecord>& question, vector<ResourceRecord>& answer, vector<ResourceRecord>& authority, vector<ResourceRecord>& additional): _hdr(hdr), _question(question), _answer(answer), _authority(authority), _additional(additional){};

DNSMessage::DNSMessage(vector<uint8_t>::iterator & iter, vector<uint8_t>::iterator end){

	_hdr(iter,end);
	
	bool recordSucceeded = true;
		
	for(uint16_t i = 0; (i < _hdr._numQuestions) && recordSucceeded; i++){
	
		_question.pushback(QuestionRecord(iter,end,recordSucceeded));
	}
	
	for(uint16_t i = 0; (i < _hdr._numAnswers) && recordSucceeded; i++){
	
		_answer.pushback(ResourceRecord(iter,end,recordSucceeded));
	}
	
	for(uint16_t i = 0; (i < _hdr._numAuthRR) && recordSucceeded; i++){
	
		_authority.pushback(ResourceRecord(iter,end,recordSucceeded));
	}
	
	for(uint16_t i = 0; (i < _hdr._numAdditRR) && recordSucceeded; i++){
	
		_additional.pushback(ResourceRecord(iter,end,recordSucceeded));
	}


}

void DNSMessage::toBuffer(vector<uint8_t> & buffer){

	_hdr.toBuffer(buffer);
	
	for(uint16_t i = 0; i < _hdr._numQuestions; i++){
	
		_question[i].toBuffer(buffer);
	}
	
	for(uint16_t i = 0; i < _hdr._numAnswers; i++){
	
		_answer[i].toBuffer(buffer);
	}
	
	for(uint16_t i = 0; i < _hdr._numAuthRR; i++){
	
		_authority[i].toBuffer(buffer);
	}
	
	for(uint16_t i = 0; i < _hdr._numAdditRR; i++){
	
		_additional[i].toBuffer(buffer);
	}
		
}

void DNSMessage::print(){

	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^START DNSMESSAGE^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;
	_hdr.print();
	
	for(uint16_t i = 0; i < _hdr._numQuestions; i++){
	
		_question[i].print(i);
	}
	
	for(uint16_t i = 0; i < _hdr._numAnswers; i++){
	
		_answer[i].print(i);
	}
	
	for(uint16_t i = 0; i < _hdr._numAuthRR; i++){
	
		_authority[i].print(i);
	}
	
	for(uint16_t i = 0; i < _hdr._numAdditRR; i++){
	
		_additional[i].print(i);
	}
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^END DNSMESSAGE^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;


}



