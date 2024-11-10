#include "structures.h"
#include <vector>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <bitset>
#include "resolver.h"

using namespace std;

DNSFlags::DNSFlags(){};
DNSFlags::DNSFlags(uint8_t qr, uint8_t opcode, uint8_t aa, uint8_t tc, uint8_t rd, uint8_t ra, uint8_t z, uint8_t rcode): _qr(qr), _opcode(opcode), _aa(aa), _tc(tc), _rd(rd), _ra(ra), _z(z), _rcode(rcode){};

//iter is assumed to point to the start of the flags section
//leaves iter at start of next section
DNSFlags::DNSFlags(vector<uint8_t>::iterator& iter, const vector<uint8_t>::iterator end, bool& succeeded){
	
	uint8_t firstByte = 0;
	uint8_t secondByte = 0;
	
	
	if(!(distance(iter,end) < 2)){
		
		firstByte = *iter;
		secondByte = *(iter + 1);
		iter = iter + 2;
		succeeded = true;
	}
	else succeeded = false;	

	_qr = ((firstByte & 0x80) >> 7);
	_opcode = ((firstByte  & 0x78) >> 3);
	_aa = ((firstByte  & 0x4) >> 2);
	_tc = ((firstByte  & 0x2) >> 1);
	_rd = (firstByte  & 0x1);
	
	_ra = ((secondByte & 0x80) >> 7);
	_z = ((secondByte & 0x70) >> 4);
	_rcode = ((secondByte & 0xF));
	

}

void DNSFlags::toBuffer(vector<uint8_t> & buffer){

	uint8_t firstByte =0;
	uint8_t secondByte =0;
	
	firstByte = firstByte | ((_qr & 0x1) << 7);
	firstByte = firstByte | (((_opcode) & 0xF) << 3);
	firstByte = firstByte | ((_aa & 0x1) << 2);
	firstByte = firstByte | ((_tc & 0x1) << 1);
	firstByte = firstByte | ((_rd & 0x1));
	
	secondByte = secondByte | ((_ra & 0x1) << 7);
	secondByte = secondByte | ((_z & 0x7) << 4);
	secondByte = secondByte | ((_rcode & 0xF));
	
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

DNSHeader::DNSHeader(){};

DNSHeader::DNSHeader(uint16_t transId, const DNSFlags& flags, uint16_t numQuestions, uint16_t numAnswers, uint16_t numAuthRR, uint16_t numAdditRR): _transId(transId), _flags(flags), _numQuestions(numQuestions),_numAnswers(numAnswers), _numAuthRR(numAuthRR), _numAdditRR(numAdditRR){};

//iter is assumed to point to the start of the header section
//leaves iter at start of next section
DNSHeader::DNSHeader(vector<uint8_t>::iterator & iter, const vector<uint8_t>::iterator end, bool& succeeded){

	_transId = 0;
	if(!(distance(iter,end) < 2)){
		
		_transId = ((((uint16_t)(*iter)) & 0xff) << 8) | (((uint16_t) *(iter + 1)) & 0xff);
		iter = iter + 2;
		succeeded = true;
	}
	
	bool flagsSucceeded = false;
	_flags = DNSFlags(iter,end,flagsSucceeded);
	
	_numQuestions = 0;
	_numAnswers = 0;
	_numAuthRR = 0;
	_numAdditRR = 0;
	if(!(distance(iter,end) < 8 || !flagsSucceeded)){
		
		_numQuestions = ((((uint16_t)(*iter)) & 0xff) << 8) | (((uint16_t) *(iter + 1)) & 0xff);
		iter = iter + 2;
		_numAnswers = ((((uint16_t)(*iter)) & 0xff) << 8) | (((uint16_t) *(iter + 1)) & 0xff);
		iter = iter + 2;
		_numAuthRR = ((((uint16_t)(*iter)) & 0xff) << 8) | (((uint16_t) *(iter + 1)) & 0xff);
		iter = iter + 2;
		_numAdditRR = ((((uint16_t)(*iter)) & 0xff) << 8) | (((uint16_t) *(iter + 1)) & 0xff);
		iter = iter + 2;
		succeeded = true;
	}
	else succeeded = false;
	
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
	_flags.print();
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


bool checkCompression(vector<uint8_t>::iterator & iter, const vector<uint8_t>::iterator end, uint16_t & offset, vector<uint8_t>& buff){

	if( (distance(iter,end) > 1) && ((*iter & 0xC0) == 0xC0)){
		
		offset = (((uint16_t)(*iter & 0x3F)) << 8);
		buff.push_back(*iter);
		iter = iter + 1;
		offset = offset | (((uint8_t)*iter) & 0xff);
		offset = offset + 2; //have to also account for tcp two byte length at beginning of message.
		buff.push_back(*iter);
		iter = iter + 1;
		return true;
	
	}
	else return false;

}

void convertBufferNameToVector(vector<uint8_t>::iterator mainMsgStart, vector<uint8_t>::iterator & mainMsgIter, const vector<uint8_t>::iterator mainMsgEnd, vector<uint8_t> & vec, uint8_t bytesRead, vector<uint8_t>* optMsg= NULL ){

	cout << endl;
	uint8_t currLength = 0;
	uint8_t currCounter = 0;
	
	vector<uint8_t>::iterator optStart;
	if(optMsg != NULL){
		optStart = optMsg->begin();
	}
	
	vector<uint8_t>::iterator start = (optMsg != NULL) ? optStart : mainMsgStart;
	vector<uint8_t>::iterator & iter = (optMsg != NULL) ? optStart : mainMsgIter;
	vector<uint8_t>::iterator end = (optMsg != NULL) ? optMsg->end() : mainMsgEnd;
		
	uint16_t compOffset = 0;
	//first out of two compressions options, name field is simply a pointer to a whole domain label series situated somewhere else.
	if( checkCompression(iter, end, compOffset,vec)){
		
		cout << "head compression " << compOffset << " ";
		vector<uint8_t>::iterator pointStart = mainMsgStart + compOffset;//make a copy so reading name somewhere else doesnt affect current position of our packet iter.
		convertBufferNameToVector(mainMsgStart, pointStart, mainMsgEnd, vec, bytesRead + 2, NULL);
	
	}
	else{
	
		for(; (iter < end) && (bytesRead <= maxDomainNameLen) ; iter++){
		
			//this byte should be a length byte
			if(currCounter >= currLength){
			
				currCounter = 0;
				currLength = *iter;
				bytesRead = bytesRead + 1;
				vec.push_back(*iter);
				
				cout << "length " << (int) currLength << " ";
				
				//0 length terminator
				if(currLength == 0) {
					iter = iter + 1;
					break;
				}
				//second of two compression options, name field has series of labels that ends with labels at location specified by pointer.
				if (checkCompression(iter, end, compOffset,vec)){
						
					cout << "tail compression " << compOffset << " ";
					vector<uint8_t>::iterator pointStart = mainMsgStart + compOffset;//make a copy so reading name somewhere else doesnt affect current position of our packet iter.
					convertBufferNameToVector(mainMsgStart, pointStart, mainMsgEnd, vec, bytesRead + 1,NULL);
					break;
				}
				
		
			}
			//still reading a label
			else{
				
				currCounter = currCounter + 1;
				bytesRead = bytesRead + 1;
				vec.push_back(*iter);
				cout << *iter << " ";

			}
		}	
	
	
	}
	
	
	


}


void printOctetSeq(const vector<uint8_t> & nameSequence){


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
			if((currLength & 0xC0) == 0xC0){
			
				uint16_t offset = (((uint16_t)(*iter & 0x3F)) << 8);
				iter = iter + 1;
				offset = offset | (((uint8_t)*iter) & 0xff);
				offset = offset + 2;
				
				cout << "compressed w/ offset: " << offset << " ";
			}
		
		}
		//still reading a label
		else{
			currCounter = currCounter + 1;
			cout << " " << (*iter);

		}
	
	}


}

void convertOctetSequenceToBuffer(const vector<uint8_t> & nameSequence, vector<uint8_t>& buffer){


	uint8_t currLength = 0;
	uint8_t currCounter = 0;
	for(auto iter = nameSequence.begin(); iter != nameSequence.end(); iter++){
	
		//this byte should be a length byte
		if(currCounter >= currLength){
			
			currLength = *iter;
			buffer.push_back(*iter);
			currCounter = 0;
			
			//0 length terminator
			if(currLength == 0) break;
			if((currLength & 0xC0 )== 0xC0){
			
				uint16_t offset = (((uint16_t)(*iter & 0x3F)) << 8);
				iter = iter + 1;
				offset = offset | (((uint8_t)*iter) & 0xff);
				offset = offset + 2;
				buffer.push_back(*iter);
				break;
			}
		
		}
		//still reading a label
		else{
			currCounter = currCounter + 1;
			buffer.push_back(*iter);

		}
	
	}


}

QuestionRecord::QuestionRecord(){};

QuestionRecord::QuestionRecord(const char * name, uint16_t qType, uint16_t qClass): _qType(qType), _qClass(qClass) {

	convertCStringToOctetForm(name, _name);
};

QuestionRecord::QuestionRecord(const vector<uint8_t>::iterator start, vector<uint8_t>::iterator & iter, const vector<uint8_t>::iterator end, bool& succeeded){

	
	convertBufferNameToVector(start, iter, end, _name, 0);
	
	_qType = 0;
	_qClass = 0;
	if(!(distance(iter,end) < 4)){
		
		_qType = ((((uint16_t)(*iter)) & 0xff) << 8) | (((uint16_t) *(iter + 1)) & 0xff);
		iter = iter + 2;
		_qClass = ((((uint16_t)(*iter)) & 0xff) << 8) | (((uint16_t) *(iter + 1)) & 0xff);
		iter = iter + 2;
		succeeded = true;
	}
	else succeeded = false;
	
}

void QuestionRecord::toBuffer(vector<uint8_t> & buffer){

	convertOctetSequenceToBuffer(_name, buffer);
	
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

ResourceRecord::ResourceRecord(){};

ResourceRecord::ResourceRecord(const char * name, uint16_t rType, uint16_t rClass, uint32_t ttl, uint16_t rdLength, vector<uint8_t> rData): _rType(rType), _rClass(rClass), _ttl(ttl), _rdLength(rdLength){

	_rData = rData;
	convertCStringToOctetForm(name, _name);

}

ResourceRecord::ResourceRecord(const vector<uint8_t>::iterator start, vector<uint8_t>::iterator & iter, const vector<uint8_t>::iterator end, bool& succeeded){

	convertBufferNameToVector(start, iter, end, _name, 0);
	
	_rType = 0;
	_rClass = 0;
	_ttl = 0;
	_rdLength = 0;
	if(!(distance(iter,end) < 10)){
		
		_rType = ((((uint16_t)(*iter)) & 0xff) << 8) | (((uint16_t) *(iter + 1)) & 0xff);
		iter = iter + 2;
		_rClass = ((((uint16_t)(*iter)) & 0xff) << 8) | (((uint16_t) *(iter + 1)) & 0xff);
		iter = iter + 2;
		_ttl = ((((uint32_t)(*iter)) & 0xff) << 24) | ((((uint32_t) *(iter + 1)) & 0xff) << 16) | ((((uint32_t) *(iter + 2)) & 0xff) << 8) | ((((uint32_t) *(iter + 3)) & 0xff));
		iter = iter + 4;
		_rdLength = ((((uint16_t)(*iter)) & 0xff) << 8) | (((uint16_t) *(iter + 1)) & 0xff);
		iter = iter + 2;
		succeeded = true;
	}
	else succeeded = false;
	
	
	for(uint16_t i = 0; (i < _rdLength) && (iter != end); i++){
		
		_rData.push_back(*iter);
		iter = iter + 1;
	}

}

void ResourceRecord::toBuffer(vector<uint8_t> & buffer){

	convertOctetSequenceToBuffer(_name, buffer);
	
	buffer.push_back((_rType & 0xff00) >> 8);
	buffer.push_back(_rType & 0x00ff);

	buffer.push_back((_rClass & 0xff00) >> 8);
	buffer.push_back(_rClass & 0x00ff);
	
	buffer.push_back((_ttl & 0xff000000) >> 24);
	buffer.push_back((_ttl & 0x00ff0000) >> 16);
	buffer.push_back((_ttl & 0x0000ff00) >> 8);
	buffer.push_back(_ttl & 0x000000ff);
	
	buffer.push_back((_rdLength & 0xff00) >> 8);
	buffer.push_back(_rdLength & 0x00ff);

	for(uint16_t i = 0; i < _rdLength; i++){
		
		buffer.push_back(_rData[i]);
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
	cout << "rData(resource data): [";
	for(auto iter = _rData.begin(); iter != _rData.end(); iter++){
		cout << " " << +(*iter);
	}
	cout << "]" << endl;
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^END RESOURCERECORD " << number << " ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;



}

uint32_t ResourceRecord::getInternetData(vector<uint8_t> data){

	if(data.size() < 4) return 0;
	else return (((uint32_t)data[0]) << 24) |  (((uint32_t)data[1]) << 16) |  (((uint32_t)data[2]) << 8) |  (((uint32_t)data[3]));
	
}

string ResourceRecord::getNSData(vector<uint8_t>& msgBuff, vector<uint8_t>& data){
	
	vector<uint8_t> realDomain;
	vector<uint8_t>::iterator beg = msgBuff.begin();
	cout << "BUFFER" << endl;
	for(auto iter = msgBuff.begin(); iter != msgBuff.end(); iter++){
		cout << (int) *iter << " ";
	
	}
	cout << endl;
	convertBufferNameToVector(beg , beg, msgBuff.end(), realDomain, 0, &data);
	
	
	
	string s;
	for(auto iter = realDomain.begin(); iter != realDomain.end(); iter++){
		s += *iter;
	
	}
	return s;
	
}

DNSMessage::DNSMessage(){};

DNSMessage::DNSMessage(const DNSHeader& hdr, vector<QuestionRecord>& question, vector<ResourceRecord>& answer, vector<ResourceRecord>& authority, vector<ResourceRecord>& additional): _hdr(hdr), _question(question), _answer(answer), _authority(authority), _additional(additional){};

DNSMessage::DNSMessage(const vector<uint8_t>::iterator start, vector<uint8_t>::iterator & iter, const vector<uint8_t>::iterator end){

	//first two will be tcp length, which can be disregarded
	iter = iter + 2;

	bool recordSucceeded = true;
	
	_hdr = DNSHeader(iter, end, recordSucceeded);
	
	for(uint16_t i = 0; (i < _hdr._numQuestions) && recordSucceeded; i++){
	
		_question.push_back(QuestionRecord(start,iter,end,recordSucceeded));
	}
	
	for(uint16_t i = 0; (i < _hdr._numAnswers) && recordSucceeded; i++){
	
		_answer.push_back(ResourceRecord(start,iter,end,recordSucceeded));
	}
	
	for(uint16_t i = 0; (i < _hdr._numAuthRR) && recordSucceeded; i++){
	
		_authority.push_back(ResourceRecord(start,iter,end,recordSucceeded));
	}
	
	for(uint16_t i = 0; (i < _hdr._numAdditRR) && recordSucceeded; i++){
	
		_additional.push_back(ResourceRecord(start,iter,end,recordSucceeded));
	}


}

void DNSMessage::toBuffer(vector<uint8_t> & buffer){

	//these two bytes will be filled by the network part with the length number(needed when using dns with tcp)
	buffer.push_back(0);
	buffer.push_back(0);
	
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
	
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^START QUESTIONS^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;
	for(uint16_t i = 0; i < _hdr._numQuestions; i++){
	
		_question[i].print(i);
	}
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^END QUESTIONS^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;
	
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^START ANSWERS^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;
	
	for(uint16_t i = 0; i < _hdr._numAnswers; i++){
	
		_answer[i].print(i);
	}
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^END ANSWERS^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;
	
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^START AUTHORITY^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;
	for(uint16_t i = 0; i < _hdr._numAuthRR; i++){
	
		_authority[i].print(i);
	}
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^END AUTHORITY^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;
	
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^START ADDITIONAL^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;
	
	for(uint16_t i = 0; i < _hdr._numAdditRR; i++){
	
		_additional[i].print(i);
	}
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^END ADDITIONAL^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;
	cout << "^^^^^^^^^^^^^^^^^^^^^^^^^^END DNSMESSAGE^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" << endl;


}



