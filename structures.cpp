#include "structures.h"
#include <vector>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <bitset>
#include "resolver.h"
#include <ctime>

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

/*
convertCStringToOctetForm-

takes a c string of a domain name that is seperated by periods, and converts it into a buffer that follows the octet form(with length bytes).
ie: a.domain.net becomes 1 a 6 d o m a i n 3 n e t 0
*/

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

/*
convertBufferNameToVector-

takes a begin, current, and end iterator of a vector that holds the raw data of a dns message recieved by the network layer. Turns this into a vector of the full domain name that results from unwrapping multiple layers of compression(if there are any). 
Takes an optional message that acts as an alternative start to the sequence. Once a compression double byte is encountered, it hands control of the sequence to the main message buffer.
An example of when this is needed is the rData section of an NS resource record. This data will be in the octet form, possibly with compression. Want to start with this seperate rData vector, then if compression is found
start traversing the compression pointers using the whole message.

*/

void convertBufferNameToVector(vector<uint8_t>::iterator mainMsgStart, vector<uint8_t>::iterator & mainMsgIter, const vector<uint8_t>::iterator mainMsgEnd, vector<uint8_t> & vec, uint8_t bytesRead, vector<uint8_t>* optMsg= NULL ){

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
				
				//second of two compression options, name field has series of labels that ends with labels at location specified by pointer.
				if (checkCompression(iter, end, compOffset,vec)){
						
					vector<uint8_t>::iterator pointStart = mainMsgStart + compOffset;//make a copy so reading name somewhere else doesnt affect current position of our packet iter.
					convertBufferNameToVector(mainMsgStart, pointStart, mainMsgEnd, vec, bytesRead + 1,NULL);
					break;
				}
				else{
									
					vec.push_back(*iter);
					//0 length terminator
					if(currLength == 0) {
						iter = iter + 1;
						break;
					}	
				
				}
				
		
			}
			//still reading a label
			else{
				
				currCounter = currCounter + 1;
				bytesRead = bytesRead + 1;
				vec.push_back(*iter);

			}
		}	
	
	
	}
	
	
	


}

/*
printOctetSeq-

takes a vector in octet form of a domain name that includes length bytes and compression indicator/offset bytes.
Prints special messages when a length or compression byte is encountered.
*/

void printOctetSeq(const vector<uint8_t> & nameSequence){

	uint8_t currLength = 0;
	uint8_t currCounter = 0;
	for(auto iter = nameSequence.begin(); iter != nameSequence.end(); iter++){
	
		//this byte should be a length byte
		if(currCounter >= currLength){
			
			currLength = *iter;
			if((currLength & 0xC0) == 0xC0){
			
				uint16_t offset = (((uint16_t)(*iter & 0x3F)) << 8);
				iter = iter + 1;
				offset = offset | (((uint8_t)*iter) & 0xff);
				offset = offset + 2;
				currLength = 0;
				currCounter =0;
				cout << "compressed w/ offset: " << offset << " ";
			}
			else{
				cout << " len: " << (+currLength) << " label: ";
				currCounter = 0;
				//0 length terminator
				if(currLength == 0) break;
			}
		}
		//still reading a label
		else{
			currCounter = currCounter + 1;
			cout << " " << (*iter) << " ";

		}
	
	}


}

/*
convertOctetSequenceToBuffer-

takes a vector in octet form of a domain name that includes length bytes and compression indicator/offset bytes.
Writes to the buffer the above sequence until after it finds a compression indicator and offset bytes(if there are any at all).
This allows for the original compression byte sequence to be preserved. 
This is important if this namesequence was read in from a response. 
Say the response had compression, the name vector the response holds will be filled with the whole domain name, ie the result of unwrapping various levels of compression.
If this was written back to a buffer as is, the original byte count/sequence of the response would not be preserved and the message would be corrupted.
So stop writing to the buffer after we see the first compression, which is how the response wouldve been originally.
*/

void convertOctetSequenceToBuffer(const vector<uint8_t> & nameSequence, vector<uint8_t>& buffer){

	uint8_t currLength = 0;
	uint8_t currCounter = 0;
	for(auto iter = nameSequence.begin(); iter != nameSequence.end(); iter++){
	
		//this byte should be a length byte
		if(currCounter >= currLength){
			
			currLength = *iter;
			if((currLength & 0xC0) == 0xC0){
				buffer.push_back(*iter);
				iter = iter + 1;
				buffer.push_back(*iter);
				break;
			}
			else{
				buffer.push_back(*iter);
				currCounter = 0;
				//0 length terminator
				if(currLength == 0) break;
			}
		}
		//still reading a label
		else{
			currCounter = currCounter + 1;
			buffer.push_back(*iter);

		}
	
	}


}

/*
convertOctetSeqToString-

takes a vector in octet form of a domain name that includes length bytes and compression indicator/offset bytes.
converts this to a string that does not have any length/compression bytes, only the ascii labels(seperated by periods).
ie: 1 a compr offset 10 restDomain 0 becomes a.restDomain
*/

string convertOctetSeqToString(const vector<uint8_t> & nameSequence){

	string s;
	uint8_t currLength = 0;
	uint8_t currCounter = 0;
	bool first = true;
	
	for(auto iter = nameSequence.begin(); iter != nameSequence.end(); iter++){
	
		//this byte should be a length byte(dont want any length byte or compression byte in this string)
		if(currCounter >= currLength){
			
			currLength = *iter;
			if((currLength & 0xC0) == 0xC0){
				iter = iter + 1;
				currLength = 0;
				currCounter =0;
			}
			else{
				currCounter = 0;
				//0 length terminator
				if(currLength == 0) break;
				else {
					if (!first) s += ".";
					first = false;
				}
			}
		}
		//still reading a label
		else{
			currCounter = currCounter + 1;
			s += *iter;

		}
	
	}
	return s;

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

string ResourceRecord::getDataAsString(){

	string s;
	for(auto iter = _rData.begin(); iter < _rData.end(); iter++){
		s += *iter;
	
	}
	return s;
}

NSResourceRecord::NSResourceRecord(const vector<uint8_t>::iterator start, vector<uint8_t>::iterator & iter, const vector<uint8_t>::iterator end, bool& succeeded){

	ResourceRecord(start, iter, end, succeeded);
	convertRData(start, end);
}

AResourceRecord::AResourceRecord(const vector<uint8_t>::iterator start, vector<uint8_t>::iterator & iter, const vector<uint8_t>::iterator end, bool& succeeded){

	ResourceRecord(start, iter, end, succeeded);
	convertRData();
}

string convertIpIntToString(uint32_t ip){

	char buffer[INET_ADDRSTRLEN];
	struct in_addr a;
	a.s_addr = ip;
	
	inet_ntop(AF_INET, &a, buffer, INET_ADDRSTRLEN);
	
	string s = string(buffer);
	
	return s;

}

void AResourceRecord::convertRData(){

	if(_rData.size() < 4){
		_ip = 0;
	}
	else{
		aType ip =  (((aType)_rData[3]) << 24) |  (((aType)_rData[2]) << 16) |  (((aType)_rData[1]) << 8) |  (((aType)_rData[0]));
		_ip = ip; 
	}

}

void AResourceRecord::convertRData(){

	if(_rData.size() < 4){
		_ip = 0;
	}
	else{
		aType ip =  (((aType)_rData[3]) << 24) |  (((aType)_rData[2]) << 16) |  (((aType)_rData[1]) << 8) |  (((aType)_rData[0]));
		_ip = ip; 
	}

}

string AResourceRecord::getDataAsString(){

	return convertIpIntToString(_ip);

}

void NSResourceRecord::convertRData(vector<uint8_t>::iterator msgStart, vector<uint8_t>::iterator msgEnd){

	vector<uint8_t> realDomain;
	convertBufferNameToVector(msgStart , msgStart, msgEnd, realDomain, 0, &_rData);
	_domain = convertOctetSeqToString(realDomain);


}

string NSResourceRecord::getDataAsString(){

	return _domain;
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

DNSMessage::DNSMessage(){};

DNSMessage::DNSMessage(const DNSHeader& hdr, vector<QuestionRecord>& question, vector<ResourceRecord>& answer, vector<ResourceRecord>& authority, vector<ResourceRecord>& additional): _hdr(hdr), _question(question), _answer(answer), _authority(authority), _additional(additional){};


ResourceRecord GetCorrectResourceRecord(const vector<uint8_t>::iterator start, vector<uint8_t>::iterator & iter, const vector<uint8_t>::iterator end, bool& succeeded){

	vector<uint8_t>::iterator locIter = iter;
	ResourceRecord r = ResourceRecord(start, locIter, end);
	
	if(r._rType == (uint16_t) ResourceTypes::a){
		
		return AResourceRecord(start,iter,end,succeeded);
	}
	else if(r._rType == (uint16_t) ResourceTypes::ns){
	
		return NSResourceRecord(start,iter,end,succeeded);
	
	}
	else{
	
		return ResourceRecord(start,iter,end,succeeded);
	
	}

}

DNSMessage::DNSMessage(const vector<uint8_t>::iterator start, vector<uint8_t>::iterator & iter, const vector<uint8_t>::iterator end){

	//first two will be tcp length, which can be disregarded
	iter = iter + 2;

	bool recordSucceeded = true;
	
	_hdr = DNSHeader(iter, end, recordSucceeded);
	
	for(uint16_t i = 0; (i < _hdr._numQuestions) && recordSucceeded; i++){
	
		_question.push_back(QuestionRecord(start,iter,end,recordSucceeded));
	}
	
	for(uint16_t i = 0; (i < _hdr._numAnswers) && recordSucceeded; i++){
	
		_answer.push_back(GetCorrectResourceRecord(start,iter,end,recordSucceeded));
	}
	
	for(uint16_t i = 0; (i < _hdr._numAuthRR) && recordSucceeded; i++){
	
		_authority.push_back(GetCorrectResourceRecord(start,iter,end,recordSucceeded));
	}
	
	for(uint16_t i = 0; (i < _hdr._numAdditRR) && recordSucceeded; i++){
	
		_additional.push_back(GetCorrectResourceRecord(start,iter,end,recordSucceeded));
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



