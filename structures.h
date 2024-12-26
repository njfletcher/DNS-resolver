#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <iterator>
#include <ctime>
#include "resolver.h"
#include <sstream>

class QueryState;
enum class QueryContext;

class DNSFlags{
	
	friend class DNSMessage;
	
	public:
			
		DNSFlags() = default;
		DNSFlags(uint8_t qr, uint8_t opcode, uint8_t aa, uint8_t tc, uint8_t rd, uint8_t ra, uint8_t z, uint8_t rcode);
		DNSFlags(std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		
		void toBuffer(std::vector<uint8_t> & buffer);
		void buildString(std::stringstream& s);
		void print();
		
	private:
		uint8_t _qr;
		uint8_t _opcode;
		uint8_t _aa;
		uint8_t _tc;
		uint8_t _rd;
		uint8_t _ra;
		uint8_t _z;
		uint8_t _rcode;
	
};

class DNSHeader{

	friend class DNSMessage;
	
	public:		
		DNSHeader() = default;
		DNSHeader(uint16_t transId, const DNSFlags& flags, uint16_t numQuestions, uint16_t numAnswers, uint16_t numAuthRR, uint16_t numAdditRR);
		DNSHeader(std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		
		void toBuffer(std::vector<uint8_t> & buffer);
		void buildString(std::stringstream& s);
		void print();
		
	private:
		uint16_t _transId;
		DNSFlags _flags;
		uint16_t _numQuestions;
		uint16_t _numAnswers;
		uint16_t _numAuthRR;
		uint16_t _numAdditRR;

};

class QuestionRecord{

	public:
		//constructor takes c style string(dont include length octets), the length conversion happens in constructor
		QuestionRecord(const char * name, uint16_t qType, uint16_t qClass);
		QuestionRecord(const std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		QuestionRecord(const QuestionRecord& rec);
		
		void toBuffer(std::vector<uint8_t> & buffer);
		void buildString(std::stringstream& s, uint16_t number = 0);
		void print(uint16_t number = 0);
		
		std::string getName();
		
	private:
		std::vector<uint8_t> _name; // a sequence of octets that repeats the pattern: length octet = n, n octets 
		std::string _realName;
		uint16_t _qType;
		uint16_t _qClass;

};

class ResourceRecord{

	public:		
		//constructor takes c style string(dont include length octets), the length conversion happens in constructor
		ResourceRecord(const char * name, uint16_t rType, uint16_t rClass, uint32_t ttl, uint16_t rdLength, std::vector<uint8_t> rData, bool auth);
		ResourceRecord(const std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
				
		virtual ~ResourceRecord() = default;
		virtual std::string getDataAsString();
		std::string getName();
		virtual void executeInstructions(std::shared_ptr<ResourceRecord> rec, QueryContext cont, QueryState& query);
			
		void toBuffer(std::vector<uint8_t> & buffer);
		void buildString(std::stringstream& s, uint16_t number = 0);
		void print(uint16_t number = 0);
		
		static std::vector<std::shared_ptr<ResourceRecord> >* getRecordsFromCache(std::string domainName);
		static void insertRecordIntoCache(std::shared_ptr<ResourceRecord> r, std::time_t time);
		
		std::shared_ptr<ResourceRecord> GetSpecialResourceRecord(const std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		bool operator==(ResourceRecord& r);
		void determineAuthority(std::vector<std::string>& queryNames, bool authMessage);
		
	protected:
		bool _authoritative; // was this record in the answer section from an authoritative message
		
		std::vector<uint8_t> _name; // a sequence of octets that repeats the pattern: length octet = n, n octets 
		std::string _realName;
		uint16_t _rType;
		uint16_t _rClass;
		uint32_t _ttl; //relative time to live given by server
		std::time_t _cacheExpireTime; //absolute expiration time used by cache
		uint16_t _rdLength; //specified in octets
		std::vector<uint8_t> _rData; //length of rdLength, not null terminated

};

class DNSMessage{

	public:
		DNSMessage(const DNSHeader& hdr, std::vector<QuestionRecord>& question, std::vector<std::shared_ptr<ResourceRecord> >& answer, std::vector<std::shared_ptr<ResourceRecord> >& authority, std::vector<std::shared_ptr<ResourceRecord> >& additional);
		DNSMessage(const std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end);
		
		void toBuffer(std::vector<uint8_t> & buffer);
		void buildString(std::stringstream& s);
		void print();
		void extractData(std::shared_ptr<QueryState> qr, std::time_t time);
		void cacheRecords(std::time_t time);
		bool checkForResponseErrors(uint16_t qId, uint8_t& code);
		
	private:
		DNSHeader _hdr;
		std::vector<QuestionRecord> _question;// one or more questions for the name server to answer
		std::vector<std::shared_ptr<ResourceRecord> > _answer; // zero or more resource records that answer the query
		std::vector<std::shared_ptr<ResourceRecord> > _authority;//zero or more resource records that point to authoritative name servers
		std::vector<std::shared_ptr<ResourceRecord> > _additional; // zero or more resource records that are strictly not answers

};

class NSResourceRecord: public ResourceRecord {
	public:
		~NSResourceRecord() = default;
		std::string getDataAsString();
		void convertRData(std::vector<uint8_t>::iterator msgStart, std::vector<uint8_t>::iterator msgEnd);
		NSResourceRecord(const std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		void executeInstructions(std::shared_ptr<ResourceRecord> rec, QueryContext cont, QueryState& query);
		
	private:
		std::string _domain;
};

class AResourceRecord: public ResourceRecord {
	public:
		~AResourceRecord() = default;
		std::string getDataAsString();
		void convertRData();
		AResourceRecord(const std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		void executeInstructions(std::shared_ptr<ResourceRecord> rec, QueryContext cont, QueryState& query);
		
	private:
		uint32_t _ip;
};

class CNameResourceRecord: public ResourceRecord{

	public:
		~CNameResourceRecord() = default;
		std::string getDataAsString();
		void convertRData(std::vector<uint8_t>::iterator msgStart, std::vector<uint8_t>::iterator msgEnd);
		CNameResourceRecord(const std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator & iter, const std::vector<uint8_t>::iterator end, bool& succeeded);
		void executeInstructions(std::shared_ptr<ResourceRecord> rec, QueryContext cont, QueryState& query);
		
	private:
		std::string _domain;

};


