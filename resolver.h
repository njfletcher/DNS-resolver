#pragma once

#include <string>
#include <utility>
#include <list>
#include <memory>
#include "structures.h"

enum class SessionStates{

	answered = 0,
	continued = 1,
	failed = 2

};

enum class qrVals{

	query = 0,
	response = 1

};

enum class opcodes{

	standard = 0, //a standard query (QUERY)
	inverse = 1, // an inverse query (IQUERY)
	status = 2 //a server status request (STATUS)

};

enum class ResourceTypes{

	a = 1, // a host address
	ns = 2, // an authoritative name server
	cname = 5, //the canonical name for an alias
	soa = 6, //marks the start of a zone of authority
	mb = 7, //a mailbox domain name
	mg = 8, // a mail group member
	mr = 9, // a mail rename domain name,
	nullR = 10, // a null resource record
	wks = 11, // a well known server description
	ptr = 12, // a domain name pointer
	hinfo = 13, // host information
	minfo = 14, //mailbox or mail list information
	mx = 15, //mail exchange
	txt = 16, //text strings
	afxr = 252, // a request for a transfer of an entire zone
	mailb = 253,//a request for mailbox related records( MB, MG, or MR)
	all = 255// a request for all records(*)

};

enum class ResourceClasses{

	in = 1, //the internet
	ch = 3, //the CHAOS class
	hs = 4, //Hesiod
	all = 255 //all classes

};

enum class ResponseCodes{

	none = 0, // no errors
	format = 1, // the name server was unable to interpret the query
	server = 2, //The name server wasunable to process this query due to a problem with the name server
	name = 3, //Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does  not exist.
	implement = 4, //The name server does not support the requested kind of query
	refused = 5 //The name server refuses to perform the specified operation for policy reasons.  For example, 
	//a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data

};

std::shared_ptr< std::list<std::pair<std::string,std::string>> > readSafetyFile(std::string filePath);
std::shared_ptr<DNSMessage> sendStandardQuery(std::string nameServerIp, std::string questionDomainName, uint16_t id);
int continueQuery(DNSMessage & resp, std::vector<std::string>& answerIps, std::vector<std::pair<std::string, std::string> >& authMaps, std::vector<std::pair<std::string, std::string> >& additMaps);
int solveStandardQuery(std::string nameServerIp, std::string questionDomainName, uint16_t id, std::vector<std::string>& answers)





