#include "resolver.h"
#include <string>
#include <utility>
#include <list>
#include <ostream>
#include <iostream>
#include "network.h"
#include <memory>
#include <vector>

using namespace std;

const string domainCommand = "-domain";
const string typeCommand = "-type";
const string helpCommand = "-help";
const string quitCommand = "-quit";
const string queryCommand = "-query";

const string startMessage = "DNS Resolver. Command loop started...\n";

const string helpMessage = quitCommand + " to quit. " + helpCommand + " for help. " + domainCommand + " flag specifies a domain to resolve. \n "  + typeCommand + " flag specifies the type of query.\n Currently supported query types: \n -A: address query \n -CName: canonical name query \n -Ns: name server query \n -All: all record query \n -Ptr: domain pointer query";


enum class PrimaryCommand{

	none,
	quit,
	help,
	query

};

void splitCommand(string command, vector<string>& splits){
	
	while(true){
		
		size_t ind = command.find(" ");
		if(ind == string::npos){
			splits.push_back(command);
			break;
		}	
		else{
			splits.push_back(command.substr(0,ind));
			command = command.substr(ind + 1);
		
		}
		
	}

}

PrimaryCommand parsePrimaryCommand(vector<string>& parts){
	
	auto end = parts.end();
	
	for(auto iter = parts.begin(); iter < end; iter++){
	
		if(*iter == helpCommand){
			cout << "Ignoring other parts of command because the help command was used." << endl;
			cout << helpMessage << endl;
			return PrimaryCommand::help;
		}
		
		if(*iter == quitCommand){
			cout << "Quitting program." << endl;
			return PrimaryCommand::quit;
		}
		
		if(*iter == queryCommand){
			cout << "Initiating query..." << endl;
			return PrimaryCommand::query;
		}
		
	}
	
	cout << "Did not recognize a primary command. Use the " + helpCommand + " for help." << endl;
	return PrimaryCommand::none;

}

void parseQuery(vector<string>& parts, string& domain, string& type){

	auto end = parts.end();
	domain = "";
	type = "";
	
	for(auto iter = parts.begin(); iter < end; iter++){
		
		if(*iter == domainCommand){
			
			iter = iter + 1;
			if(iter >= end){
				cout << "Missing argument to domain command." <<endl;
				break;
			}
			domain = *iter;
			
		}
		
		if(*iter == typeCommand){
			
			iter = iter + 1;
			if(iter >= end){
				cout << "Missing argument to query type command." <<endl;
				break;
			}
			type = *iter;
			
		}
	}
}


shared_ptr<QueryState> buildQuery(string domain, string type, bool& success){


	if(type == "A"){
		success = true;
		shared_ptr<QueryInstruction> qi = make_shared<AQueryInstruction>();
		return make_shared<QueryState>(domain, (uint16_t)ResourceTypes::a, (uint16_t)ResourceClasses::in, qi);
		
	}
	else if(type == "CName"){
		success = true;
		shared_ptr<QueryInstruction> qi = make_shared<CNameQueryInstruction>();
		return make_shared<QueryState>(domain, (uint16_t)ResourceTypes::cname, (uint16_t)ResourceClasses::in, qi);
	
	}
	else if(type == "NS"){
		success = true;
		shared_ptr<QueryInstruction> qi = make_shared<NSQueryInstruction>();
		return make_shared<QueryState>(domain, (uint16_t)ResourceTypes::ns, (uint16_t)ResourceClasses::in, qi);
	
	}
	else if(type == "All"){
		success = true;
		shared_ptr<QueryInstruction> qi = make_shared<AllQueryInstruction>();
		return make_shared<QueryState>(domain, (uint16_t)ResourceTypes::all, (uint16_t)ResourceClasses::in, qi);
	
	}
	else if(type == "Ptr"){
		success = true;
		shared_ptr<QueryInstruction> qi = make_shared<PtrQueryInstruction>();
		return make_shared<QueryState>(domain, (uint16_t)ResourceTypes::ptr, (uint16_t)ResourceClasses::in, qi);
	
	}
	else{
		cout << "Query type " + type + " is not supported yet. Use the " + helpCommand + " command for a list of supported types." << endl;
		success = false;
		return make_shared<QueryState>();
	}
	

}


void makeQuery(string domain, string type){

	loadSafeties("./safety.txt");

	bool success = false;
	shared_ptr<QueryState> q = buildQuery(domain,type,success);
	if(!success) return;
	
	moreThreads.store(true);
	QueryState::solveStandardQuery(q);
	q->displayResult();
	moreThreads.store(false);
	
	
	while(true){
	
		threadMutex.lock();
		if(threads.size() < 1){
			threadMutex.unlock();
			break;
		}
		else{
			thread& t = threads.back();
			if(t.joinable()){
				threadMutex.unlock();
				t.join();
			}
			else{
				threadMutex.unlock();
				threads.pop_back();
			
			}
			
		
		}
	

	}
	
	dumpCacheToFile();

}


int main(int argc, char** argv){

	cout << startMessage << endl;
	
	bool running = true;
	string command = "";
	
	while(running){
	
		cout << "Please enter a command: ";
		getline(cin,command);
		if(command == ""){
			cout << "Entered an empty command. Use the " + helpCommand + " command for information about this program.";
			continue;
		}
		
		vector<string> commandParts;
		splitCommand(command, commandParts);
	
		PrimaryCommand c = parsePrimaryCommand(commandParts);
		
		switch(c){
		
			case PrimaryCommand::quit:
				running = false;
				break;
			case PrimaryCommand::help:
				break;
			case PrimaryCommand::query:
			{
				string domain;
				string type;
				parseQuery(commandParts,domain,type);
				if(domain == "" || type == ""){
					cout << "missing query argument" << endl;
					break;
				}
				makeQuery(domain,type);
				break;
			}
			case PrimaryCommand::none:
				break;
			default:
				break;
		}
			
	}
	

	return 0;


}
