#pragma once

#include <string>
#include <utility>
#include <list>
#include <memory>
#include "structures.h"

std::shared_ptr< std::list<std::pair<std::string,std::string>> > readSafetyFile(std::string filePath);
std::shared_ptr<DNSMessage> sendStandardQuery(std::string nameServerIp, std::string questionDomainName, uint16_t id);





