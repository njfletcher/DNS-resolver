#include <string>
#include <utility>
#include <list>
#include <memory>

#pragma once


std::shared_ptr< std::list<std::pair<std::string,std::string>> > readSafetyFile(std::string filePath);
void sendTestQuery();





