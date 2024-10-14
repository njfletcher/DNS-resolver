#pragma once

#include <string>
#include <utility>
#include <list>
#include <memory>

std::shared_ptr< std::list<std::pair<std::string,std::string>> > readSafetyFile(std::string filePath);
void sendTestQuery();





