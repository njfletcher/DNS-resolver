#pragma once

#include <string>
#include <vector>
#include <cstdint>

int sendMessageResolverClient(std::string serverIp, const std::vector<uint8_t>& msg, std::vector<uint8_t>& resp);
