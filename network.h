#pragma once

#include <string>
#include <vector>
#include <cstdint>

enum class NetworkErrors{

	none = 0,
	socket = 1,
	sending = 2,
	recieving = 3,
	user = 4
};


int sendMessageResolverClient(std::string serverIp, std::vector<uint8_t>& msg, std::vector<uint8_t>& resp);
