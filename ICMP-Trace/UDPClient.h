#pragma once
#include "pch.h"


#define MAX_ATTEMPTS 3
#define MAX_DNS_SIZE 512

class UDPClient {
private:
    struct sockaddr_in serverAddr;
    int bindPort;
    std::chrono::high_resolution_clock::time_point startTime;
public:
    UDPClient(int port = 0);
    ~UDPClient();
    SOCKET socketFd;

    bool setServer(const std::string& ip, int port);
    bool sendData(const std::vector<char>& data);
    std::vector<char> receiveData();
    SOCKET* getSocket() const { return (SOCKET*)socketFd; }
};