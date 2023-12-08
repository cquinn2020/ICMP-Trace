#include "pch.h"
#include "UDPClient.h"


UDPClient::UDPClient(int port) : socketFd(INVALID_SOCKET), bindPort(port) {
    memset(&serverAddr, 0, sizeof(serverAddr));

    socketFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socketFd == INVALID_SOCKET) {
        throw std::runtime_error("Failed to create socket: " + std::to_string(WSAGetLastError()));
    }

    u_long mode = 1; // 1 to enable non-blocking mode
    if (ioctlsocket(socketFd, FIONBIO, &mode) != NO_ERROR) {
        closesocket(socketFd);
        throw std::runtime_error("Failed to set non-blocking mode: " + std::to_string(WSAGetLastError()));
    }

    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(port);

    if (bind(socketFd, (struct sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
        closesocket(socketFd);
        throw std::runtime_error("Bind failed: " + std::to_string(WSAGetLastError()));
    }
}


bool UDPClient::setServer(const std::string& ip, int port) {
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(ip.c_str());

    return serverAddr.sin_addr.s_addr != INADDR_NONE;
}

bool UDPClient::sendData(const std::vector<char>& data) {
    int sentBytes = sendto(socketFd, data.data(), data.size(), 0,
        (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    if (sentBytes == data.size()) {
        return true;
    }
    else if (sentBytes == SOCKET_ERROR) {
        std::cout << " socket error " << WSAGetLastError() << std::endl; // Log here
        return false;
    }
}

std::vector<char> UDPClient::receiveData() {
    std::vector<char> buffer(MAX_DNS_SIZE);
    struct sockaddr_in responseAddr;
    int responseAddrLen = sizeof(responseAddr);

    int attempts = 0;
    while (attempts < 1) {
        int receivedBytes = recvfrom(socketFd, buffer.data(), buffer.size(), 0,
            (struct sockaddr*)&responseAddr, &responseAddrLen);

        if (receivedBytes != SOCKET_ERROR) {
            auto endTime = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
            buffer.resize(receivedBytes);
            std::cout << " response in " << elapsed << " ms with " << receivedBytes << " bytes" << std::endl; // Log here
            return buffer;
        }
        else {
            // Check if the error is due to message size
            int error = WSAGetLastError();
            if (error == WSAEMSGSIZE) {
                throw std::runtime_error(" socket error 10040");
            }
        }
        attempts++;
    }

    buffer.clear();
    return buffer;
}


UDPClient::~UDPClient() {
    if (socketFd != INVALID_SOCKET) {
        closesocket(socketFd);
    }
}