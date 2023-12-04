#include "pch.h"
#include "ICMP_Socket.h"

void ICMP_Socket::InitializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        throw std::runtime_error("WSAStartup failed with error: " + std::to_string(result));
    }
}
ICMP_Socket::ICMP_Socket() {
    InitializeWinsock();

    ttl = 1;
    seqNumber = 1;

    // Raw socket to send ICMP pkts
	icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (icmp_sock == INVALID_SOCKET) {
        // Cleanup Winsock
        WSACleanup();
        throw std::runtime_error("Failed to create ICMP socket with error: " + std::to_string(WSAGetLastError()));
    }


}

ICMP_Socket::~ICMP_Socket() {
    if (icmp_sock != INVALID_SOCKET) {
        closesocket(icmp_sock);
    }
    WSACleanup();
}

u_short ICMP_Socket::ComputeChecksum(u_short *sendBuf, int size) {
    u_long cksum = 0;

    /* sum all the words together, adding the final byte if size is odd */
    while (size > 1)
    {
        cksum += *sendBuf++;
        size -= sizeof(u_short);
    }
    
    if (size) 
        cksum += *(u_char*)sendBuf;

    /* add carry bits to lower u_short word */
    cksum = (cksum >> 16) + (cksum & 0xffff);

    /* return a bitwise complement of the resulting mishmash */
    return (u_short)(~cksum);
}

void ICMP_Socket::Create_ICMP_Header() {
    // Set up the ICMP header
    icmpHdr.type = ICMP_ECHO_REQUEST;
    icmpHdr.code = 0;
    processId = GetProcessId();
    icmpHdr.id = processId;
    icmpHdr.seq = seqNumber;

    printf("ICMP Packet Details:\n\nProcess ID: %d\nType: ICMP_ECHO_REQUEST\nSequence Number: %d", icmpHdr.id, icmpHdr.seq);

    icmpHdr.checksum = 0; // Initialize checksum to 0 before calculation
    packet_size = sizeof(ICMPHeader); // Size of the ICMP packet
    icmpHdr.checksum = ComputeChecksum((u_short*)&icmpHdr, packet_size); // Compute and set the checksum

    // Set the TTL for the packet
    if (setsockopt(icmp_sock, IPPROTO_IP, IP_TTL, (const char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
        printf("setsockopt failed with %d\n", WSAGetLastError());
        closesocket(icmp_sock);
        // Perform any necessary cleanup
        exit(-1);
    }

    std::cout << "ttl: " << ttl << std::endl;   
}




u_short ICMP_Socket::GetProcessId() const {
    return (u_short)GetCurrentProcessId();
}

void ICMP_Socket::SetDestAddress(const char* destAddress) {
	DWORD IP = inet_addr(destAddress);
    if (IP == INADDR_NONE) {
        if ((destHost = gethostbyname(destAddress)) == NULL) {
			throw std::runtime_error("Unable to resolve destination address");
		}
        else {
			memcpy((char*)&(destAddr.sin_addr), destHost->h_addr, destHost->h_length);
		}
    }
    else {
        destAddr.sin_addr.S_un.S_addr = IP;
    }
    // print the resolved destination IP address
    std::cout << "Destination IP: " << inet_ntoa(destAddr.sin_addr) << std::endl;

    destAddr.sin_family = AF_INET;
    destAddr.sin_port = 0;  
}

int ICMP_Socket::SendICMPPacket() {
    // Populate the packet buffer with the IP and ICMP headers
    PopulatePacketBuffer();
    PrintHeaders();

    std::cout << "\n\nDestination IP address:\n";
    std::cout << inet_ntoa(destAddr.sin_addr) << std::endl;
    
    int bytesSent = sendto(icmp_sock, (char*)sendBuf, packet_size, 0, (sockaddr*)&destAddr, sizeof(destAddr));

    if (bytesSent == SOCKET_ERROR) {
        std::cerr << "sendto() failed with error: " << WSAGetLastError() << std::endl;
        return -1;  // Return -1 to indicate an error
    }
    ttl++;
    seqNumber++;

    return bytesSent;  // Return the number of bytes sent
}


bool ICMP_Socket::ReceiveICMPResponse() {
    sockaddr_in fromAddr;
    int fromAddrLen = sizeof(fromAddr);

    int bytesReceived = recvfrom(icmp_sock, recvBuf, MAX_REPLY_SIZE, 0, (sockaddr*)&fromAddr, &fromAddrLen);

    if (bytesReceived == SOCKET_ERROR) {
		// Handle error case
        throw std::runtime_error("recvfrom() failed with error code: " + std::to_string(WSAGetLastError()));
		return false;
	}

    if ()


    //bool ttl_expired = false;
    //while (!ttl_expired) {
    //    receivedBytes = recvfrom(icmp_sock, recvBuf, MAX_REPLY_SIZE, 0, (sockaddr*)&fromAddr, &fromAddrLen);
    //    if (receivedBytes == SOCKET_ERROR) {
    //        // Handle error case
    //        std::cerr << "recvfrom() failed with error code: " << WSAGetLastError() << std::endl;
    //        return false;
    //    }
    //    if (receivedBytes > 0) {
    //        std::cout << "Received " << receivedBytes << " bytes from " << inet_ntoa(fromAddr.sin_addr) << std::endl;
    //        if (receivedBytes == 56) {
    //            IPHeader* router_ip_hdr = (IPHeader*)recvBuf;
    //            ICMPHeader* router_icmp_hdr = (ICMPHeader*)(router_ip_hdr + 1);
    //            IPHeader* orig_ip_hdr = (IPHeader*)(router_icmp_hdr + 1);
    //            ICMPHeader* orig_icmp_hdr = (ICMPHeader*)(orig_ip_hdr + 1);

    //            if (router_icmp_hdr->type == ICMP_TTL_EXPIRED)
    //                std::cout << "TTL Expired" << std::endl;
    //        }
    //    }
    //    else {
    //        std::cout << "No bytes received" << std::endl;
    //    }
    //}

    // Parse the response
    //ParseICMPResponse(receivedBytes, fromAddr);
    return true;
}

void ICMP_Socket::ParseICMPResponse(int receivedBytes, sockaddr_in& fromAddr) {
    // Assuming the first 28 bytes are the IP header and ICMP header
    IPHeader* ipHdr = (IPHeader*)recvBuf;
    ICMPHeader* icmpHdr = (ICMPHeader*)(recvBuf + sizeof(IPHeader));

    // Now extract the original IP header and ICMP header sent by us
    IPHeader* origIpHdr = (IPHeader*)(recvBuf + sizeof(IPHeader) + sizeof(ICMPHeader));
    ICMPHeader* origIcmpHdr = (ICMPHeader*)(recvBuf + 2 * sizeof(IPHeader) + sizeof(ICMPHeader));

    // Check the ID field of the original ICMP header to match our process ID
    if (origIcmpHdr->id == GetProcessId()) {
        // This response is in reply to our probe
        ICMPResponse response;
        response.sourceAddr = fromAddr;
        response.resolved = false; // We haven't resolved the hostname yet
        responses.push_back(response);
    }
    else {
        // This response is not for our probe, ignore it
    }
}

void ICMP_Socket::SetIpAddresses(const char* destAddress) {
    // Resolve the destination address
    destAddr.sin_addr.s_addr = inet_addr(destAddress);
    if (destAddr.sin_addr.s_addr == INADDR_NONE) {
        destHost = gethostbyname(destAddress);
        if (destHost == NULL) {
            int errorVal = WSAGetLastError();
            throw std::runtime_error("Unable to resolve destination address, error code: " + std::to_string(errorVal));
        }
        memcpy(&destAddr.sin_addr, destHost->h_addr, destHost->h_length);
    }
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = 0;
    // Print the resolved destination IP address
    std::cout << "Destination IP: " << inet_ntoa(destAddr.sin_addr) << std::endl;

    // Set destination IP address in the IP header
    ipHdr.dest_ip = destAddr.sin_addr.s_addr;

    // Set up the source address (the local machine)
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
        int errorVal = WSAGetLastError();
        throw std::runtime_error("Failed to get local host name, error code: " + std::to_string(errorVal));
    }
    destHost = gethostbyname(hostname);
    if (destHost == NULL) {
        int errorVal = WSAGetLastError();
        throw std::runtime_error("Failed to resolve source host name, error code: " + std::to_string(errorVal));
    }
    memcpy(&ipHdr.source_ip, destHost->h_addr, destHost->h_length);

    // Print the source IP address
    std::cout << "Source IP: " << inet_ntoa(*(struct in_addr*)destHost->h_addr) << std::endl;
}


void ICMP_Socket::PopulatePacketBuffer() {
    // Create the ICMP header
    Create_ICMP_Header();

    memcpy(sendBuf, &icmpHdr, sizeof(ICMPHeader));
    // Set the packet size for the entire packet
    packet_size = sizeof(ICMPHeader);
}

void ICMP_Socket::PrintHeaders() {
    // Assuming sendBuf is an array of u_char
    u_char* buf = reinterpret_cast<u_char*>(sendBuf);

    std::cout << "\nICMP Header:" << std::endl;
    for (size_t i = 0; i < sizeof(ICMPHeader); ++i) {
        printf("%02X ", buf[i]);
        if ((i + 1) % 4 == 0) {
            std::cout << std::endl; // Print four bytes per line
        }
    }
}
