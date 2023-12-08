#include "pch.h"
#include "ICMP_Socket.h"

void ICMP_Socket::InitializeWinsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        throw std::runtime_error("WSAStartup failed with error: " + std::to_string(result));
    }
}

ICMP_Socket::ICMP_Socket(): udpClient(nullptr)   {
    InitializeWinsock();
    
    ttl = 1;
    seqNumber = 1;
    traceFinished = false;
    echoResponseFromDest = false;

    // Raw socket to send ICMP pkts
	icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
   

    if (icmp_sock == INVALID_SOCKET) {
        // Cleanup Winsock
        WSACleanup();
        throw std::runtime_error("Failed to create ICMP socket with error: " + std::to_string(WSAGetLastError()));
    }

    u_long mode = 1; // Non-zero value sets the socket to non-blocking mode
    if (ioctlsocket(icmp_sock, FIONBIO, &mode) != NO_ERROR) {
        throw std::runtime_error("Failed to set non-blocking mode: " + std::to_string(WSAGetLastError()));
    }

    InitializeUDPClient();


}


ICMP_Socket::~ICMP_Socket() {
    if (icmp_sock != INVALID_SOCKET) {
        closesocket(icmp_sock);
    }
    WSACleanup();
    delete udpClient;
}

std::pair<std::chrono::steady_clock::time_point, int> ICMP_Socket::GetNextTimeout() {
    auto nextTimeout = timeouts.top();
    timeouts.pop();  
    return nextTimeout;
}


void  ICMP_Socket::InitializeUDPClient() {
	udpClient = new UDPClient();
    
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
}

u_short ICMP_Socket::GetProcessId() const {
    return (u_short)GetCurrentProcessId();
}

int ICMP_Socket::SendICMPPacket(bool retransmitting) {
    if (retransmitting && (retxSeqNumber > 0)) {
		// Retransmit the probe with the given sequence number
		seqNumber = retxSeqNumber;
	}

    PopulatePacketBuffer();
    auto sendTime = std::chrono::steady_clock::now();   
    int bytesSent = sendto(icmp_sock, (char*)sendBuf, packet_size, 0, (sockaddr*)&destAddr, sizeof(destAddr));

    if (bytesSent == SOCKET_ERROR) {
        std::cerr << "sendto() failed with error: " << WSAGetLastError() << std::endl;
        return -1;  // Return -1 to indicate an error
    }
    
    
    if (!retransmitting) {
        Probe newProbe(seqNumber);
        newProbe.sentTime = sendTime;
        probes.push_back(newProbe);

        // Insert the probe into the min-heap with a default RTO of 500 ms
        timeouts.push(std::make_pair(newProbe.sentTime + std::chrono::milliseconds(500), seqNumber));
		// Increment the TTL and sequence number for the next probe
		ttl++;
		seqNumber++;
    }
    else {
        // Retransmit the probe with the given sequence number
        seqNumber = retxSeqNumber;

        // Calculate dynamic RTO for retransmission based on neighbors
        //std::chrono::milliseconds dynamicRTO = CalculateDynamicRTO(retxSeqNumber - 1);
        std::chrono::milliseconds dynamicRTO =std::chrono::milliseconds(500);

        int rtxIndex = retxSeqNumber - 1;
        Probe* retxProbe = (Probe*)&probes[rtxIndex];
        retxProbe->probeCount++;
        retxProbe->sentTime = sendTime;
        retxProbe->status = RETRANSMITTED;
      

        // Insert the probe into the min-heap with the calculated dynamic RTO
        timeouts.push(std::make_pair(retxProbe->sentTime + dynamicRTO, retxSeqNumber));
        retransmitting = false;
    }

    return bytesSent;  // Return the number of bytes sent
}

ICMP_ResponseInfo ICMP_Socket::ReceiveICMPResponse() {
    sockaddr_in fromAddr;
    int fromAddrLen = sizeof(fromAddr);

    int bytesReceived = recvfrom(icmp_sock, recvBuf, MAX_REPLY_SIZE, 0, (sockaddr*)&fromAddr, &fromAddrLen);

    if (bytesReceived == SOCKET_ERROR) {
		// Handle error case
        throw std::runtime_error("recvfrom() failed with error code: " + std::to_string(WSAGetLastError()));
		
	}

    if (bytesReceived >= ICMP_ECHO && bytesReceived <= MAX_SIZE) {
        IPHeader* ipResponseHdr = (IPHeader*)recvBuf;
        ICMPHeader* icmpResponseHdr = (ICMPHeader*)(recvBuf + sizeof(IPHeader));

        if (icmpResponseHdr->type == ICMP_ECHO_REPLY) {
            ICMP_ResponseInfo resp = ProcessEchoResponse(bytesReceived, fromAddr);
            return resp;
		}
        else if (icmpResponseHdr->type == ICMP_TTL_EXPIRED) {
            ICMP_ResponseInfo timeExcMsg =  ProcessTimeExceededMessage(bytesReceived, fromAddr);
            return timeExcMsg;
		}
        else if (icmpResponseHdr->type == ICMP_DEST_UNREACH) {
			std::cout << "Destination Unreachable" << std::endl;
		}
        else {
			std::cout << "Unknown ICMP type" << std::endl;
		}
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

void ICMP_Socket::PrintProbeDetails(const Probe& probe, const sockaddr_in& fromAddr) {
    std::string ipAddr = inet_ntoa(fromAddr.sin_addr);
    printf("%d %s %lld ms (%d)\n",
        probe.ttl,
        ipAddr.c_str(),
        probe.rtt.count(),
        probe.probeCount);
}


ICMP_ResponseInfo ICMP_Socket::ProcessEchoResponse(int receivedBytes, sockaddr_in& fromAddr) {
    ICMP_ResponseInfo responseInfo; // Create an instance of ResponseInfo

    IPHeader* ipRcvHdr = (IPHeader*)recvBuf;
    ICMPHeader* icmpHdr = (ICMPHeader*)(recvBuf + sizeof(IPHeader));

    // Convert source IP to human-readable format
    char srcIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipRcvHdr->source_ip), srcIpStr, INET_ADDRSTRLEN);

    // Check the ID field of the original ICMP header to match our process ID
    if (icmpHdr->id == GetProcessId()) {
        responseInfo.sequenceNumber = icmpHdr->seq;

        responseInfo.ipAddress = srcIpStr;

        if (ipRcvHdr->source_ip == ipHdr.dest_ip) {
            this->echoResponseFromDest = true;
        }

        auto now = std::chrono::steady_clock::now();
        int ttlIndex = icmpHdr->seq - 1; // Assuming sequence number starts from 1

        if (ttlIndex >= 0 && ttlIndex < probes.size()) {
            Probe& responseProbe = probes[ttlIndex];
            responseProbe.status = RECEIVED;
            responseProbe.receiveTime = now;
            responseProbe.rtt = std::chrono::duration_cast<std::chrono::milliseconds>(now - responseProbe.sentTime);
            responseProbe.ipAddress = srcIpStr;

        }
    }

    // Return the ResponseInfo structure
    return responseInfo;
}

ICMP_ResponseInfo ICMP_Socket::ProcessTimeExceededMessage(int receivedBytes, sockaddr_in& fromAddr) {
    ICMP_ResponseInfo responseInfo; // Create an instance of ICMP_ResponseInfo

    IPHeader* ipHdr = (IPHeader*)recvBuf;
    ICMPHeader* icmpHdr = (ICMPHeader*)(recvBuf + sizeof(IPHeader));

    std::cout << "Timeout Exceeded Message" << std::endl;

    // Convert source IP to human-readable format
    char srcIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHdr->source_ip), srcIpStr, INET_ADDRSTRLEN);

    if (icmpHdr->type == ICMP_TTL_EXPIRED) {
        IPHeader* origIpHdr = (IPHeader*)(recvBuf + sizeof(IPHeader) + sizeof(ICMPHeader));
        ICMPHeader* origIcmpHdr = (ICMPHeader*)(recvBuf + sizeof(IPHeader) + sizeof(ICMPHeader) + sizeof(IPHeader));

        char strIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(origIpHdr->source_ip), strIp, INET_ADDRSTRLEN);

        if (origIcmpHdr->id == GetProcessId()) {
            auto now = std::chrono::steady_clock::now();
            int ttlIndex = origIcmpHdr->seq - 1;
            if (ttlIndex >= 0 && ttlIndex < probes.size()) {
                probes[ttlIndex].status = RECEIVED;
                probes[ttlIndex].receiveTime = now;
                probes[ttlIndex].rtt = std::chrono::duration_cast<std::chrono::milliseconds>(now - probes[ttlIndex].sentTime);
                probes[ttlIndex].ipAddress = strIp;
            }
            // Fill in the responseInfo structure
            responseInfo.sequenceNumber = origIcmpHdr->seq;
            responseInfo.ipAddress = strIp;
            return responseInfo;
        }
    }
    // Return an empty responseInfo structure if the condition is not met
    return responseInfo;
}


std::chrono::milliseconds ICMP_Socket::CalculateDynamicRTO(int currentSeqNumber) {
    // Define default RTO
    const std::chrono::milliseconds defaultRTO(3000);

    // Check for left and right neighbors
    int leftNeighborIndex = currentSeqNumber - 2; // -2 because currentSeqNumber is already incremented for the next probe
    int rightNeighborIndex = currentSeqNumber;

    bool leftNeighborValid = (leftNeighborIndex >= 0 && probes[leftNeighborIndex].status == RECEIVED);
    bool rightNeighborValid = (rightNeighborIndex < probes.size() && probes[rightNeighborIndex].status == RECEIVED);


    //return defaultRTO;
    if (leftNeighborValid && rightNeighborValid) {
        // Average RTT of both neighbors
        auto avgRtt = (probes[leftNeighborIndex].rtt + probes[rightNeighborIndex].rtt) / 2;
        return avgRtt * 2;
    }
    else if (leftNeighborValid) {
        // Twice the RTT of the left neighbor
        return probes[leftNeighborIndex].rtt * 2;
    }
    else if (rightNeighborValid) {
        // Three times the RTT of the right neighbor
        return probes[rightNeighborIndex].rtt * 3;
    }
    else {
        // Default RTO if no valid neighbors
        return defaultRTO;
    }
}

void ICMP_Socket::SendDNSQuery(const std::string& ipAddress, int txId) {
    std::cout << "Sending DNS query for " << ipAddress << std::endl;
    // Prepare the DNS query packet using DNSQueryBuilder
    dnsQueryBuilder.prepareQueryPacket(ipAddress, "168.63.129.16", txId);
    std::vector<char> packet = dnsQueryBuilder.getConstructedPacket();

    // Send the packet using UDPClient
    if (!udpClient->sendData(packet)) {
        throw std::runtime_error("Failed to send DNS query packet.");
    }


    // push new timeout with 5 seconds for dns query
    timeouts.push(std::make_pair(std::chrono::steady_clock::now() + std::chrono::seconds(5), txId));
    probes[txId - 1].reinsertCount++;
}

void ICMP_Socket::HandleTimeout() {
	// Get the next timeout from the min-heap
	auto nextTimeout = GetNextTimeout();
	auto now = std::chrono::steady_clock::now();
    int seqNumber = nextTimeout.second;
    auto newRTO = CalculateDynamicRTO(seqNumber);

    auto probeTimeout = probeTimeouts.find(seqNumber);
    if (probeTimeout != probeTimeouts.end()) {
        // Check if the probe has timed out more than 3 times
        int probeIndex = seqNumber - 1;
        if (probes[probeIndex].probeCount == 3) {
            probes[probeIndex].status = LOST;
        }
        else {
            // Retransmit the probe
            int probesIndex = seqNumber - 1;
            
            retxSeqNumber = seqNumber;
            probeTimeouts[seqNumber] = now + newRTO;
            probes[probesIndex].status = RETRANSMITTED;
            probes[probesIndex].sentTime = now;
            probes[probesIndex].probeCount++;
            timeouts.push(std::make_pair(now + newRTO, seqNumber));
            
            SendICMPPacket(true);
        }
    }

}   

void ICMP_Socket::UpdateProbeDNSInfo(int seqNumber, const std::string& dnsName, bool dnsResolved) {
    // Access and update the DNS-related information for a specific Probe

    // Ensure seqNumber is within valid range
    if (seqNumber >= 1 && seqNumber <= probes.size()) {
        Probe& probe = probes[seqNumber - 1];
        probe.dnsName = dnsName;  // Update the DNS name
        probe.dnsQuerySent = dnsResolved;  // Update the DNS resolution status

        if (dnsResolved) {
			probe.status = DNS_RESOLVED;
		}
        std::cout << "DNS resolved for probe " << seqNumber << std::endl;
        std::cout << "DNS name: " << dnsName << std::endl;
        std::cout << "Number of probes: " << probes.size() << std::endl;
	}
	else {
		std::cerr << "Invalid sequence number." << std::endl;
    }
}