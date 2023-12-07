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
    traceFinished = false;

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
    else {
		// Send a new probe
		retxSeqNumber = seqNumber;
	}
    // Populate the packet buffer with the IP and ICMP headers
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
        Probe* retxProbe = (Probe*) &probes[retxSeqNumber - 1];
        retxProbe->probeCount++;
        retxProbe->sentTime = sendTime;
        retxProbe->status = RETRANSMITTED;
        timeouts.push(std::make_pair(retxProbe->sentTime + std::chrono::milliseconds(2000), retxSeqNumber));
        retransmitting = false;
    }

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

    if (bytesReceived >= ICMP_ECHO && bytesReceived <= MAX_SIZE) {
        IPHeader* ipResponseHdr = (IPHeader*)recvBuf;
        ICMPHeader* icmpResponseHdr = (ICMPHeader*)(recvBuf + sizeof(IPHeader));

        if (icmpResponseHdr->type == ICMP_ECHO_REPLY) {
            ProcessEchoResponse(bytesReceived, fromAddr);
		}
        else if (icmpResponseHdr->type == ICMP_TTL_EXPIRED) {
            ProcessTimeExceededMessage(bytesReceived, fromAddr);
		}
        else if (icmpResponseHdr->type == ICMP_DEST_UNREACH) {
			std::cout << "Destination Unreachable" << std::endl;
		}
        else {
			std::cout << "Unknown ICMP type" << std::endl;
		}
    }   
    return true;
}

//void ICMP_Socket::ParseICMPResponse(int receivedBytes, sockaddr_in& fromAddr) {
//    // Assuming the first 28 bytes are the IP header and ICMP header
//    IPHeader* ipHdr = (IPHeader*)recvBuf;
//    ICMPHeader* icmpHdr = (ICMPHeader*)(recvBuf + sizeof(IPHeader));
//
//    // Now extract the original IP header and ICMP header sent by us
//    IPHeader* origIpHdr = (IPHeader*)(recvBuf + sizeof(IPHeader) + sizeof(ICMPHeader));
//    ICMPHeader* origIcmpHdr = (ICMPHeader*)(recvBuf + 2 * sizeof(IPHeader) + sizeof(ICMPHeader));
//
//    // Check the ID field of the original ICMP header to match our process ID
//    if (origIcmpHdr->id == GetProcessId()) {
//        // This response is in reply to our probe
//        ICMPResponse response;
//        response.sourceAddr = fromAddr;
//        response.resolved = false; // We haven't resolved the hostname yet
//        responses.push_back(response);
//    }
//    else {
//        // This response is not for our probe, ignore it
//    }
//}

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

bool ICMP_Socket::ProcessEchoResponse(int receivedBytes, sockaddr_in& fromAddr) {

    IPHeader* ipRcvHdr = (IPHeader*)recvBuf;
    ICMPHeader* icmpHdr = (ICMPHeader*)(recvBuf + sizeof(IPHeader));

    // Check the ID field of the original ICMP header to match our process ID
    if (icmpHdr->id == GetProcessId()) {
        if (ipRcvHdr->source_ip == ipHdr.dest_ip) {
            this->traceFinished = true;
        }
        auto now = std::chrono::steady_clock::now();
        int ttlIndex = icmpHdr->seq - 1; // Assuming sequence number starts from 1
        if (ttlIndex >= 0 && ttlIndex < probes.size()) {
            probes[ttlIndex].status = RECEIVED;
            probes[ttlIndex].receiveTime = now;
            probes[ttlIndex].rtt = std::chrono::duration_cast<std::chrono::milliseconds>(now - probes[ttlIndex].sentTime);

            // Print the output
            PrintProbeDetails(probes[ttlIndex], fromAddr);
        }
        return true;
    }
    return false;
}

bool ICMP_Socket::ProcessTimeExceededMessage(int receivedBytes, sockaddr_in& fromAddr) {
    IPHeader* ipHdr = (IPHeader*)recvBuf;
    ICMPHeader* icmpHdr = (ICMPHeader*)(recvBuf + sizeof(IPHeader));

    if (icmpHdr->type == ICMP_TTL_EXPIRED) {
        IPHeader* origIpHdr = (IPHeader*)(recvBuf + sizeof(IPHeader) + sizeof(ICMPHeader));
        ICMPHeader* origIcmpHdr = (ICMPHeader*)(recvBuf + sizeof(IPHeader) + sizeof(ICMPHeader) + sizeof(IPHeader));

        if (origIcmpHdr->id == GetProcessId()) {
            auto now = std::chrono::steady_clock::now();
            int ttlIndex = origIcmpHdr->seq - 1;
            if (ttlIndex >= 0 && ttlIndex < probes.size()) {
                probes[ttlIndex].status = RECEIVED;
                probes[ttlIndex].receiveTime = now;
                probes[ttlIndex].rtt = std::chrono::duration_cast<std::chrono::milliseconds>(now - probes[ttlIndex].sentTime);

                // Print the output
                PrintProbeDetails(probes[ttlIndex], fromAddr);
            }
            return true;
        }
    }
    return false;
}
