#pragma once
#include "pch.h"
#include "NetworkUtils.h"

class ICMP_Socket
{
private:
	IPHeader ipHdr;
	ICMPHeader icmpHdr;
	u_short seqNumber;
	u_short processId;
	u_short checksum;
	int ttl;  // check the logic of this
	int packet_size;

	u_char sendBuf[MAX_ICMP_SIZE];
	sockaddr_in destAddr;
	hostent* destHost;

	char recvBuf[MAX_REPLY_SIZE];
	std::vector<Probe> probes;
	MinHeap timeouts;
	int retxSeqNumber; // check the logic of this

public:
	ICMP_Socket();
	~ICMP_Socket();
	void InitializeWinsock();
	SOCKET icmp_sock;
	

	u_short ComputeChecksum(u_short* sendBuf, int size);
	u_short GetProcessId() const;
	void Create_ICMP_Header();
	int SendICMPPacket(bool retransmitting);
	bool ReceiveICMPResponse();
	bool ProcessEchoResponse(int receivedBytes, sockaddr_in& fromAddr);
	bool ProcessTimeExceededMessage(int receivedBytes, sockaddr_in& fromAddr);
	void SetIpAddresses(const char* destAddress);
	void PopulatePacketBuffer();
	void PrintHeaders();
	void PrintProbeDetails(const Probe& probe, const sockaddr_in& fromAddr);

	MinHeap GetTimeouts() const { return timeouts;  }
	std::pair<std::chrono::steady_clock::time_point, int> GetNextTimeout() const { return timeouts.top(); }
	void SetRetxSeqNumber(int seqNumber) { retxSeqNumber = seqNumber; }


	bool traceFinished;
};

