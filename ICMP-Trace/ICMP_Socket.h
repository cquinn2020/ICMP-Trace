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
	int ttl;
	int packet_size;

	u_char sendBuf[MAX_ICMP_SIZE];
	sockaddr_in destAddr;
	hostent* destHost;

	char recvBuf[MAX_REPLY_SIZE];
	std::vector<ICMPResponse> responses;

public:
	ICMP_Socket();
	~ICMP_Socket();
	void InitializeWinsock();
	SOCKET icmp_sock;

	u_short ComputeChecksum(u_short* sendBuf, int size);
	u_short GetProcessId() const;
	void Create_ICMP_Header();
	void CreateIPHeader(int ttl, u_short totalLength);
	void SetDestAddress(const char* destAddress);
	int SendICMPPacket();
	bool ReceiveICMPResponse();
	void ParseICMPResponse(int receivedBytes, sockaddr_in& fromAddr);
	void SetIpAddresses(const char* destAddress);
	void PopulatePacketBuffer();
	void PrintHeaders();
};

