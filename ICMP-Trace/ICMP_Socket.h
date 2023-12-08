#pragma once
#include "pch.h"
#include "NetworkUtils.h"
#include "UDPClient.h"
#include "DNSQueryBuilder.h"
#include "DNSResponseParser.h"


class ICMP_Socket
{
private:

	// icmp related variables
	IPHeader ipHdr;
	ICMPHeader icmpHdr;
	u_short seqNumber;
	u_short processId;
	u_short checksum;
	int ttl;  
	int packet_size;

	// sending related variables
	u_char sendBuf[MAX_ICMP_SIZE];
	sockaddr_in destAddr;
	hostent* destHost;

	char recvBuf[MAX_REPLY_SIZE];
	
	std::vector<Probe> probes;
	MinHeap timeouts;
	std::unordered_map<int, std::chrono::steady_clock::time_point> probeTimeouts;

	int retxSeqNumber;

	
	void InitializeUDPClient();

public:
	ICMP_Socket();
	~ICMP_Socket();
	void InitializeWinsock();
	SOCKET icmp_sock;
	

	u_short ComputeChecksum(u_short* sendBuf, int size);
	u_short GetProcessId() const;
	void Create_ICMP_Header();
	int SendICMPPacket(bool retransmitting);
	ICMP_ResponseInfo ReceiveICMPResponse();
	ICMP_ResponseInfo ProcessTimeExceededMessage(int receivedBytes, sockaddr_in& fromAddr);
	ICMP_ResponseInfo ProcessEchoResponse(int receivedBytes, sockaddr_in& fromAddr);
	void SetIpAddresses(const char* destAddress);
	void PopulatePacketBuffer();
	void PrintHeaders();
	void PrintProbeDetails(const Probe& probe, const sockaddr_in& fromAddr);
	void SendDNSQuery(const std::string& ipAddress, int txId);
	std::chrono::milliseconds CalculateDynamicRTO(int currentSeqNumber);
	void HandleTimeout();
	Probe* GetProbe(int seqNumber) { return &probes[seqNumber - 1]; }
	void UpdateProbeDNSInfo(int seqNumber, const std::string& dnsName, bool dnsResolved);


	MinHeap GetTimeouts() const { return timeouts;  }
	std::pair<std::chrono::steady_clock::time_point, int> GetNextTimeout();
	void SetRetxSeqNumber(int seqNumber) { retxSeqNumber = seqNumber; }

	bool traceFinished;
	bool echoResponseFromDest;

	// dns related variables
	UDPClient* udpClient;	
	DNSQueryBuilder dnsQueryBuilder;
	DNSResponseParser dnsResponseParser;


};

