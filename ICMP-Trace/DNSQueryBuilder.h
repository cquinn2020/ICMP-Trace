#pragma once
#include "pch.h"
#include "NetworkUtils.h"


class DNSQueryBuilder {

private:
    enum class QueryType {
        A,
        PTR,
        UNKNOWN
    };
    FixedDNSheader fdh; // fixed DNS header
    std::vector<char> queryBuffer; // buffer to hold the constructed DNS query
    std::string domainName; // domain name to be resolved
    std::string destinationIPAddress; // IP address of the DNS server
    u_short transactionID; // 16 bit transaction ID
    QueryType queryType; // type of query to be sent
    void initializeFixedDNSHeader();
    void setQuestionHeader();
    std::string reverseIP(const std::string& ip);

public:
    bool typeA = false;

    DNSQueryBuilder();
    std::vector<char> domainToLabel(const std::string& domain);
    QueryType determineQueryType(const std::string& input);
    void setDomainName(const std::string& domain) { this->domainName = domain; }
    void setIpAddress(const std::string& ip) { this->destinationIPAddress = ip; }
    void constructDNSPacket();
    std::vector<char> getConstructedPacket() { return this->queryBuffer; }
    void setTransactionID(u_short id) { this->transactionID = id; }
    USHORT getTransactionID() { return this->transactionID; }
    void displayQueryInfo() const;
    void prepareQueryPacket(const std::string& domainOrIP, const std::string& serverIP, int txId);
};