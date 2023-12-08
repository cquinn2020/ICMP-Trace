#include "pch.h"
#include "DNSQueryBuilder.h"

DNSQueryBuilder::DNSQueryBuilder() {}

DNSQueryBuilder::QueryType DNSQueryBuilder::determineQueryType(const std::string& input) {
    // If the input is a valid IP address, it's a PTR query
    if (inet_addr(input.c_str()) != INADDR_NONE) {
        this->queryType = QueryType::PTR;
        this->typeA = false;
        return QueryType::PTR;
    }

    // Otherwise, assume it's an A record query
    this->queryType = QueryType::A;
    this->typeA = true;
    return QueryType::A;
}

std::vector<char> DNSQueryBuilder::domainToLabel(const std::string& domain) {
    std::vector<char> labelFormat;
    size_t startPos = 0;
    while (true) {
        size_t periodPos = domain.find('.', startPos);
        if (periodPos == std::string::npos) {  // if there's no more period
            labelFormat.push_back(static_cast<char>(domain.length() - startPos));
            for (size_t i = startPos; i < domain.length(); i++) {
                labelFormat.push_back(domain[i]);
            }
            labelFormat.push_back(0);  // null terminator for the label
            break;
        }
        else {
            labelFormat.push_back(static_cast<char>(periodPos - startPos));
            for (size_t i = startPos; i < periodPos; i++) {
                labelFormat.push_back(domain[i]);
            }
            startPos = periodPos + 1;  // next segment starts after the found period
        }
    }
    return labelFormat;
}

void DNSQueryBuilder::initializeFixedDNSHeader() {
    // set the transaction ID as the sequence number of the corresponding icmp packet
    fdh.setID(transactionID);

    // Set the flags: Standard query with recursion desired
    fdh.setFlags(htons(DNS_QUERY | DNS_RD | DNS_STDQUERY));

    fdh.setQuestions(htons(1));

    // Since it's a query, answers, authority, and additional records are 0
    fdh.setAnswers(0);
    fdh.setAuthority(0);
    fdh.setAdditional(0);
}

void DNSQueryBuilder::setQuestionHeader() {
    QueryHeader qh;

    if (queryType == QueryType::A) {
        qh.setQType(htons(DNS_A));  // Assuming DNS_A is 1 for "A" type queries
        qh.setQClass(htons(DNS_INET));  // Internet address
    }
    else if (queryType == QueryType::PTR) {
        qh.setQType(htons(DNS_PTR));
        qh.setQClass(htons(DNS_INET));
    }

    // Push the QueryHeader into the queryBuffer
    char* qhPtr = reinterpret_cast<char*>(&qh);
    for (size_t i = 0; i < sizeof(QueryHeader); i++) {
        queryBuffer.push_back(qhPtr[i]);
    }
}

void DNSQueryBuilder::constructDNSPacket() {
    // 1. Initialize the fixed DNS header
    initializeFixedDNSHeader();

    char* fdhPtr = reinterpret_cast<char*>(&fdh);
    for (size_t i = 0; i < sizeof(FixedDNSheader); i++) {
        queryBuffer.push_back(fdhPtr[i]);
    }

    // 2. Depending on the query type, construct the question section
    if (queryType == QueryType::A) {
        // Convert domain name to label format
        std::vector<char> label = domainToLabel(domainName);
        queryBuffer.insert(queryBuffer.end(), label.begin(), label.end());
    }
    else if (queryType == QueryType::PTR) {
        // Reverse the IP address and append ".in-addr.arpa"
        std::string reversedIP = reverseIP(domainName) + ".in-addr.arpa";
        std::vector<char> label = domainToLabel(reversedIP);
        queryBuffer.insert(queryBuffer.end(), label.begin(), label.end());
    }
    else {
        // Handle any other query types or raise an error
    }

    // 3. Set the question header
    setQuestionHeader();
}

std::string DNSQueryBuilder::reverseIP(const std::string& ip) {
    std::stringstream ss(ip);
    std::string segment;
    std::vector<std::string> ipSegments;

    while (std::getline(ss, segment, '.')) {
        ipSegments.push_back(segment);
    }

    std::reverse(ipSegments.begin(), ipSegments.end());
    std::string reversedIP = std::accumulate(ipSegments.begin(), ipSegments.end(), std::string(),
        [](const std::string& a, const std::string& b) {
            return a + (a.length() > 0 ? "." : "") + b;
        });

    return reversedIP;
}

void DNSQueryBuilder::displayQueryInfo() const {
    std::cout << "Lookup  : " << domainName << std::endl;
    std::cout << "Query   : " << domainName << ", type 1, TXID "
        << std::hex << std::uppercase << "0x"
        << std::setfill('0') << std::setw(4) << transactionID
        << std::dec << std::endl;
    std::cout << "Server  : " << destinationIPAddress << std::endl;
    std::cout << "********************************" << std::endl;
}

void DNSQueryBuilder::prepareQueryPacket(const std::string& domainOrIP, const std::string& serverIP, int txId) {
    transactionID = txId;
    setDomainName(domainOrIP);
    setIpAddress(serverIP);
    determineQueryType(domainOrIP);
    constructDNSPacket();
}