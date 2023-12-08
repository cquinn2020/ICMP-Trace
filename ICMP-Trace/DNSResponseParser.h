#pragma once
#include "NetworkUtils.h"

class DNSResponseParser {
public:
    DNSResponseParser(const std::vector<char>& responseBuffer, unsigned int requestTxId, size_t bufferSize);

    // Default constructor
    DNSResponseParser()
        : buffer(dummyBuffer), currentPos(0), requestTxId(0), bufferLength(0),
        id(0), rcode(0), flags(0), questionsCount(0), answersCount(0),
        authorityCount(0), additionalCount(0) {}

    void parse();

    unsigned int getRCode() const;
    unsigned int getID() const;
    FixedDNSheader header;

private:
    static const std::vector<char> dummyBuffer; // Add a static dummy buffer

    const std::vector<char>& buffer;
    size_t currentPos;
    USHORT requestTxId;
    size_t bufferLength;

    void parseHeader();
    void parseQuestions();
    void parseAnswers();
    void parseAuthority();
    void parseAdditional();
    std::string readDomainName();
    ResourceRecord parseResourceRecord();
    void printAnswers() const;
    void printQuestions() const;
    void printAuthority() const;
    void printAdditional() const;
    void ensureTxIdMatching();
    bool isValidResourceRecord(size_t& pos) const;

    unsigned int id;
    unsigned int rcode;
    unsigned int flags;
    unsigned int questionsCount;
    unsigned int answersCount;
    unsigned int authorityCount;
    unsigned int additionalCount;
public:
    
    std::vector<Question> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorityRecords;
    std::vector<ResourceRecord> additionalRecords;
    ResourceRecord resourceRecord;
};