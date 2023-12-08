#include "pch.h"
#include "DNSResponseParser.h"

DNSResponseParser::DNSResponseParser(const std::vector<char>& responseBuffer, unsigned int requestTxId, size_t bufferSize)
    : buffer(responseBuffer),
    currentPos(0),
    requestTxId(requestTxId),
    id(0),
    rcode(0),
    flags(0),
    questionsCount(0),
    answersCount(0),
    authorityCount(0),
    additionalCount(0),
    header(),
    bufferLength(bufferSize) {}


const std::vector<char> DNSResponseParser::dummyBuffer = {}; 


void DNSResponseParser::parse() {
    parseHeader();
    //ensureTxIdMatching();


    if (rcode == 0) {
        std::cout << "  succeeded with Rcode = 0" << std::endl;
    }
    else {
        std::cout << "  failed with Rcode = " << rcode << std::endl;
        return;
    }

    parseQuestions();
    printQuestions();

    parseAnswers();
    printAnswers();


    parseAuthority();
    printAuthority();

    parseAdditional();
    printAdditional();
}

void DNSResponseParser::parseHeader() {
    if (buffer.size() < 12) {
        throw std::runtime_error("  ++ invalid reply: packet smaller than fixed DNS header");
    }

    // Copy the first 12 bytes into our FixedDNSHeader structure
    std::memcpy(&header, buffer.data(), sizeof(FixedDNSheader));

    // Convert fields from network byte order to host byte order
    id = header.ID;
    flags = ntohs(header.flags);
    questionsCount = ntohs(header.questions);
    answersCount = ntohs(header.answers);
    authorityCount = ntohs(header.authority);
    additionalCount = ntohs(header.additional);
    rcode = ntohs(header.flags) & 0x000F;

    // Move currentPos past the header
    currentPos = sizeof(FixedDNSheader);

    printf("  TXID 0x%04X flags 0x%04X questions %d answers %d authority %d additional %d\n",
        id, flags, questionsCount, answersCount, authorityCount, additionalCount);
}

void DNSResponseParser::parseQuestions() {
    questions.clear();

    for (unsigned int i = 0; i < questionsCount; ++i) {
        Question q;

        q.domainName = readDomainName();

        uint16_t qTypeNetOrder;
        std::memcpy(&qTypeNetOrder, &buffer[currentPos], sizeof(uint16_t));
        q.qType = ntohs(qTypeNetOrder);
        currentPos += sizeof(uint16_t);

        uint16_t qClassNetOrder;
        std::memcpy(&qClassNetOrder, &buffer[currentPos], sizeof(uint16_t));
        q.qClass = ntohs(qClassNetOrder);
        currentPos += sizeof(uint16_t);

        questions.push_back(q);
    }
}

void DNSResponseParser::parseAnswers() {
    answers.clear();
    for (unsigned int i = 0; i < answersCount; ++i) {
        size_t tempPos = currentPos;

        if (!isValidResourceRecord(tempPos)) {
            throw std::runtime_error("  ++ invalid section: not enough records");
        }
        answers.push_back(parseResourceRecord());
    }
}

void DNSResponseParser::parseAuthority() {
    authorityRecords.clear();
    for (unsigned int i = 0; i < authorityCount; ++i) {
        size_t tempPos = currentPos;

        if (!isValidResourceRecord(tempPos)) {
            throw std::runtime_error("  ++ invalid section: not enough records");
        }
        authorityRecords.push_back(parseResourceRecord());
    }
}

void DNSResponseParser::parseAdditional() {
    additionalRecords.clear();
    for (unsigned int i = 0; i < additionalCount; ++i) {
        size_t tempPos = currentPos;

        if (!isValidResourceRecord(tempPos)) {
            throw std::runtime_error("  ++ invalid section: not enough records");
        }
        additionalRecords.push_back(parseResourceRecord());
    }
}

unsigned int DNSResponseParser::getRCode() const {
    return rcode;
}

unsigned int DNSResponseParser::getID() const {
    return id;
}

std::string DNSResponseParser::readDomainName() {
    std::string domainName;
    size_t pos = currentPos;
    bool jumped = false;
    size_t jumpCount = 0; // To avoid potential infinite loops
    while (true) {
        if (pos >= buffer.size() && jumped) { // Check if we're not jumping beyond the packet boundary
            throw std::runtime_error("  ++ invalid record: jump beyond packet boundary");
        }

        if (pos >= buffer.size() && !domainName.empty()) {
            throw std::runtime_error("  ++ invalid record: truncated name");
        }

        unsigned char length = buffer[pos];

        // Check for domain name compression
        if ((length & 0xC0) == 0xC0) {

            // We've encountered 0xC0 but there's no additional byte for the offset.
            if (pos + 1 >= buffer.size()) {
                throw std::runtime_error("  ++ invalid record: truncated jump offset");
            }
            if (jumpCount++ > 1000) { // Look into the RFC for the actual limit
                throw std::runtime_error("  ++ invalid record: jump loop");
            }

            // Next 14 bits after 11 is an offset from the start of the buffer
            size_t offset = ((length & 0x3F) << 8) | static_cast<unsigned char>(buffer[pos + 1]);
            if (offset < 12) {
                // The pointer is jumping into the fixed header!
                throw std::runtime_error("  ++ invalid record: jump into fixed DNS header");
            }
            if (!jumped) {
                currentPos = pos + 2; // Update only if we've not jumped before
            }
            pos = offset;
            jumped = true;
            continue;
        }

        if (length == 0) { // End of domain name
            break;
        }

        if (!domainName.empty()) {
            domainName += '.';
        }
        // Check if the length is valid (could be a truncated record)
        if (pos + 1 + length > buffer.size()) {
            throw std::runtime_error("  ++ invalid record: truncated name");
        }
        domainName.append(&buffer[pos + 1], length);
        pos += length + 1; // Move past the length byte and the actual label
    }

    if (!jumped) {
        currentPos = pos + 1; // Move past the 0x00 byte
    }
    return domainName;
}

void DNSResponseParser::printAnswers() const {
    if (answers.size() > 0) {
        std::cout << "  ------------ [answers] ------------" << std::endl;
        for (const auto& answer : answers) {
            answer.print();
        }
    }
}

void DNSResponseParser::printAuthority() const {
    if (authorityRecords.size() > 0) {
        std::cout << "  ------------ [authority] ------------" << std::endl;
        for (const auto& authority : authorityRecords) {
            authority.print();
        }
    }
}

void DNSResponseParser::printAdditional() const {
    if (additionalRecords.size() > 0) {
        std::cout << "  ------------ [additional] ------------" << std::endl;
        for (const auto& additional : additionalRecords) {
            additional.print();
        }
    }
}

void DNSResponseParser::printQuestions() const {
    std::cout << "  ------------ [questions] ----------" << std::endl;
    for (auto& q : questions) {
        std::cout << "\t  " << q.domainName << " type " << q.qType << " class " << q.qClass << std::endl;
    }
}

ResourceRecord DNSResponseParser::parseResourceRecord() {
    ResourceRecord record;
    record.name = readDomainName();

    // Interpret the record header (first check that there is enough data)
    if (currentPos + sizeof(DNSanswerHdr) > buffer.size()) {
        throw std::runtime_error("  ++ invalid record: truncated RR answer header");
    }
    const DNSanswerHdr* recordHeader = reinterpret_cast<const DNSanswerHdr*>(&buffer[currentPos]);
    record.type = ntohs(recordHeader->type);
    record.classType = ntohs(recordHeader->cls);
    record.ttl = ntohl(recordHeader->ttl);
    uint16_t dataLength = ntohs(recordHeader->len);
    currentPos += sizeof(DNSanswerHdr);

    // Check if there's enough data left for the entire RR
    if (currentPos + dataLength > buffer.size()) {
        throw std::runtime_error("  ++ invalid record: RR value length stretches the answer beyond packet");
    }


    // Interpret RDATA based on the type
    if (record.type == DNS_A) {
        std::ostringstream oss;
        for (int j = 0; j < 3; ++j) {
            oss << static_cast<unsigned int>(static_cast<unsigned char>(buffer[currentPos + j])) << ".";
        }
        oss << static_cast<unsigned int>(static_cast<unsigned char>(buffer[currentPos + 3]));
        record.rdata = oss.str();
        currentPos += 4;
    }
    else if (record.type == DNS_CNAME || record.type == DNS_PTR || record.type == DNS_NS) {
        record.rdata = readDomainName();
    }
    else {
        record.rdata = "Data not parsed";
        currentPos += dataLength;
    }

    this->resourceRecord = record;
    return record;
}

void DNSResponseParser::ensureTxIdMatching() {
    if (requestTxId != header.getID()) {
        std::ostringstream errMsg;
        errMsg << "  ++ invalid reply: TXID mismatch, sent 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << requestTxId
            << ", received 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << header.getID();
        throw std::runtime_error(errMsg.str());
    }
}

bool DNSResponseParser::isValidResourceRecord(size_t& pos) const {
    // Check if we are at the end of the buffer
    if (pos + 1 > buffer.size() || pos == bufferLength) {
        throw std::runtime_error("  ++ invalid section: not enough records");
    }

    return true;
}
