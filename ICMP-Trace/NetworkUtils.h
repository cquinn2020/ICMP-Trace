#pragma once

#define IP_HDR_SIZE 20 /* RFC 791 */
#define ICMP_HDR_SIZE 8 /* RFC 792 */
/* max payload size of an ICMP message originated in the program */
#define MAX_SIZE 65200
/* max size of an IP datagram */
#define MAX_ICMP_SIZE (MAX_SIZE + ICMP_HDR_SIZE)
/* the returned ICMP message will most likely include only 8 bytes
* of the original message plus the IP header (as per RFC 792); however,
* longer replies (e.g., 68 bytes) are possible */
#define MAX_REPLY_SIZE (IP_HDR_SIZE + ICMP_HDR_SIZE + MAX_ICMP_SIZE)
#define ICMP_ECHO  (IP_HDR_SIZE + ICMP_HDR_SIZE)
/* ICMP packet types */
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRED 11
#define ICMP_ECHO_REQUEST 8


// I think this is no longer needed
struct ICMPResponse {
	sockaddr_in sourceAddr; // Source address of the response
	std::string hostname;   // Resolved hostname from DNS
	bool resolved;          // Flag to indicate if DNS resolution was successful
};

/* remember the current packing state */
#pragma pack (push)
#pragma pack (1)
/* define the IP header (20 bytes) */
class IPHeader {
public:
	u_char h_len : 4; /* lower 4 bits: length of the header in dwords */
	u_char version : 4; /* upper 4 bits: version of IP, i.e., 4 */
	u_char tos; /* type of service (TOS), ignore */
	u_short len; /* length of packet */
	u_short ident; /* unique identifier */
	u_short flags; /* flags together with fragment offset - 16 bits */
	u_char ttl; /* time to live */
	u_char proto; /* protocol number (6=TCP, 17=UDP, etc.) */
	u_short checksum; /* IP header checksum */
	u_long source_ip;
	u_long dest_ip;
};
/* define the ICMP header (8 bytes) */
class ICMPHeader {
public:
	u_char type; /* ICMP packet type */
	u_char code; /* type subcode */
	u_short checksum; /* checksum of the ICMP */
	u_short id; /* application-specific ID */
	u_short seq; /* application-specific sequence */
};
/* now restore the previous packing state */
#pragma pack (pop) 


enum ProbeStatus {
	SENT, RETRANSMITTED, LOST, RECEIVED, DNS_RESOLVED
};


struct Probe {
	int ttl;
	int probeCount;
	std::chrono::steady_clock::time_point sentTime;
	std::chrono::steady_clock::time_point receiveTime;
	std::chrono::milliseconds rtt;
	std::string ipAddress;
	std::string dnsName;
    bool dnsQuerySent;
	ProbeStatus status;
    int reinsertCount;

	Probe(int ttl) : ttl(ttl), probeCount(1), status(SENT), dnsQuerySent(false), reinsertCount(0) {}
};



struct CompareRTO {
	bool operator()(const std::pair<std::chrono::steady_clock::time_point, int>& a,
		const std::pair<std::chrono::steady_clock::time_point, int>& b) {
		return a.first > b.first;
	}
};

using MinHeap = std::priority_queue<std::pair<std::chrono::steady_clock::time_point, int>,
	std::vector<std::pair<std::chrono::steady_clock::time_point, int>>,
	CompareRTO>;

#define DNS_QUERY (0 << 15) // 0 for query, 1 for response
#define DNS_RESPONSE (1 << 15) // 0 for query, 1 for response
#define DNS_STDQUERY (0 << 11) // opcode - 4 bits
#define DNS_AA (1 << 10) // authoritative answer
#define DNS_TC (1 << 9) // truncated
#define DNS_RD (1 << 8) // recursion desired
#define DNS_RA (1 << 7) // recursion available

#define DNS_A 1       // A record
#define DNS_INET 1    // Internet class
#define DNS_PTR 12    // PTR record for reverse DNS
#define DNS_NS 2      // Name server record
#define DNS_CNAME 5   // Canonical name record
#define DNS_ANY 255   // Matches any type


// use pack to avoid padding
#pragma pack(push,1)

// Fixed DNS Header class
class FixedDNSheader {
private:

public:
    USHORT ID;
    USHORT flags;
    USHORT questions;
    USHORT answers;
    USHORT authority;
    USHORT additional;
    void setID(USHORT id) { this->ID = id; }
    void setFlags(USHORT flags) { this->flags = flags; }
    void setQuestions(USHORT questions) { this->questions = questions; }
    void setAnswers(USHORT answers) { this->answers = answers; }
    void setAuthority(USHORT authority) { this->authority = authority; }
    void setAdditional(USHORT additional) { this->additional = additional; }
    USHORT getID() { return this->ID; }
    USHORT getFlags() { return this->flags; }
    USHORT getQuestions() { return this->questions; }
    USHORT getAnswers() { return this->answers; }
    USHORT getAuthority() { return this->authority; }
    USHORT getAdditional() { return this->additional; }
};

// Query Header class
class QueryHeader {
private:
    USHORT qType;
    USHORT qClass;
public:
    void setQType(USHORT qType) { this->qType = qType; }
    void setQClass(USHORT qClass) { this->qClass = qClass; }
    USHORT getQType() { return this->qType; }
    USHORT getQClass() { return this->qClass; }
};

// Answer Header class
class DNSanswerHdr {
public:
    u_short getType() const { return ntohs(type); }
    u_short getClass() const { return ntohs(cls); }
    u_int getTTL() const { return ntohl(ttl); }
    u_short getLen() const { return ntohs(len); }
    void setType(u_short type) { this->type = htons(type); }
    void setClass(u_short cls) { this->cls = htons(cls); }
    void setTTL(u_int ttl) { this->ttl = htonl(ttl); }
    void setLen(u_short len) { this->len = htons(len); }
    u_short type;
    u_short cls;
    u_int ttl;
    u_short len;
public:

};


#pragma pack(pop)
// end of pack 

struct Question {
    std::string domainName;
    USHORT qType;
    USHORT qClass;
};

struct ResourceRecord {
    std::string name;       // The domain name for this record
    uint16_t type;          // The type of this record (e.g., A, CNAME, NS, PTR, ...)
    uint16_t classType;     // Class type, typically IN for internet
    uint32_t ttl;           // Time to live in seconds
    std::string rdata;      // The data associated with this record, interpretation depends on 'type'

    void print() const {
        switch (type) {
        case DNS_A: // Type A record
            std::cout << "\t  " << name << " A " << rdata << " TTL = " << ttl << std::endl;
            break;
        case DNS_CNAME: // CNAME record
            std::cout << "\t  " << name << " CNAME " << rdata << " TTL = " << ttl << std::endl;
            break;
        case DNS_PTR: // PTR record
            std::cout << "\t  " << name << " PTR " << rdata << " TTL = " << ttl << std::endl;
            break;
        case DNS_NS: // NS record
            std::cout << "\t  " << name << " NS " << rdata << " TTL = " << ttl << std::endl;
            break;
        default:
            std::cout << "\t   " << name << " type " << type << " class " << classType << " TTL = " << ttl << " rdata: " << rdata << std::endl;
            break;
        }
    }
};

struct ICMP_ResponseInfo {
    int sequenceNumber;
    std::string ipAddress;
};