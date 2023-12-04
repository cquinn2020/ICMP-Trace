// ICMP-Trace.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"


#include "ICMP_Socket.h"

int main(int argc, char* argv[]) {
    // Check command line arguments
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <destination>" << std::endl;
        return 1;
    }

    


  

    try {
        // Initialize the ICMP_Socket object
        ICMP_Socket icmpSocket;


        // Send an ICMP packet
        icmpSocket.SetDestAddress(argv[1]);


        for (int i = 1; i < 31; i++) {
            if (icmpSocket.SendICMPPacket() == -1) {
			    throw std::runtime_error("Failed to send ICMP packet.");
		    }
        }

        // Receive and process the ICMP response
        if (!icmpSocket.ReceiveICMPResponse()) {
            throw std::runtime_error("Failed to receive ICMP response.");
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        WSACleanup();
        return 1;
    }

    // Cleanup Winsock
    WSACleanup();
    return 0;
}
