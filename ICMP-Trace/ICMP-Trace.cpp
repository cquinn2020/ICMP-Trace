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
        icmpSocket.SetIpAddresses(argv[1]);

        // will need to add udp for dns resolution


        for (int i = 1; i < 31; i++) {
            if (icmpSocket.SendICMPPacket(false) == -1) {
			    throw std::runtime_error("Failed to send ICMP packet.");
		    }
        }

        fd_set readfds;
        int maxfd = icmpSocket.icmp_sock;

        while (!icmpSocket.traceFinished) {

            FD_ZERO(&readfds);
            FD_SET(icmpSocket.icmp_sock, &readfds);

            struct timeval tv;
            if (!icmpSocket.GetTimeouts().empty()) {
                auto now = std::chrono::steady_clock::now();
                auto nextTimeout = icmpSocket.GetNextTimeout().first;
                if (nextTimeout > now) {
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(nextTimeout - now);
                    tv.tv_sec = duration.count() / 1000000;
                    tv.tv_usec = duration.count() % 1000000;    
                }
                else {
                    tv.tv_sec = 0;
                    tv.tv_usec = 0;
                }
            }
            else {
				tv.tv_sec = 0;
				tv.tv_usec = 500;
			}

            int activity = select(maxfd + 1, &readfds, NULL, NULL, &tv);

            if (activity < 0) {
                std::cerr << "Select error." << std::endl;
                break;
            }

            if (activity == 0) {
                std::cerr << "Select timeout." << std::endl;
                // Handle timeout
                if (!icmpSocket.GetTimeouts().empty()) {
                    auto timedOutProbeInfo = icmpSocket.GetNextTimeout();
                    icmpSocket.SetRetxSeqNumber(timedOutProbeInfo.second);
                    icmpSocket.SendICMPPacket(true); 
                }
                continue;
            }

            if (FD_ISSET(icmpSocket.icmp_sock, &readfds)) {
                // ICMP socket has data
                if (!icmpSocket.ReceiveICMPResponse()) {
                    throw std::runtime_error("Failed to receive ICMP response.");
                }
            }

            // eventually will need to add udp for dns resolution

			
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
