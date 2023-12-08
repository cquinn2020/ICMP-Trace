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

		//Initialize the ICMP_Socket object
		ICMP_Socket icmpSocket;
		icmpSocket.SetIpAddresses(argv[1]);
		
		
		/////
		DNSQueryBuilder queryBuilder;
		
		UDPClient udpClient;
		for (int i = 1; i <= 30; i++) {
			if (icmpSocket.SendICMPPacket(false) == -1) {
				throw std::runtime_error("Failed to send ICMP packet.");
			}
		}

		fd_set readfds;

		while (!icmpSocket.traceFinished) {
			FD_ZERO(&readfds);
			FD_SET(icmpSocket.icmp_sock, &readfds);
			FD_SET(udpClient.socketFd, &readfds);
					
			

			int maxfd = max(icmpSocket.icmp_sock, udpClient.socketFd);
			struct timeval tv;
			if (!icmpSocket.GetTimeouts().empty()) {
				auto now = std::chrono::steady_clock::now();
				auto timePair = icmpSocket.GetNextTimeout();
				auto nextTimeout = timePair.first;
				int seqNumber = timePair.second;
				Probe* currProbe = icmpSocket.GetProbe(seqNumber);

				// If the probe has been received, pop it be
				if (currProbe->status == ProbeStatus::RECEIVED && currProbe->reinsertCount > 0) {
					icmpSocket.GetNextTimeout();
					currProbe->reinsertCount--;
					continue;
				}

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
				// Handle timeout
				if (!icmpSocket.GetTimeouts().empty()) {
					auto timedOutProbeInfo = icmpSocket.GetNextTimeout();
					icmpSocket.SetRetxSeqNumber(timedOutProbeInfo.second);
					icmpSocket.SendICMPPacket(true);
				}
				continue;
			}

			// eventually will need to add udp for dns resolution
			if (FD_ISSET(udpClient.socketFd, &readfds)) {
				std::vector<char> response = udpClient.receiveData();

				if (!response.empty()) {
					DNSResponseParser parser(response, queryBuilder.getTransactionID(), response.size());
					parser.parse();
					ResourceRecord answer = parser.resourceRecord;
					// call the icmp socket obj to update the probe	
					icmpSocket.UpdateProbeDNSInfo(queryBuilder.getTransactionID(), answer.name, true);
				}
				else {
					std::cout << "No response received or error occurred." << std::endl;
				}
			}

			if (FD_ISSET(icmpSocket.icmp_sock, &readfds)) {
				// ICMP socket has data
				try {
					ICMP_ResponseInfo messageInfo = icmpSocket.ReceiveICMPResponse();
					if (messageInfo.sequenceNumber == -1) {
						continue;
					}
					fd_set wfd;
					FD_ZERO(&wfd);
					FD_SET(udpClient.socketFd, &wfd);
					int udpActivity = select(udpClient.socketFd + 1, NULL, &wfd, NULL, &tv);
					if (udpActivity < 0) {
						throw std::runtime_error("Select error.");
						break;
					}
					else {
						queryBuilder.prepareQueryPacket(messageInfo.ipAddress, "8.8.8.8", messageInfo.sequenceNumber);
						std::vector<char> dnsLookup = queryBuilder.getConstructedPacket();
						if (!udpClient.setServer("8.8.8.8", 53)) {
							std::cerr << "Error setting up the server address." << std::endl;
							return 1;
						}

						if (!udpClient.sendData(dnsLookup)) {
							std::cerr << "Error sending data." << std::endl;
							return 1;
						}
					}

				}
				catch (const std::exception& e) {
					std::cerr << "Error: " << e.what() << std::endl;
					WSACleanup();
					return 1;
				}	
			}

			


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
