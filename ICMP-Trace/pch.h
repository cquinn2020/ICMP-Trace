#ifndef PCH_H
#define PCH_H
#define _WINSOCK_DEPRECATED_NO_WARNINGS


// add headers that you want to pre-compile here
// Windows Header Files
#include <winsock2.h>
#include "Ws2tcpip.h"
#include <iphlpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <windows.h>

// Standard headers
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <numeric>
#include <chrono>

#include <iomanip>  // for std::setfill and std::setw
#include <cctype> // for std::toupper

#endif //PCH_H