#ifndef IP_H
#define IP_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <WinSock2.h>
#include <Windows.h>
#include <WinCon.h>
#include <IPHlpApi.h>

#include "Include/pcap.h"
#include "if.h"

#pragma comment (lib,"wpcap")
#pragma comment (lib,"iphlpapi.lib")

#define DPRINTF printf
#define sleep Sleep
#define SIOCGIFNAME 0x8910

using namespace std;

#endif
