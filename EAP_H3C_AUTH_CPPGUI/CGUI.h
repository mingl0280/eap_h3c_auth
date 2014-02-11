#ifndef CGUI_H
#define CGUI_H
#include <iostream>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <ctime>
#include <WinSock2.h>
#include <Windows.h>
#include <WinCon.h>
#include <IPHlpApi.h>
#include <iomanip>
#include <string>

#include "../Include/pcap.h"
#include "../Include/remote-ext.h"
#include "if.h"

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")

#define DPRINTF printf
#define sleep Sleep

using namespace std;

int EXIT(int errcode);
int Authentication(const char *UserName, const char *Password, const char *DeviceName);

typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2,ALLOCATED=7, MD5=4, AVAILABLE=20} EAP_Type;
typedef uint8_t EAP_ID;
const uint8_t BroadcastAddr[6] = {0xff,0xff,0xff,0xff,0xff,0xff}; // 广播MAC地址
const uint8_t MultcastAddr[6]  = {0x01,0x80,0xc2,0x00,0x00,0x03}; // 多播MAC地址
const char H3C_VERSION[16]="CH V3.60-6210"; // 华为客户端版本号
const char H3C_KEY[64]    ="HuaWei3COM1X";  // H3C的固定密钥
typedef struct _ASTAT_
{
	ADAPTER_STATUS adapt;
	NAME_BUFFER NameBuff[30];
}ASTAT,*PASTAT;
ASTAT Adapter;
typedef struct nDevice
{
	string nDeviceName;
	string nDeviceDescription;
}NetDevice;

#endif

#endif