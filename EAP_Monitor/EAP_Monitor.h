#ifndef STDAFX_H
#define STDAFX_H

#pragma once

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
#include <tchar.h>
#include <fstream>


#include "Include\pcap.h"
#include "Include\remote-ext.h"
#include "if.h"

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

int Authentication(const char *UserName,std::string dir, const char *DeviceName);

typedef enum { REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4, H3CDATA = 10 } EAP_Code;
typedef enum { IDENTITY = 1, NOTIFICATION = 2, ALLOCATED = 7, MD5 = 4, AVAILABLE = 20 } EAP_Type;
typedef uint8_t EAP_ID;
const uint8_t BroadcastAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; // 广播MAC地址
const uint8_t MultcastAddr[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 }; // 多播MAC地址
const char H3C_VERSION[16] = "CH V3.60-6210"; // 华为客户端版本号
const char H3C_KEY[64] = "HuaWei3COM1X";  // H3C的固定密钥

typedef struct _ASTAT_
{
	ADAPTER_STATUS adapt;
	NAME_BUFFER NameBuff[30];
}ASTAT, *PASTAT;

ASTAT Adapter;
static void SendResponseIdentity(pcap_t *adhandle, const uint8_t request[], const uint8_t ethhdr[], const uint8_t ip[4], const char username[]);
static void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen);

static void GetMacFromDevice(uint8_t mac[6], const char *devicename);

static void FillClientVersionArea(uint8_t area[]);
static void FillWindowsVersionArea(uint8_t area[]);
static void FillBase64Area(char area[]);
// From fillmd5.c
//extern void FillMD5Area(uint8_t digest[],uint8_t id, const char passwd[], const uint8_t srcMD5[]);

// From ip.c
extern void GetIpFromDevice(uint8_t ip[4], const char DeviceName[]);
std::string GetDeviceList(bool GoAuth);
const char * GetDeviceList(bool GoAuth, const char *usr, const char *psw, const char *dname);
int matchName(const char *c1, const char *c2);
static void PrepareAuth(const char *DeviceName);
static void RenewSpecifiedDevice(const char *devicename);
char *wcharTochar(const wchar_t *wchar, int length);

bool NeedPause = false;

typedef struct nDevice
{
	std::string nDeviceName;
	std::string nDeviceDescription;
}NetDevice;

void Init();
BOOL isInstalled();
BOOL Install();
BOOL Uninstall();
void LogEvent(LPCTSTR pszFormat, ...);
void WINAPI ServiceMain();
void WINAPI ServiceStrl(DWORD dwOpcode);

TCHAR szServiceName[] = _T("EAP_ONLINE_SERVICE");
BOOL bInstall;
SERVICE_STATUS_HANDLE hServiceStatus;
SERVICE_STATUS status;
DWORD dwThreadID;


#define EXIT(__CODE) LogEvent(_T("%d"),__CODE)
#define sleep(__TIME) Sleep(__TIME)
#define DPRINTF(__CONT,...) LogEvent(_T(__CONT),__VA_ARGS__)
#endif