#ifndef AUTH_H
#define AUTH_H
/*
  ------------------------------
  swufe inode client(for inode v3.60 E6303)
  this program is based on njit-802.1x client.
  supports MD5-Challange connection and normal password connection.
  editor:pxm,xulin
  -------------------------------
*/
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
#include <fstream>

#include "Include/pcap.h"
#include "Include/remote-ext.h"
#include "if.h"

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define DPRINTF printf
#define sleep Sleep
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x)) 
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

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

//const char H3C_KEY[64]  ="Oly5D62FaE94W7";  // H3C的另一个固定密钥，网友取自MacOSX版本的iNode官方客户端

// 子函数声明
static void SendStartPkt(pcap_t *adhandle, const uint8_t mac[]);
static void SendLogoffPkt(const char* DeviceName);
static void SendResponseIdentity(pcap_t *adhandle,const uint8_t request[],const uint8_t ethhdr[], const uint8_t ip[4],const char username[]);
static void SendResponseMD5(pcap_t *adhandle,const uint8_t request[],const uint8_t ethhdr[],const char username[],const char passwd[]);
static void SendResponseAvailable(pcap_t *adhandle,const uint8_t request[],const uint8_t ethhdr[],const uint8_t ip[4],const char username[]);
static void SendResponseNotification(pcap_t *handle,const uint8_t request[],const uint8_t ethhdr[]);
static void SendResponseH3C(pcap_t *adhandle,const uint8_t request[],const uint8_t ethhdr[],const char username[],const char passwd[]);

static void GetMacFromDevice(uint8_t mac[6], const char *devicename);

static void FillClientVersionArea(uint8_t area[]);
static void FillWindowsVersionArea(uint8_t area[]);
static void FillBase64Area(char area[]);
// From fillmd5.c
//extern void FillMD5Area(uint8_t digest[],uint8_t id, const char passwd[], const uint8_t srcMD5[]);

// From ip.c
extern void GetIpFromDevice(uint8_t ip[4], const char DeviceName[]);
//void sleep(int second){Sleep(second*1000);}
string GetDeviceList(bool GoAuth);
const char * GetDeviceList(bool GoAuth,const char *usr,const char *psw,const char *dname);
int matchName(const char *c1,const char *c2);
static void PrepareAuth(const char *DeviceName);
static void RenewSpecifiedDevice(const char *devicename);
//int matchName(const char *c1,char *c2);
char *wcharTochar(const wchar_t *wchar, int length) ;

bool NeedPause = false;

typedef struct nDevice
{
	string nDeviceName;
	string nDeviceDescription;
}NetDevice;

#endif

