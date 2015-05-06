// EAP_Monitor.cpp : 定义控制台应用程序的入口点。
//
//#define DEBUG
#include "EAP_Monitor.h"

using namespace std;


#ifdef DEBUG 
int main(){
	string devName = "", usrName = "", ip = "";
	//ifstream ifs("eap_online_status");
	//ifs >> devName >> usrName;
	char buff[512];
	unsigned long len = ::GetModuleFileNameA(NULL, buff, 512);
	char *pLstSlash = &buff[len];
	while (pLstSlash != NULL && *pLstSlash != '\\')pLstSlash--;
	*pLstSlash++;
	*pLstSlash = 0;
	string fPath(buff);
	string olstatus = fPath + "eap_online_status";
	string pktfile = fPath + "eap_pkt_data";
	string ipfile = fPath + "eap_ip_data";
	ifstream ifs(olstatus.c_str());
	ifs >> devName >> usrName;
	Authentication(usrName.c_str(), fPath, devName.c_str());
	return 0;
}
#else
int APIENTRY WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nCmdShow)
{

	Init();

	dwThreadID = ::GetCurrentThreadId();

	SERVICE_TABLE_ENTRY st[] =
	{
		{ szServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
		{ NULL, NULL }
	};

	if (_stricmp(lpCmdLine, "/install") == 0)
	{
		Install();
	}
	else if (_stricmp(lpCmdLine, "/uninstall") == 0)
	{
		Uninstall();
	}
	else
	{
		if (!::StartServiceCtrlDispatcher(st))
		{
			LogEvent(_T("Register Service Main Function Error!"));
		}
	}
	return 0;
}
#endif

void Init()
{
	hServiceStatus = NULL;
	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	status.dwCurrentState = SERVICE_STOPPED;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	status.dwWin32ExitCode = 0;
	status.dwServiceSpecificExitCode = 0;
	status.dwCheckPoint = 0;
	status.dwWaitHint = 0;
}
void WINAPI ServiceMain()
{
	// Register the control request handler
	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	//注册服务控制
	hServiceStatus = RegisterServiceCtrlHandler(szServiceName, ServiceStrl);
	if (hServiceStatus == NULL)
	{
		LogEvent(_T("Handler not installed"));
		return;
	}
	SetServiceStatus(hServiceStatus, &status);

	status.dwWin32ExitCode = S_OK;
	status.dwCheckPoint = 0;
	status.dwWaitHint = 0;
	status.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(hServiceStatus, &status);

	//TODO:ServiceModule Here

	string devName = "", usrName = "", ip = "";
	//ifstream ifs("eap_online_status");
	//ifs >> devName >> usrName;
	char buff[512];
	unsigned long len = ::GetModuleFileNameA(NULL, buff, 512);
	char *pLstSlash = &buff[len];
	while (pLstSlash != NULL && *pLstSlash != '\\')pLstSlash--;
	*pLstSlash++;
	*pLstSlash = 0;
	string fPath(buff);
	string olstatus = fPath + "eap_online_status";
	string pktfile = fPath + "eap_pkt_data";
	string ipfile = fPath + "eap_ip_data";
	ifstream ifs(olstatus.c_str());
	ifs >> devName >> usrName;

	Authentication(usrName.c_str(), fPath, devName.c_str());

	status.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(hServiceStatus, &status);
	LogEvent(_T("Service stopped"));
}

int Authentication(const char *UserName, string dir, const char *DeviceName)
{
	char    errbuf[PCAP_ERRBUF_SIZE];
	pcap_t    *adhandle; // adapter handle
	uint8_t    MAC[6];

	char    FilterStr[100];
	struct bpf_program    fcode;
	const int DefaultTimeout = 1000;//设置接收超时参数，单位ms

	// NOTE: 这里没有检查网线是否已插好,网线插口可能接触不良

	/* 打开适配器(网卡) */
	adhandle = pcap_open_live(DeviceName, 65536, 1, DefaultTimeout, errbuf);
	if (adhandle == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		EXIT(-1);
	}

	/* 查询本机MAC地址 */
	GetMacFromDevice(MAC, DeviceName);

	/*
	* 设置过滤器：
	* 初始情况下只捕获发往本机的802.1X认证会话，不接收多播信息（避免误捕获其他客户端发出的多播信息）
	* 进入循环体前可以重设过滤器，那时再开始接收多播信息
	*/
	sprintf(FilterStr, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
		MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);


START_AUTHENTICATION:
	{
		int retcode;
		struct pcap_pkthdr *header;
		const uint8_t    *captured;
		uint8_t    ethhdr[14] = { 0 }; // ethernet header
		uint8_t    ip[4] = { 0 };    // ip address
		string ffile = dir + "eap_pkt_data";
		
		FILE *bin_in = fopen(ffile.c_str(), "rb");
		fseek(bin_in, 0, SEEK_END);

		unsigned long flen = ftell(bin_in);

		rewind(bin_in);
		uint8_t *tempdata = (uint8_t *)malloc(flen*sizeof(uint8_t));
		fread(tempdata, sizeof(uint8_t), flen, bin_in);
		captured = (uint8_t *)tempdata;
		fclose(bin_in);
		// 填写应答包的报头(以后无须再修改)
		// 默认以单播方式应答802.1X认证设备发来的Request
		memcpy(ethhdr + 0, captured + 6, 6);
		memcpy(ethhdr + 6, MAC, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;

		sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			captured[6], captured[7], captured[8], captured[9], captured[10], captured[11]);
		pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
		pcap_setfilter(adhandle, &fcode);

		// 进入循环体
		for (;;)
		{
			// 调用pcap_next_ex()函数捕获数据包
			while (pcap_next_ex(adhandle, &header, &captured) != 1)
			{
				DPRINTF("."); // 若捕获失败，则等1秒后重试
				sleep(1);// 直到成功捕获到一个数据包后再跳出
				// NOTE: 这里没有检查网线是否已被拔下或插口接触不良
			}

			// 根据收到的Request，回复相应的Response包
			if ((EAP_Code)captured[18] == REQUEST)
			{
				switch ((EAP_Type)captured[22])
				{
				case IDENTITY:
					DPRINTF("[%d] Server: Request Identity!\n", (EAP_ID)captured[19]);
					GetIpFromDevice(ip, DeviceName);
					SendResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
					DPRINTF("[%d] Client: Response Identity.\n", (EAP_ID)captured[19]);
					break;
				}
			}
			else if ((EAP_Code)captured[18] == FAILURE)
			{    // 处理认证失败信息
				NeedPause = 1;
				uint8_t errtype = captured[22];
				uint8_t msgsize = captured[23];
				const char *msg = (const char*)&captured[24];
				DPRINTF("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
				if (errtype == 0x09 && msgsize > 0)
				{    // 输出错误提示消息
					fprintf(stderr, "%s\n", msg);
					// 已知的几种错误如下
					// E2531:用户名不存在
					// E2535:Service is paused
					// E2542:该用户帐号已经在别处登录
					// E2547:接入时段限制
					// E2553:密码错误
					// E2602:认证会话不存在
					// E3137:客户端版本号无效
					EXIT(-1);
				}
				else if (errtype == 0x08) // 可能网络无流量时服务器结束此次802.1X认证会话
				{    // 遇此情况客户端立刻发起新的认证会话
					goto START_AUTHENTICATION;
				}
				else
				{
					DPRINTF("errtype=0x%02x\n", errtype);
					NeedPause = 1;
					EXIT(-1);
				}
			}

		}
	}
	return (0);
}

//*********************************************************
//Functiopn:            ServiceStrl
//Description:            服务控制主函数，这里实现对服务的控制，
//                        当在服务管理器上停止或其它操作时，将会运行此处代码
//Calls:
//Called By:
//Table Accessed:
//Table Updated:
//Input:                dwOpcode：控制服务的状态
//Output:
//Return:
//Others:
//History:
//            <author>niying <time>2006-8-10        <version>        <desc>
//*********************************************************
void WINAPI ServiceStrl(DWORD dwOpcode)
{
	switch (dwOpcode)
	{
	case SERVICE_CONTROL_STOP:
		status.dwCurrentState = SERVICE_STOP_PENDING;
		SetServiceStatus(hServiceStatus, &status);
		PostThreadMessage(dwThreadID, WM_CLOSE, 0, 0);
		break;
	case SERVICE_CONTROL_PAUSE:
		break;
	case SERVICE_CONTROL_CONTINUE:
		break;
	case SERVICE_CONTROL_INTERROGATE:
		break;
	case SERVICE_CONTROL_SHUTDOWN:
		break;
	default:
		LogEvent(_T("Bad service request"));
	}
}
//*********************************************************
//Functiopn:            IsInstalled
//Description:            判断服务是否已经被安装
//Calls:
//Called By:
//Table Accessed:
//Table Updated:
//Input:
//Output:
//Return:
//Others:
//History:
//            <author>niying <time>2006-8-10        <version>        <desc>
//*********************************************************
BOOL IsInstalled()
{
	BOOL bResult = FALSE;

	//打开服务控制管理器
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hSCM != NULL)
	{
		//打开服务
		SC_HANDLE hService = ::OpenService(hSCM, szServiceName, SERVICE_QUERY_CONFIG);
		if (hService != NULL)
		{
			bResult = TRUE;
			::CloseServiceHandle(hService);
		}
		::CloseServiceHandle(hSCM);
	}
	return bResult;
}

//*********************************************************
//Functiopn:            Install
//Description:            安装服务函数
//Calls:
//Called By:
//Table Accessed:
//Table Updated:
//Input:
//Output:
//Return:
//Others:
//History:
//            <author>niying <time>2006-8-10        <version>        <desc>
//*********************************************************
BOOL Install()
{
	if (IsInstalled())
		return TRUE;

	//打开服务控制管理器
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL)
	{
		MessageBox(NULL, _T("Couldn't open service manager"), szServiceName, MB_OK);
		return FALSE;
	}

	// Get the executable file path
	TCHAR szFilePath[MAX_PATH];
	::GetModuleFileName(NULL, szFilePath, MAX_PATH);

	//创建服务
	SC_HANDLE hService = ::CreateService(
		hSCM, szServiceName, szServiceName,
		SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
		SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		szFilePath, NULL, NULL, _T(""), NULL, NULL);

	if (hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		MessageBox(NULL, _T("Couldn't create service"), szServiceName, MB_OK);
		return FALSE;
	}

	::CloseServiceHandle(hService);
	::CloseServiceHandle(hSCM);
	return TRUE;
}

//*********************************************************
//Functiopn:            Uninstall
//Description:            删除服务函数
//Calls:
//Called By:
//Table Accessed:
//Table Updated:
//Input:
//Output:
//Return:
//Others:
//History:
//            <author>niying <time>2006-8-10        <version>        <desc>
//*********************************************************
BOOL Uninstall()
{
	if (!IsInstalled())
		return TRUE;

	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hSCM == NULL)
	{
		MessageBox(NULL, _T("Couldn't open service manager"), szServiceName, MB_OK);
		return FALSE;
	}

	SC_HANDLE hService = ::OpenService(hSCM, szServiceName, SERVICE_STOP | DELETE);

	if (hService == NULL)
	{
		::CloseServiceHandle(hSCM);
		MessageBox(NULL, _T("Couldn't open service"), szServiceName, MB_OK);
		return FALSE;
	}
	SERVICE_STATUS status;
	::ControlService(hService, SERVICE_CONTROL_STOP, &status);

	//删除服务
	BOOL bDelete = ::DeleteService(hService);
	::CloseServiceHandle(hService);
	::CloseServiceHandle(hSCM);

	if (bDelete)
		return TRUE;

	LogEvent(_T("Service could not be deleted"));
	return FALSE;
}

//*********************************************************
//Functiopn:            LogEvent
//Description:            记录服务事件
//Calls:
//Called By:
//Table Accessed:
//Table Updated:
//Input:
//Output:
//Return:
//Others:
//History:
//            <author>niying <time>2006-8-10        <version>        <desc>
//*********************************************************
void LogEvent(LPCTSTR pFormat, ...)
{
	TCHAR    chMsg[256];
	HANDLE  hEventSource;
	LPTSTR  lpszStrings[1];
	va_list pArg;

	va_start(pArg, pFormat);
	_vstprintf(chMsg, pFormat, pArg);
	va_end(pArg);

	lpszStrings[0] = chMsg;

	hEventSource = RegisterEventSource(NULL, szServiceName);
	if (hEventSource != NULL)
	{
		ReportEvent(hEventSource, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, (LPCTSTR*)&lpszStrings[0], NULL);
		DeregisterEventSource(hEventSource);
	}
}

static void SendResponseIdentity(pcap_t *adhandle, const uint8_t request[], const uint8_t ethhdr[], const uint8_t ip[4], const char username[])
{
	uint8_t    response[128];
	size_t i;
	uint16_t eaplen;
	int usernamelen;

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == IDENTITY
		|| (EAP_Type)request[22] == AVAILABLE); // 兼容中南财经政法大学情况

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
	response[14] = 0x1;    // 802.1X Version 1
	response[15] = 0x0;    // Type=0 (EAP Packet)
	//response[16~17]留空    // Length

	// Extensible Authentication Protocol
	// {
	response[18] = (EAP_Code)RESPONSE;    // Code
	response[19] = request[19];        // ID
	//response[20~21]留空            // Length
	response[22] = (EAP_Type)IDENTITY;    // Type
	// Type-Data
	// {
	i = 23;
	//response[i++] = 0x15;      // 上传IP地址
	//response[i++] = 0x04;      //
	//memcpy(response+i, ip, 4);//
	//i += 4;              //
	response[i++] = 0x06;          // 携带版本号
	response[i++] = 0x07;          //
	//memcpy(response+i, "bjQ7SE8BZ3MqHhs3clMregcDY3Y=", sizeof("bjQ7SE8BZ3MqHhs3clMregcDY3Y="));
	FillBase64Area((char*)response + i);//
	i += 28;              //
	response[i++] = ' '; // 两个空格符
	response[i++] = ' '; //
	usernamelen = strlen(username); //末尾添加用户名
	memcpy(response + i, username, usernamelen);
	i += usernamelen;
	assert(i <= sizeof(response));
	// }
	// }
	// }

	// 补填前面留空的两处Length
	//重要！此处的0x25可以规避明码数据包中的密码长度bug
	eaplen = htons(usernamelen + 0x25);
	memcpy(response + 16, &eaplen, sizeof(eaplen));
	memcpy(response + 20, &eaplen, sizeof(eaplen));

	// 发送
	pcap_sendpacket(adhandle, response, 55 + usernamelen);
	return;
}

static void GetMacFromDevice(uint8_t mac[6], const char *devicename)
{
	/* UNAVALIABLE LINUX CODE

	int    fd;
	int    err;
	struct ifreq    ifr;

	fd = socket(PF_PACKET, SOCK_RAW, htons(0x0806));
	assert(fd != -1);

	assert(strlen(devicename) < IFNAMSIZ);
	strncpy(ifr.ifr_name, devicename, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;

	err = ioctl(fd, SIOCGIFHWADDR, &ifr);
	assert(err != -1);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	err = close(fd);
	assert(err != -1);
	return;
	*/
	PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	int netCardNum = 0;
	int IPnumPerNetCard = 0;
	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		/*如果函数返回的是ERROR_BUFFER_OVERFLOW
		则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
		这也是说明为什么stSize既是一个输入量也是一个输出量*/
		//释放原来的内存空间
		delete pIpAdapterInfo;
		//重新申请内存空间用来存储所有网卡信息
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		//再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
	if (ERROR_SUCCESS == nRel)
	{
		//输出网卡信息
		//可能有多网卡,因此通过循环去判断
		while (pIpAdapterInfo)
		{
			if (pIpAdapterInfo->Type == MIB_IF_TYPE_ETHERNET)
			{
				char *buf = new char[strlen(devicename) + 1];
				strcpy(buf, devicename);
				if (matchName(pIpAdapterInfo->AdapterName, buf))
				{
					//转移MAC数据到mac数组
					for (int k = 0; k < 6; k++)
					{
						mac[k] = (uint8_t)pIpAdapterInfo->Address[k];
					}
					break;
				}
			}
			pIpAdapterInfo = pIpAdapterInfo->Next;
		}
	}
	return;

}

static void FillBase64Area(char area[])
{
	uint8_t version[20];
	const char Tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/"; // 标准的Base64字符映射表
	uint8_t    c1, c2, c3;
	int    i, j;

	// 首先生成20字节加密过的H3C版本号信息
	FillClientVersionArea(version);

	// 然后按照Base64编码法将前面生成的20字节数据转换为28字节ASCII字符
	i = 0;
	j = 0;
	while (j < 24)
	{
		c1 = version[i++];
		c2 = version[i++];
		c3 = version[i++];
		area[j++] = Tbl[(c1 & 0xfc) >> 2];
		area[j++] = Tbl[((c1 & 0x03) << 4) | ((c2 & 0xf0) >> 4)];
		area[j++] = Tbl[((c2 & 0x0f) << 2) | ((c3 & 0xc0) >> 6)];
		area[j++] = Tbl[c3 & 0x3f];
	}
	c1 = version[i++];
	c2 = version[i++];
	area[24] = Tbl[(c1 & 0xfc) >> 2];
	area[25] = Tbl[((c1 & 0x03) << 4) | ((c2 & 0xf0) >> 4)];
	area[26] = Tbl[((c2 & 0x0f) << 2)];
	area[27] = '=';
}

static
void FillWindowsVersionArea(uint8_t area[20])
{
	const uint8_t WinVersion[20] = "r70393861";
	memcpy(area, WinVersion, 20);
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}


static void FillClientVersionArea(uint8_t area[20])
{
	uint32_t random;
	char     RandomKey[8 + 1];

	random = (uint32_t)time(NULL);    // 注：可以选任意32位整数
	sprintf(RandomKey, "%08x", random);// 生成RandomKey[]字符串

	// 第一轮异或运算，以RandomKey为密钥加密16字节
	memcpy(area, H3C_VERSION, sizeof(H3C_VERSION));
	XOR(area, 16, RandomKey, strlen(RandomKey));

	// 此16字节加上4字节的random，组成总计20字节
	random = htonl(random); // （需调整为网络字节序） big-endian
	memcpy(area + 16, &random, 4);

	// 第二轮异或运算，以H3C_KEY为密钥加密前面生成的20字节
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

static void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen)
{
	unsigned int    i, j;

	// 先按正序处理一遍
	for (i = 0; i < dlen; i++)
		data[i] ^= key[i%klen];
	// 再按倒序处理第二遍
	for (i = dlen - 1, j = 0; j < dlen; i--, j++)
		data[i] ^= key[j%klen];
}
int matchName(const char *c1, const char *c2)
{
	string cc1(c1);
	string cc2(c2);
	if (cc2.find(cc1) != cc2.npos)return 1;
	return 0;
}
