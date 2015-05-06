// EAP_Monitor.cpp : �������̨Ӧ�ó������ڵ㡣
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

	//ע��������
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
	const int DefaultTimeout = 1000;//���ý��ճ�ʱ��������λms

	// NOTE: ����û�м�������Ƿ��Ѳ��,���߲�ڿ��ܽӴ�����

	/* ��������(����) */
	adhandle = pcap_open_live(DeviceName, 65536, 1, DefaultTimeout, errbuf);
	if (adhandle == NULL) {
		fprintf(stderr, "%s\n", errbuf);
		EXIT(-1);
	}

	/* ��ѯ����MAC��ַ */
	GetMacFromDevice(MAC, DeviceName);

	/*
	* ���ù�������
	* ��ʼ�����ֻ������������802.1X��֤�Ự�������նಥ��Ϣ�������󲶻������ͻ��˷����Ķಥ��Ϣ��
	* ����ѭ����ǰ�����������������ʱ�ٿ�ʼ���նಥ��Ϣ
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
		// ��дӦ����ı�ͷ(�Ժ��������޸�)
		// Ĭ���Ե�����ʽӦ��802.1X��֤�豸������Request
		memcpy(ethhdr + 0, captured + 6, 6);
		memcpy(ethhdr + 6, MAC, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;

		sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			captured[6], captured[7], captured[8], captured[9], captured[10], captured[11]);
		pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
		pcap_setfilter(adhandle, &fcode);

		// ����ѭ����
		for (;;)
		{
			// ����pcap_next_ex()�����������ݰ�
			while (pcap_next_ex(adhandle, &header, &captured) != 1)
			{
				DPRINTF("."); // ������ʧ�ܣ����1�������
				sleep(1);// ֱ���ɹ�����һ�����ݰ���������
				// NOTE: ����û�м�������Ƿ��ѱ����»��ڽӴ�����
			}

			// �����յ���Request���ظ���Ӧ��Response��
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
			{    // ������֤ʧ����Ϣ
				NeedPause = 1;
				uint8_t errtype = captured[22];
				uint8_t msgsize = captured[23];
				const char *msg = (const char*)&captured[24];
				DPRINTF("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
				if (errtype == 0x09 && msgsize > 0)
				{    // ���������ʾ��Ϣ
					fprintf(stderr, "%s\n", msg);
					// ��֪�ļ��ִ�������
					// E2531:�û���������
					// E2535:Service is paused
					// E2542:���û��ʺ��Ѿ��ڱ𴦵�¼
					// E2547:����ʱ������
					// E2553:�������
					// E2602:��֤�Ự������
					// E3137:�ͻ��˰汾����Ч
					EXIT(-1);
				}
				else if (errtype == 0x08) // ��������������ʱ�����������˴�802.1X��֤�Ự
				{    // ��������ͻ������̷����µ���֤�Ự
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
//Description:            �������������������ʵ�ֶԷ���Ŀ��ƣ�
//                        ���ڷ����������ֹͣ����������ʱ���������д˴�����
//Calls:
//Called By:
//Table Accessed:
//Table Updated:
//Input:                dwOpcode�����Ʒ����״̬
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
//Description:            �жϷ����Ƿ��Ѿ�����װ
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

	//�򿪷�����ƹ�����
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (hSCM != NULL)
	{
		//�򿪷���
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
//Description:            ��װ������
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

	//�򿪷�����ƹ�����
	SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL)
	{
		MessageBox(NULL, _T("Couldn't open service manager"), szServiceName, MB_OK);
		return FALSE;
	}

	// Get the executable file path
	TCHAR szFilePath[MAX_PATH];
	::GetModuleFileName(NULL, szFilePath, MAX_PATH);

	//��������
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
//Description:            ɾ��������
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

	//ɾ������
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
//Description:            ��¼�����¼�
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
		|| (EAP_Type)request[22] == AVAILABLE); // �������ϲƾ�������ѧ���

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
	response[14] = 0x1;    // 802.1X Version 1
	response[15] = 0x0;    // Type=0 (EAP Packet)
	//response[16~17]����    // Length

	// Extensible Authentication Protocol
	// {
	response[18] = (EAP_Code)RESPONSE;    // Code
	response[19] = request[19];        // ID
	//response[20~21]����            // Length
	response[22] = (EAP_Type)IDENTITY;    // Type
	// Type-Data
	// {
	i = 23;
	//response[i++] = 0x15;      // �ϴ�IP��ַ
	//response[i++] = 0x04;      //
	//memcpy(response+i, ip, 4);//
	//i += 4;              //
	response[i++] = 0x06;          // Я���汾��
	response[i++] = 0x07;          //
	//memcpy(response+i, "bjQ7SE8BZ3MqHhs3clMregcDY3Y=", sizeof("bjQ7SE8BZ3MqHhs3clMregcDY3Y="));
	FillBase64Area((char*)response + i);//
	i += 28;              //
	response[i++] = ' '; // �����ո��
	response[i++] = ' '; //
	usernamelen = strlen(username); //ĩβ����û���
	memcpy(response + i, username, usernamelen);
	i += usernamelen;
	assert(i <= sizeof(response));
	// }
	// }
	// }

	// ����ǰ�����յ�����Length
	//��Ҫ���˴���0x25���Թ���������ݰ��е����볤��bug
	eaplen = htons(usernamelen + 0x25);
	memcpy(response + 16, &eaplen, sizeof(eaplen));
	memcpy(response + 20, &eaplen, sizeof(eaplen));

	// ����
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
		/*����������ص���ERROR_BUFFER_OVERFLOW
		��˵��GetAdaptersInfo�������ݵ��ڴ�ռ䲻��,ͬʱ�䴫��stSize,��ʾ��Ҫ�Ŀռ��С
		��Ҳ��˵��ΪʲôstSize����һ��������Ҳ��һ�������*/
		//�ͷ�ԭ�����ڴ�ռ�
		delete pIpAdapterInfo;
		//���������ڴ�ռ������洢����������Ϣ
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		//�ٴε���GetAdaptersInfo����,���pIpAdapterInfoָ�����
		nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
	}
	if (ERROR_SUCCESS == nRel)
	{
		//���������Ϣ
		//�����ж�����,���ͨ��ѭ��ȥ�ж�
		while (pIpAdapterInfo)
		{
			if (pIpAdapterInfo->Type == MIB_IF_TYPE_ETHERNET)
			{
				char *buf = new char[strlen(devicename) + 1];
				strcpy(buf, devicename);
				if (matchName(pIpAdapterInfo->AdapterName, buf))
				{
					//ת��MAC���ݵ�mac����
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
		"0123456789+/"; // ��׼��Base64�ַ�ӳ���
	uint8_t    c1, c2, c3;
	int    i, j;

	// ��������20�ֽڼ��ܹ���H3C�汾����Ϣ
	FillClientVersionArea(version);

	// Ȼ����Base64���뷨��ǰ�����ɵ�20�ֽ�����ת��Ϊ28�ֽ�ASCII�ַ�
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

	random = (uint32_t)time(NULL);    // ע������ѡ����32λ����
	sprintf(RandomKey, "%08x", random);// ����RandomKey[]�ַ���

	// ��һ��������㣬��RandomKeyΪ��Կ����16�ֽ�
	memcpy(area, H3C_VERSION, sizeof(H3C_VERSION));
	XOR(area, 16, RandomKey, strlen(RandomKey));

	// ��16�ֽڼ���4�ֽڵ�random������ܼ�20�ֽ�
	random = htonl(random); // �������Ϊ�����ֽ��� big-endian
	memcpy(area + 16, &random, 4);

	// �ڶ���������㣬��H3C_KEYΪ��Կ����ǰ�����ɵ�20�ֽ�
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

static void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen)
{
	unsigned int    i, j;

	// �Ȱ�������һ��
	for (i = 0; i < dlen; i++)
		data[i] ^= key[i%klen];
	// �ٰ�������ڶ���
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
