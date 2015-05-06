
#include "Auth.h"
#define HAVE_REMOTE

/**
* 函数：Authentication()
*
* 使用以太网进行802.1X认证(802.1X Authentication)
* 该函数将不断循环，应答802.1X认证会话，直到遇到错误后才退出
*/

using namespace std;

int main(int argc,char *argv[])
{
	bool isLogin = true;
	const char *DeviceName;
	string arguments[5];

	if (argc > 5){ cerr << "错误的参数设置" << endl; system("pause"); EXIT(0); }//参数数量基本判定
	for (int i=0;i<argc;i++)arguments[i]=argv[i];//转换参数列表到string数组
	
	/*
	参数列表：
	无参数
	/help
	/connect Username Password
	/connect Username Password PcapID
	/disconnect
	/disconnect PcapID
	*/

	if (arguments[1] == "/disconnect" && argc == 3) //如果使用/disconnnect并且给出了PcapID
	{
		//isLogin=false;
		//DeviceName=GetDeviceList(isLogin);

		DeviceName=arguments[2].c_str();
		cout<<"下线中，请稍候"<<endl;
		SendLogoffPkt(DeviceName);			//发送下线数据包
		Sleep(1000);						//避免未下线完成前刷新IP导致错误
		cout<<"正在刷新IP地址..."<<endl;
		cout<<DeviceName<<endl;
		//RenewSpecifiedDevice(DeviceName);
		system("ipconfig -release > nul");
		system("ipconfig -release6 > nul");
		cout<<"下线完成。"<<endl;
		NeedPause=false;
	}
	else
	{

		if(argc == 1) //没有参数时
		{
			GetDeviceList(true);
			NeedPause=true;
		}
		else
		{
			if(argc == 5 && arguments[1] == "/connect")		//给出用户名、密码、PcapID时
			{
				isLogin=true;
				GetDeviceList(isLogin,arguments[2].c_str(),arguments[3].c_str(),arguments[4].c_str());//认证
			}
			else
			{
				if (argc==4 && arguments[1] == "/connect")	//仅给出用户名、密码
				{
					isLogin=true;
					string dname;
					dname= GetDeviceList(false);			//获得设备PcapID
					GetDeviceList(isLogin,arguments[2].c_str(),arguments[3].c_str(),dname.c_str());//认证
					NeedPause=true;
				}
				else
				{
					if(argc == 2 && arguments[1] == "/help")//输出帮助信息
					{
						cout<<"     本程序使用方法：\n\nEAP_H3C_AUTH [ /connect | /disconnect] [Username] [Password] [PCAPID] \n     1.直接运行\n\n     2.参数：\n          EAP_H3C_Auth /connect 用户名 密码       用于给出用户名及密码的登录\n          EAP_H3C_Auth /connect 用户名 密码 PcapID        用于已知PcapID用户上线。PcapID 为以下字符串加上cimv2数据库中获取的设备ID。\n              PCAP字串：rpcap://\\DEVICE\\NPF_\n          EAP_H3C_Auth /disconnect PCAPID 用于用户下线。\n          EAP_H3C_Auth /disconnect        用于未知设备PcapID的用户下线。\n     3.使用GUI界面进行调用。"<<endl;
					}
					else
					{
						if(argc == 2 && arguments[1] == "/disconnect")//不带PcapID的下线
						{
							isLogin=false;					//不登录
							string dname;
							dname= GetDeviceList(isLogin);	//获得设备PcapID
							cout<<"下线中，请稍候"<<endl;
							SendLogoffPkt(dname.c_str());	//下线
							Sleep(1000);					//避免未下线完成前刷新IP导致错误
							//Stop Monitor Service.
							cout<<"正在刷新IP地址..."<<endl;
							//RenewSpecifiedDevice(DeviceName);
							system("ipconfig -release > nul");
							system("ipconfig -release6 > nul");
							cout<<"下线完成。"<<endl;
							NeedPause=true;
						}
						else								//参数列错误
						{
							cout<<"错误的参数列表！"<<endl<<"详情请使用/help指令查看。";
							NeedPause=true;
						}
					}
				}
			}
		}
	}
	NeedPause = true;
	cout<<endl;
	if (NeedPause)system("pause");
	return 0;
}

int Authentication(const char *UserName, const char *Password, const char *DeviceName)
{
	char    errbuf[PCAP_ERRBUF_SIZE];
	pcap_t    *adhandle; // adapter handle
	uint8_t    MAC[6];

	char    FilterStr[100];
	struct bpf_program    fcode;
	const int DefaultTimeout=1000;//设置接收超时参数，单位ms

	// NOTE: 这里没有检查网线是否已插好,网线插口可能接触不良

	/* 打开适配器(网卡) */
	adhandle = pcap_open_live(DeviceName,65536,1,DefaultTimeout,errbuf);
	if (adhandle==NULL) {
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
		MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
	pcap_compile(adhandle, &fcode, FilterStr, 1, 0xff);
	pcap_setfilter(adhandle, &fcode);


START_AUTHENTICATION:
	{
		int retcode;
		struct pcap_pkthdr *header;
		const uint8_t    *captured;
		uint8_t    ethhdr[14]={0}; // ethernet header
		uint8_t    ip[4]={0};    // ip address

		/* 主动发起认证会话 */
		SendStartPkt(adhandle, MAC);
		DPRINTF("[ ] Client: Start.\n");

		/* 等待认证服务器的回应 */
		bool serverIsFound = false;
		while (!serverIsFound)
		{
			retcode = pcap_next_ex(adhandle, &header, &captured);
			if (retcode==1 && (EAP_Code)captured[18]==REQUEST)
				serverIsFound = true;
			else
			{    // 延时后重试
				sleep(1); DPRINTF(".");
				SendStartPkt(adhandle, MAC);
				// NOTE: 这里没有检查网线是否接触不良或已被拔下
			}
		}

		// 填写应答包的报头(以后无须再修改)
		// 默认以单播方式应答802.1X认证设备发来的Request
		memcpy(ethhdr+0, captured+6, 6);
		memcpy(ethhdr+6, MAC, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;

		// 收到的第一个包可能是Request Notification。取决于校方网络配置
		if ((EAP_Type)captured[22] == NOTIFICATION)
		{
			DPRINTF("[%d] Server: Request Notification!\n", captured[19]);
			// 发送Response Notification
			SendResponseNotification(adhandle, captured, ethhdr);
			DPRINTF("    Client: Response Notification.\n");

			// 继续接收下一个Request包
			retcode = pcap_next_ex(adhandle, &header, &captured);
			assert(retcode==1);
			assert((EAP_Code)captured[18] == REQUEST);
		}

		// 分情况应答下一个包
		if ((EAP_Type)captured[22] == IDENTITY)
		{    // 通常情况会收到包Request Identity，应回答Response Identity
			DPRINTF("[%d] Server: Request Identity!\n", captured[19]);
			GetIpFromDevice(ip, DeviceName);
			SendResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
			DPRINTF("[%d] Client: Response Identity.\n", (EAP_ID)captured[19]);
		}
		else if ((EAP_Type)captured[22] == AVAILABLE)
		{    // 遇到AVAILABLE包时需要特殊处理
			// 中南财经政法大学目前使用的格式：
			// 收到第一个Request AVAILABLE时要回答Response Identity
			DPRINTF("[%d] Server: Request AVAILABLE!\n", captured[19]);
			GetIpFromDevice(ip, DeviceName);
			SendResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
			DPRINTF("[%d] Client: Response Identity.\n", (EAP_ID)captured[19]);
		}
		else if ((EAP_Type)captured[22] == ALLOCATED)
		{
			//ALLOCATED
		}
		// 重设过滤器，只捕获华为802.1X认证设备发来的包（包括多播Request Identity / Request AVAILABLE）
		sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			captured[6],captured[7],captured[8],captured[9],captured[10],captured[11]);
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
				case AVAILABLE:
					DPRINTF("[%d] Server: Request AVAILABLE!\n", (EAP_ID)captured[19]);
					GetIpFromDevice(ip, DeviceName);
					SendResponseAvailable(adhandle, captured, ethhdr, ip, UserName);
					DPRINTF("[%d] Client: Response AVAILABLE.\n", (EAP_ID)captured[19]);
					break;
				case MD5:
					DPRINTF("[%d] Server: Request MD5-Challenge!\n", (EAP_ID)captured[19]);
					SendResponseMD5(adhandle, captured, ethhdr, UserName, Password);
					DPRINTF("[%d] Client: Response MD5-Challenge.\n", (EAP_ID)captured[19]);
					break;
				case NOTIFICATION:
					DPRINTF("[%d] Server: Request Notification!\n", captured[19]);
					SendResponseNotification(adhandle, captured, ethhdr);
					DPRINTF("Client: Response Notification.\n");
					break;
				case ALLOCATED:
					DPRINTF("[%d] Server:Request Normal Verfication.\n",captured[19]);
					SendResponseH3C(adhandle,captured,ethhdr,UserName,Password);
					DPRINTF("[%d] Client: Response Allocated(Password).\n", (EAP_ID)captured[19]);
					break;
				default:
					DPRINTF("[%d] Server: Request (type:%d)!\n", (EAP_ID)captured[19], (EAP_Type)captured[22]);
					DPRINTF("Error! Unexpected request type\n");
					EXIT(-1);
					break;
				}
			}
			else if ((EAP_Code)captured[18] == FAILURE)
			{    // 处理认证失败信息
				NeedPause=1; 
				uint8_t errtype = captured[22];
				uint8_t msgsize = captured[23];
				const char *msg = (const char*) &captured[24];
				DPRINTF("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
				if (errtype==0x09 && msgsize>0)
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
				else if (errtype==0x08) // 可能网络无流量时服务器结束此次802.1X认证会话
				{    // 遇此情况客户端立刻发起新的认证会话
					goto START_AUTHENTICATION;
				}
				else
				{
					DPRINTF("errtype=0x%02x\n", errtype);
					NeedPause=1;
					EXIT(-1);
				}
			}
			else if ((EAP_Code)captured[18] == SUCCESS)
			{
				DPRINTF("[%d] Server: Success.\n", captured[19]);
				cout<<"正在刷新IP地址,请稍候...(若刷新时间较长可直接退出)"<<endl;
				// 刷新IP地址
				//RenewSpecifiedDevice(DeviceName); not suopported
				system("ipconfig /release > nul");
				system("ipconfig /release6 > nul");
				system("ipconfig /renew >nul");
				system("ipconfig /renew6 >nul");
				cout<<"认证过程完成！"<<endl;
				ofstream ofs("eap_online_status", ios::trunc);
				FILE *bin_out = fopen("eap_pkt_data","wb+");
				ofs << DeviceName <<" "<< UserName << endl;
				ofs.close();
				for (int i = 0; i < sizeof(captured) / sizeof(uint8_t); i++)
				{
					fwrite(&captured[i], sizeof(captured), sizeof(uint8_t), bin_out);
				}
				fclose(bin_out);
				//system("net start EAP_ONLINE_SERVICE");
				/*
				FILE *bin_out_2 = fopen("eap_ip_data", "wb+");
				for (int i = 0; i < sizeof(ip) / sizeof(uint8_t); i++)
				{
					fwrite(&ip[i], sizeof(ip), sizeof(uint8_t), bin_out_2);
				}
				fclose(bin_out_2);
				//Start Monitor Service*/
				//break;
			}
			else
			{
				DPRINTF("[%d] Server: (H3C data)\n", captured[19]);
				// TODO: 这里没有处理华为自定义数据包 
			}
		}
	}
	return (0);
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
	int nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
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
		nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);    
	}
	if (ERROR_SUCCESS == nRel)
	{
		//输出网卡信息
		//可能有多网卡,因此通过循环去判断
		while (pIpAdapterInfo)
		{
			if (pIpAdapterInfo->Type == MIB_IF_TYPE_ETHERNET)
			{
				char *buf = new char[strlen(devicename)+1];
				strcpy(buf,devicename);
				if (matchName(pIpAdapterInfo->AdapterName,buf))
				{
					//转移MAC数据到mac数组
					for (int k=0;k<6;k++)
					{
						mac[k]=(uint8_t)pIpAdapterInfo->Address[k];
					}
					break;
				}
			}
			pIpAdapterInfo = pIpAdapterInfo->Next;
		}
	}
	return;

}
static void RenewSpecifiedDevice(const char *devicename)
{
	char t[128]={0};string tmp = devicename;
	for (int i=20;i<tmp.length();i++)
		t[i-20]=tmp[i];
	//for (int i=tmp.length();i<128;i++)
		//t[i]='\0';
	string ir = "\\DEVICE\\TCPIP_";
	string t2(t);
	ir += t;
	const char *dev = ir.c_str();
	ULONG ulOutBufLen = 0;
	DWORD dwRetVal = 0;
	PIP_INTERFACE_INFO pInfo;
	int nRel = 0;

	pInfo = (IP_INTERFACE_INFO *) MALLOC(sizeof(IP_INTERFACE_INFO));//声明一个IPInterfaceInfo
	nRel = GetInterfaceInfo(pInfo,&ulOutBufLen);
	//若空间不够则重新申请空间
	if (nRel == ERROR_INSUFFICIENT_BUFFER) {
		FREE(pInfo);
		pInfo = (IP_INTERFACE_INFO *) MALLOC (ulOutBufLen);
		nRel=GetInterfaceInfo(pInfo,&ulOutBufLen);
	}

	if (ERROR_SUCCESS == GetInterfaceInfo(pInfo,&ulOutBufLen))
	{
		while (pInfo)
		{
			char *buf = new char[strlen(devicename)+1];
			strcpy(buf,devicename);
			char name[128];
			wsprintf(name,"%ws",pInfo->Adapter[0].Name);
			
			//if (matchName(dev,name))
			//{
				//IpReleaseAddress(&pInfo->Adapter[0]);
				IpRenewAddress(&pInfo->Adapter[0]);
				Sleep(5000);
				break;
			//}
			
		}

	}
}


//判断两个字符串是否相同
int matchName(const char *c1,const char *c2)
{
	string cc1(c1);
	string cc2(c2);
	if (cc2.find(cc1) != cc2.npos)return 1;
	return 0;
}
/*
int matchName(const char *c1,char *c2)
{
	string cc1(c1);
	string cc2(c2);
	if (cc2.find(cc1) != cc2.npos)return 1;
	return 0;
}*/

char *wcharTochar(const wchar_t *wchar, int length)   
{   
	char chr[512];
	WideCharToMultiByte( CP_ACP, 0, wchar, -1,   
		chr, length, NULL, NULL ); 
	return chr;
}  

static    void SendStartPkt(pcap_t *handle, const uint8_t localmac[])
{
	uint8_t packet[18];

	// Ethernet Header (14 Bytes)
	memcpy(packet, BroadcastAddr, 6);
	memcpy(packet+6, localmac,   6);
	packet[12] = 0x88;
	packet[13] = 0x8e;

	// EAPOL (4 Bytes)
	packet[14] = 0x01;    // Version=1
	packet[15] = 0x01;    // Type=Start
	packet[16] = packet[17] =0x00;// Length=0x0000

	// 为了兼容不同院校的网络配置，这里发送两遍Start包
	// 1、广播发送Strat包
	//pcap_sendpacket(handle, packet, sizeof(packet));
	// 2、多播发送Strat包
	memcpy(packet, MultcastAddr, 6);
	pcap_sendpacket(handle, packet, sizeof(packet));
}


static void SendResponseAvailable(pcap_t *handle, const uint8_t request[], const uint8_t ethhdr[], const uint8_t ip[4], const char username[])
{
	int i;
	uint16_t eaplen;
	int usernamelen;
	uint8_t response[128];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == AVAILABLE);

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
	response[14] = 0x1;    // 802.1X Version 1
	response[15] = 0x0;    // Type=0 (EAP Packet)
	//response[16~17]留空    // Length

	// Extensible Authentication Protocol
	// {
	response[18] = (EAP_Code) RESPONSE;    // Code
	response[19] = request[19];        // ID
	//response[20~21]留空            // Length
	response[22] = (EAP_Type) AVAILABLE;    // Type
	// Type-Data
	// {
	i = 23;
	response[i++] = 0x00;// 上报是否使用代理
	response[i++] = 0x15;      // 上传IP地址
	response[i++] = 0x04;      //
	memcpy(response+i, ip, 4);//
	i += 4;              //
	response[i++] = 0x06;          //	携带版本号
	response[i++] = 0x07;          //
	FillBase64Area((char*)response+i);//
	i += 28;              //
	response[i++] = ' '; // 两个空格符
	response[i++] = ' '; //
	usernamelen = strlen(username);
	memcpy(response+i, username, usernamelen);//
	i += usernamelen;              //
	// }
	// }
	// }

	// 补填前面留空的两处Length
	eaplen = htons(i-18);
	memcpy(response+16, &eaplen, sizeof(eaplen));
	memcpy(response+20, &eaplen, sizeof(eaplen));

	// 发送
	pcap_sendpacket(handle, response, i);
}


static void SendResponseIdentity(pcap_t *adhandle, const uint8_t request[], const uint8_t ethhdr[], const uint8_t ip[4], const char username[])
{
	uint8_t    response[128];
	size_t i;
	uint16_t eaplen;
	int usernamelen;

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == IDENTITY
		||(EAP_Type)request[22] == AVAILABLE); // 兼容中南财经政法大学情况

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
	response[14] = 0x1;    // 802.1X Version 1
	response[15] = 0x0;    // Type=0 (EAP Packet)
	//response[16~17]留空    // Length

	// Extensible Authentication Protocol
	// {
	response[18] = (EAP_Code) RESPONSE;    // Code
	response[19] = request[19];        // ID
	//response[20~21]留空            // Length
	response[22] = (EAP_Type) IDENTITY;    // Type
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
	FillBase64Area((char*)response+i);//
	i += 28;              //
	response[i++] = ' '; // 两个空格符
	response[i++] = ' '; //
	usernamelen = strlen(username); //末尾添加用户名
	memcpy(response+i, username, usernamelen);
	i += usernamelen;
	assert(i <= sizeof(response));
	// }
	// }
	// }

	// 补填前面留空的两处Length
	//重要！此处的0x25可以规避明码数据包中的密码长度bug
	eaplen = htons(usernamelen + 0x25);
	memcpy(response+16, &eaplen, sizeof(eaplen));
	memcpy(response+20, &eaplen, sizeof(eaplen));

	// 发送
	pcap_sendpacket(adhandle, response, 55+usernamelen);
	return;
}


static void SendResponseMD5(pcap_t *handle, const uint8_t request[], const uint8_t ethhdr[], const char username[], const char passwd[])
{
	uint16_t eaplen;
	size_t   usernamelen;
	size_t   packetlen;
	size_t   passwdlen;
	uint8_t  response[128];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == MD5);

	usernamelen = strlen(username);
	passwdlen = strlen(passwd);
	eaplen = htons(22+usernamelen);
	packetlen = 14+4+22+usernamelen; // ethhdr+EAPOL+EAP+usernamelen

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802.1X Authentication
	// {
	response[14] = 0x1;	// 802.1X Version 1
	response[15] = 0x0;	// Type=0 (EAP Packet)
	memcpy(response+16, &eaplen, sizeof(eaplen));	// Length

	// Extensible Authentication Protocol
	// {
	response[18] = (EAP_Code) RESPONSE;// Code
	response[19] = request[19];	// ID
	response[20] = response[16];	// Length
	response[21] = response[17];	//
	response[22] = (EAP_Type) MD5;	// Type
	response[23] = 16;		// Value-Size: 16 Bytes


	uint8_t md5[16];
	int jj=0;
	size_t kk=passwdlen;
	int ll=0;

	for(;jj<passwdlen;jj++){
		md5[jj] = passwd[jj];
	}
	for(;kk<16;kk++){
		md5[kk] = 0x00; //MD5 lenth is 16,if password lenth < 16 ,fill 0x0 after it
	}
	uint8_t chap[16];
	for(;ll<16;ll++)
	{
		chap[ll] = md5[ll]^request[24+ll]; //fill MD5 area
	}
	memcpy(response+24, chap, sizeof(chap));
	memcpy(response+40, username, usernamelen);
	// }
	// }

	pcap_sendpacket(handle, response, packetlen);
}

static void SendLogoffPkt(const char* DeviceName)
{
	char    errbuf[PCAP_ERRBUF_SIZE];
	pcap_t    *handle; // adapter handle
	uint8_t    localmac[6];

	char    FilterStr[100];
	struct bpf_program    fcode;
	const int DefaultTimeout=1000;//设置接收超时参数，单位ms

	// NOTE: 这里没有检查网线是否已插好,网线插口可能接触不良

	/* 打开适配器(网卡) */
	handle = pcap_open_live(DeviceName,65536,1,DefaultTimeout,errbuf);
	if (handle==NULL) {
		fprintf(stderr, "%s\n", errbuf); 
		EXIT(-1);
	}

	/* 查询本机MAC地址 */
	GetMacFromDevice(localmac, DeviceName);

	uint8_t packet[18];
	// Ethernet Header (14 Bytes)
	memcpy(packet, MultcastAddr, 6);
	memcpy(packet+6, localmac,   6);
	packet[12] = 0x88;
	packet[13] = 0x8e;
	// EAPOL (4 Bytes)
	packet[14] = 0x01;    // Version=1
	packet[15] = 0x02;    // Type=Logoff
	packet[16] = packet[17] =0x00;// Length=0x0000
	// 发包
	pcap_sendpacket(handle, packet, sizeof(packet));
}


// 函数: XOR(data[], datalen, key[], keylen)
//
// 使用密钥key[]对数据data[]进行异或加密
//（注：该函数也可反向用于解密）
// 异或算法：1011 XOR 233 = 794,794 XOR 233 = 1011
static void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen)
{
	unsigned int    i,j;

	// 先按正序处理一遍
	for (i=0; i<dlen; i++)
		data[i] ^= key[i%klen];
	// 再按倒序处理第二遍
	for (i=dlen-1,j=0;  j<dlen;  i--,j++)
		data[i] ^= key[j%klen];
}

static void FillClientVersionArea(uint8_t area[20])
{
	uint32_t random;
	char     RandomKey[8+1];

	random = (uint32_t) time(NULL);    // 注：可以选任意32位整数
	sprintf(RandomKey, "%08x", random);// 生成RandomKey[]字符串

	// 第一轮异或运算，以RandomKey为密钥加密16字节
	memcpy(area, H3C_VERSION, sizeof(H3C_VERSION));
	XOR(area, 16, RandomKey, strlen(RandomKey));

	// 此16字节加上4字节的random，组成总计20字节
	random = htonl(random); // （需调整为网络字节序） big-endian
	memcpy(area+16, &random, 4);

	// 第二轮异或运算，以H3C_KEY为密钥加密前面生成的20字节
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}


static
	void FillWindowsVersionArea(uint8_t area[20])
{
	const uint8_t WinVersion[20] = "r70393861";
	memcpy(area, WinVersion, 20);
	XOR(area, 20, H3C_KEY, strlen(H3C_KEY));
}

static void SendResponseNotification(pcap_t *handle, const uint8_t request[], const uint8_t ethhdr[])
{
	uint8_t    response[67];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == NOTIFICATION);

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
	response[14] = 0x1;    // 802.1X Version 1
	response[15] = 0x0;    // Type=0 (EAP Packet)
	response[16] = 0x00;    // Length
	response[17] = 0x31;    //

	// Extensible Authentication Protocol
	// {
	response[18] = (EAP_Code) RESPONSE;    // Code
	response[19] = (EAP_ID) request[19];    // ID
	response[20] = response[16];        // Length
	response[21] = response[17];        //
	response[22] = (EAP_Type) NOTIFICATION;    // Type

	int i=23;
	/* Notification Data (44 Bytes) */
	// 其中前2+20字节为客户端版本
	response[i++] = 0x01; // type 0x01
	response[i++] = 22;   // lenth
	FillClientVersionArea(response+i);
	i += 20;

	// 最后2+20字节存储加密后的Windows操作系统版本号
	response[i++] = 0x02; // type 0x02
	response[i++] = 22;   // length
	FillWindowsVersionArea(response+i);
	i += 20;
	// }
	// }

	pcap_sendpacket(handle, response, sizeof(response));
}


static void FillBase64Area(char area[])
{
	uint8_t version[20];
	const char Tbl[] =  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/"; // 标准的Base64字符映射表
	uint8_t    c1,c2,c3;
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
		area[j++] = Tbl[ (c1&0xfc)>>2 ];
		area[j++] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)];
		area[j++] = Tbl[((c2&0x0f)<<2)|((c3&0xc0)>>6)];
		area[j++] = Tbl[  c3&0x3f];
	}
	c1 = version[i++];
	c2 = version[i++];
	area[24] = Tbl[ (c1&0xfc)>>2 ];
	area[25] = Tbl[((c1&0x03)<<4)|((c2&0xf0)>>4)];
	area[26] = Tbl[((c2&0x0f)<<2)];
	area[27] = '=';
}
/*生成MD5数据不可用
void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[])
{
uint8_t    msgbuf[128]; // msgbuf = ‘id‘ + ‘passwd’ + ‘srcMD5’
size_t    msglen;
size_t    passlen;

passlen = strlen(passwd);
msglen = 1 + passlen + 16;
assert(sizeof(msgbuf) >= msglen);

msgbuf[0] = id;
memcpy(msgbuf+1,     passwd, passlen);
memcpy(msgbuf+1+passlen, srcMD5, 16);

(void) MD5(msgbuf, msglen, digest);
}
*/
int EXIT(int errcode)
{
	if(NeedPause)system("pause");
	exit(errcode);
}

string GetDeviceList(bool GoAuth)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0,counter;
	char errbuf[PCAP_ERRBUF_SIZE];
	string dNameList[32];
	string dDeviceList[64];
	/* 获取本地机器设备列表 */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	counter=0;
	/* 打印列表 */
	//遍历网卡列表并输出
	cout.setf(ios::left);
	cout<<"请选择你要使用的网卡："<<endl;
	cout<<setw(5)<<"序号 "<<setw(70)<<"网卡名称"<<"网卡描述"<<endl;
	for(d=alldevs; d != NULL; d= d->next)
	{
		//输出格式化
		cout<<setw(5)<<++i;
		cout<<setw(69)<<d->name;
		dNameList[counter]=d->name;
		counter++;
		if (d->description)printf(" (%s)\n", d->description);
		else printf(" (No description available)\n");
	}
	if (i == 0)//找不到网卡时处理
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return "";
	}
	/* 不再需要设备列表了，释放它 */
	pcap_freealldevs(alldevs);

	//用户选择使用的网卡
	int selection = 0;
	const char *DeviceName;
	cout<<"请选择序号：";
	while (1)
	{
		cin>>selection;
		if (selection > counter-1)continue;
		else
		{
			DeviceName=dNameList[selection-1].c_str();
			break;
		}
	};
	if(GoAuth)PrepareAuth(DeviceName);//如果不进行认证则跳过认证
	string retstr(DeviceName); //毫无道理的无法返回const char*,用string替换。
	return retstr;
}

const char * GetDeviceList(bool GoAuth,const char *usr,const char *psw,const char *dname)
{
	//用于已给出用户名、密码及设备PcapID的时候使用
	if (dname != "")cout<<Authentication(usr,psw,dname);
	return dname;
}


static void PrepareAuth(const char *DeviceName)
{
	//没有给出用户名和密码，获取用户名和密码
	const char *au ,*bp,*dName;
	char a[32],b[128];
	cout<<"请输入用户名:";
	scanf("%s",a);
	cout<<"请输入密码：";
	scanf("%s",b);
	au=a;
	bp=b;
	if (DeviceName != "")cout<<Authentication(a,b,DeviceName);
}

static void SendResponseH3C(pcap_t *handle,const uint8_t request[],const uint8_t ethhdr[],const char username[],const char passwd[])
{
	if (username == NULL || passwd == NULL){cout<<"Username or password does not exist.quit."<<endl;EXIT(0);}//判定用户名和密码不为空
	//uint8_t
	uint16_t eaplen;
	size_t   usernamelen;
	size_t   passwordlen;
	size_t   packetlen;
	uint8_t  response[128];

	assert((EAP_Code)request[18] == REQUEST);
	assert((EAP_Type)request[22] == ALLOCATED);

	usernamelen = strlen(username);
	passwordlen = strlen(passwd);
	eaplen = htons(6+usernamelen+passwordlen);
	packetlen =24+usernamelen+passwordlen; //14+4+22+usernamelen; // ethhdr+EAPOL+EAP+usernamelen

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802.1X Authentication
	// {
	response[14] = 0x1;	// 802.1X Version 1
	response[15] = 0x0;	// Type=0 (EAP Packet)
	memcpy(response+16, &eaplen, sizeof(eaplen));	// Length

	// Extensible Authentication Protocol
	// {
	response[18] = (EAP_Code) RESPONSE;// Code
	response[19] = request[19];	// ID
	response[20] = response[16];	// Length
	response[21] = response[17];	//
	response[22] = (EAP_Type) ALLOCATED;	// Type
	response[23] = passwordlen;		// Value-Size: 16 Bytes
	memcpy(response+24, passwd, passwordlen);
	memcpy(response+24+passwordlen+1, username, usernamelen);//?????
	// }

	pcap_sendpacket(handle, response, packetlen);
}
