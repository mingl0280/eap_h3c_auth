
#include "Auth.h"
#define HAVE_REMOTE

/**
* ������Authentication()
*
* ʹ����̫������802.1X��֤(802.1X Authentication)
* �ú���������ѭ����Ӧ��802.1X��֤�Ự��ֱ�������������˳�
*/

using namespace std;

int main(int argc,char *argv[])
{
	bool isLogin = true;
	const char *DeviceName;
	string arguments[5];

	if (argc > 5){ cerr << "����Ĳ�������" << endl; system("pause"); EXIT(0); }//�������������ж�
	for (int i=0;i<argc;i++)arguments[i]=argv[i];//ת�������б�string����
	
	/*
	�����б�
	�޲���
	/help
	/connect Username Password
	/connect Username Password PcapID
	/disconnect
	/disconnect PcapID
	*/

	if (arguments[1] == "/disconnect" && argc == 3) //���ʹ��/disconnnect���Ҹ�����PcapID
	{
		//isLogin=false;
		//DeviceName=GetDeviceList(isLogin);

		DeviceName=arguments[2].c_str();
		cout<<"�����У����Ժ�"<<endl;
		SendLogoffPkt(DeviceName);			//�����������ݰ�
		Sleep(1000);						//����δ�������ǰˢ��IP���´���
		cout<<"����ˢ��IP��ַ..."<<endl;
		cout<<DeviceName<<endl;
		//RenewSpecifiedDevice(DeviceName);
		system("ipconfig -release > nul");
		system("ipconfig -release6 > nul");
		cout<<"������ɡ�"<<endl;
		NeedPause=false;
	}
	else
	{

		if(argc == 1) //û�в���ʱ
		{
			GetDeviceList(true);
			NeedPause=true;
		}
		else
		{
			if(argc == 5 && arguments[1] == "/connect")		//�����û��������롢PcapIDʱ
			{
				isLogin=true;
				GetDeviceList(isLogin,arguments[2].c_str(),arguments[3].c_str(),arguments[4].c_str());//��֤
			}
			else
			{
				if (argc==4 && arguments[1] == "/connect")	//�������û���������
				{
					isLogin=true;
					string dname;
					dname= GetDeviceList(false);			//����豸PcapID
					GetDeviceList(isLogin,arguments[2].c_str(),arguments[3].c_str(),dname.c_str());//��֤
					NeedPause=true;
				}
				else
				{
					if(argc == 2 && arguments[1] == "/help")//���������Ϣ
					{
						cout<<"     ������ʹ�÷�����\n\nEAP_H3C_AUTH [ /connect | /disconnect] [Username] [Password] [PCAPID] \n     1.ֱ������\n\n     2.������\n          EAP_H3C_Auth /connect �û��� ����       ���ڸ����û���������ĵ�¼\n          EAP_H3C_Auth /connect �û��� ���� PcapID        ������֪PcapID�û����ߡ�PcapID Ϊ�����ַ�������cimv2���ݿ��л�ȡ���豸ID��\n              PCAP�ִ���rpcap://\\DEVICE\\NPF_\n          EAP_H3C_Auth /disconnect PCAPID �����û����ߡ�\n          EAP_H3C_Auth /disconnect        ����δ֪�豸PcapID���û����ߡ�\n     3.ʹ��GUI������е��á�"<<endl;
					}
					else
					{
						if(argc == 2 && arguments[1] == "/disconnect")//����PcapID������
						{
							isLogin=false;					//����¼
							string dname;
							dname= GetDeviceList(isLogin);	//����豸PcapID
							cout<<"�����У����Ժ�"<<endl;
							SendLogoffPkt(dname.c_str());	//����
							Sleep(1000);					//����δ�������ǰˢ��IP���´���
							//Stop Monitor Service.
							cout<<"����ˢ��IP��ַ..."<<endl;
							//RenewSpecifiedDevice(DeviceName);
							system("ipconfig -release > nul");
							system("ipconfig -release6 > nul");
							cout<<"������ɡ�"<<endl;
							NeedPause=true;
						}
						else								//�����д���
						{
							cout<<"����Ĳ����б�"<<endl<<"������ʹ��/helpָ��鿴��";
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
	const int DefaultTimeout=1000;//���ý��ճ�ʱ��������λms

	// NOTE: ����û�м�������Ƿ��Ѳ��,���߲�ڿ��ܽӴ�����

	/* ��������(����) */
	adhandle = pcap_open_live(DeviceName,65536,1,DefaultTimeout,errbuf);
	if (adhandle==NULL) {
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

		/* ����������֤�Ự */
		SendStartPkt(adhandle, MAC);
		DPRINTF("[ ] Client: Start.\n");

		/* �ȴ���֤�������Ļ�Ӧ */
		bool serverIsFound = false;
		while (!serverIsFound)
		{
			retcode = pcap_next_ex(adhandle, &header, &captured);
			if (retcode==1 && (EAP_Code)captured[18]==REQUEST)
				serverIsFound = true;
			else
			{    // ��ʱ������
				sleep(1); DPRINTF(".");
				SendStartPkt(adhandle, MAC);
				// NOTE: ����û�м�������Ƿ�Ӵ��������ѱ�����
			}
		}

		// ��дӦ����ı�ͷ(�Ժ��������޸�)
		// Ĭ���Ե�����ʽӦ��802.1X��֤�豸������Request
		memcpy(ethhdr+0, captured+6, 6);
		memcpy(ethhdr+6, MAC, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e;

		// �յ��ĵ�һ����������Request Notification��ȡ����У����������
		if ((EAP_Type)captured[22] == NOTIFICATION)
		{
			DPRINTF("[%d] Server: Request Notification!\n", captured[19]);
			// ����Response Notification
			SendResponseNotification(adhandle, captured, ethhdr);
			DPRINTF("    Client: Response Notification.\n");

			// ����������һ��Request��
			retcode = pcap_next_ex(adhandle, &header, &captured);
			assert(retcode==1);
			assert((EAP_Code)captured[18] == REQUEST);
		}

		// �����Ӧ����һ����
		if ((EAP_Type)captured[22] == IDENTITY)
		{    // ͨ��������յ���Request Identity��Ӧ�ش�Response Identity
			DPRINTF("[%d] Server: Request Identity!\n", captured[19]);
			GetIpFromDevice(ip, DeviceName);
			SendResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
			DPRINTF("[%d] Client: Response Identity.\n", (EAP_ID)captured[19]);
		}
		else if ((EAP_Type)captured[22] == AVAILABLE)
		{    // ����AVAILABLE��ʱ��Ҫ���⴦��
			// ���ϲƾ�������ѧĿǰʹ�õĸ�ʽ��
			// �յ���һ��Request AVAILABLEʱҪ�ش�Response Identity
			DPRINTF("[%d] Server: Request AVAILABLE!\n", captured[19]);
			GetIpFromDevice(ip, DeviceName);
			SendResponseIdentity(adhandle, captured, ethhdr, ip, UserName);
			DPRINTF("[%d] Client: Response Identity.\n", (EAP_ID)captured[19]);
		}
		else if ((EAP_Type)captured[22] == ALLOCATED)
		{
			//ALLOCATED
		}
		// �����������ֻ����Ϊ802.1X��֤�豸�����İ��������ಥRequest Identity / Request AVAILABLE��
		sprintf(FilterStr, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			captured[6],captured[7],captured[8],captured[9],captured[10],captured[11]);
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
			{    // ������֤ʧ����Ϣ
				NeedPause=1; 
				uint8_t errtype = captured[22];
				uint8_t msgsize = captured[23];
				const char *msg = (const char*) &captured[24];
				DPRINTF("[%d] Server: Failure.\n", (EAP_ID)captured[19]);
				if (errtype==0x09 && msgsize>0)
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
				else if (errtype==0x08) // ��������������ʱ�����������˴�802.1X��֤�Ự
				{    // ��������ͻ������̷����µ���֤�Ự
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
				cout<<"����ˢ��IP��ַ,���Ժ�...(��ˢ��ʱ��ϳ���ֱ���˳�)"<<endl;
				// ˢ��IP��ַ
				//RenewSpecifiedDevice(DeviceName); not suopported
				system("ipconfig /release > nul");
				system("ipconfig /release6 > nul");
				system("ipconfig /renew >nul");
				system("ipconfig /renew6 >nul");
				cout<<"��֤������ɣ�"<<endl;
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
				// TODO: ����û�д���Ϊ�Զ������ݰ� 
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
		/*����������ص���ERROR_BUFFER_OVERFLOW
		��˵��GetAdaptersInfo�������ݵ��ڴ�ռ䲻��,ͬʱ�䴫��stSize,��ʾ��Ҫ�Ŀռ��С
		��Ҳ��˵��ΪʲôstSize����һ��������Ҳ��һ�������*/
		//�ͷ�ԭ�����ڴ�ռ�
		delete pIpAdapterInfo;
		//���������ڴ�ռ������洢����������Ϣ
		pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
		//�ٴε���GetAdaptersInfo����,���pIpAdapterInfoָ�����
		nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);    
	}
	if (ERROR_SUCCESS == nRel)
	{
		//���������Ϣ
		//�����ж�����,���ͨ��ѭ��ȥ�ж�
		while (pIpAdapterInfo)
		{
			if (pIpAdapterInfo->Type == MIB_IF_TYPE_ETHERNET)
			{
				char *buf = new char[strlen(devicename)+1];
				strcpy(buf,devicename);
				if (matchName(pIpAdapterInfo->AdapterName,buf))
				{
					//ת��MAC���ݵ�mac����
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

	pInfo = (IP_INTERFACE_INFO *) MALLOC(sizeof(IP_INTERFACE_INFO));//����һ��IPInterfaceInfo
	nRel = GetInterfaceInfo(pInfo,&ulOutBufLen);
	//���ռ䲻������������ռ�
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


//�ж������ַ����Ƿ���ͬ
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

	// Ϊ�˼��ݲ�ͬԺУ���������ã����﷢������Start��
	// 1���㲥����Strat��
	//pcap_sendpacket(handle, packet, sizeof(packet));
	// 2���ಥ����Strat��
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
	//response[16~17]����    // Length

	// Extensible Authentication Protocol
	// {
	response[18] = (EAP_Code) RESPONSE;    // Code
	response[19] = request[19];        // ID
	//response[20~21]����            // Length
	response[22] = (EAP_Type) AVAILABLE;    // Type
	// Type-Data
	// {
	i = 23;
	response[i++] = 0x00;// �ϱ��Ƿ�ʹ�ô���
	response[i++] = 0x15;      // �ϴ�IP��ַ
	response[i++] = 0x04;      //
	memcpy(response+i, ip, 4);//
	i += 4;              //
	response[i++] = 0x06;          //	Я���汾��
	response[i++] = 0x07;          //
	FillBase64Area((char*)response+i);//
	i += 28;              //
	response[i++] = ' '; // �����ո��
	response[i++] = ' '; //
	usernamelen = strlen(username);
	memcpy(response+i, username, usernamelen);//
	i += usernamelen;              //
	// }
	// }
	// }

	// ����ǰ�����յ�����Length
	eaplen = htons(i-18);
	memcpy(response+16, &eaplen, sizeof(eaplen));
	memcpy(response+20, &eaplen, sizeof(eaplen));

	// ����
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
		||(EAP_Type)request[22] == AVAILABLE); // �������ϲƾ�������ѧ���

	// Fill Ethernet header
	memcpy(response, ethhdr, 14);

	// 802,1X Authentication
	// {
	response[14] = 0x1;    // 802.1X Version 1
	response[15] = 0x0;    // Type=0 (EAP Packet)
	//response[16~17]����    // Length

	// Extensible Authentication Protocol
	// {
	response[18] = (EAP_Code) RESPONSE;    // Code
	response[19] = request[19];        // ID
	//response[20~21]����            // Length
	response[22] = (EAP_Type) IDENTITY;    // Type
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
	FillBase64Area((char*)response+i);//
	i += 28;              //
	response[i++] = ' '; // �����ո��
	response[i++] = ' '; //
	usernamelen = strlen(username); //ĩβ����û���
	memcpy(response+i, username, usernamelen);
	i += usernamelen;
	assert(i <= sizeof(response));
	// }
	// }
	// }

	// ����ǰ�����յ�����Length
	//��Ҫ���˴���0x25���Թ���������ݰ��е����볤��bug
	eaplen = htons(usernamelen + 0x25);
	memcpy(response+16, &eaplen, sizeof(eaplen));
	memcpy(response+20, &eaplen, sizeof(eaplen));

	// ����
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
	const int DefaultTimeout=1000;//���ý��ճ�ʱ��������λms

	// NOTE: ����û�м�������Ƿ��Ѳ��,���߲�ڿ��ܽӴ�����

	/* ��������(����) */
	handle = pcap_open_live(DeviceName,65536,1,DefaultTimeout,errbuf);
	if (handle==NULL) {
		fprintf(stderr, "%s\n", errbuf); 
		EXIT(-1);
	}

	/* ��ѯ����MAC��ַ */
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
	// ����
	pcap_sendpacket(handle, packet, sizeof(packet));
}


// ����: XOR(data[], datalen, key[], keylen)
//
// ʹ����Կkey[]������data[]����������
//��ע���ú���Ҳ�ɷ������ڽ��ܣ�
// ����㷨��1011 XOR 233 = 794,794 XOR 233 = 1011
static void XOR(uint8_t data[], unsigned dlen, const char key[], unsigned klen)
{
	unsigned int    i,j;

	// �Ȱ�������һ��
	for (i=0; i<dlen; i++)
		data[i] ^= key[i%klen];
	// �ٰ�������ڶ���
	for (i=dlen-1,j=0;  j<dlen;  i--,j++)
		data[i] ^= key[j%klen];
}

static void FillClientVersionArea(uint8_t area[20])
{
	uint32_t random;
	char     RandomKey[8+1];

	random = (uint32_t) time(NULL);    // ע������ѡ����32λ����
	sprintf(RandomKey, "%08x", random);// ����RandomKey[]�ַ���

	// ��һ��������㣬��RandomKeyΪ��Կ����16�ֽ�
	memcpy(area, H3C_VERSION, sizeof(H3C_VERSION));
	XOR(area, 16, RandomKey, strlen(RandomKey));

	// ��16�ֽڼ���4�ֽڵ�random������ܼ�20�ֽ�
	random = htonl(random); // �������Ϊ�����ֽ��� big-endian
	memcpy(area+16, &random, 4);

	// �ڶ���������㣬��H3C_KEYΪ��Կ����ǰ�����ɵ�20�ֽ�
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
	// ����ǰ2+20�ֽ�Ϊ�ͻ��˰汾
	response[i++] = 0x01; // type 0x01
	response[i++] = 22;   // lenth
	FillClientVersionArea(response+i);
	i += 20;

	// ���2+20�ֽڴ洢���ܺ��Windows����ϵͳ�汾��
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
		"0123456789+/"; // ��׼��Base64�ַ�ӳ���
	uint8_t    c1,c2,c3;
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
/*����MD5���ݲ�����
void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[])
{
uint8_t    msgbuf[128]; // msgbuf = ��id�� + ��passwd�� + ��srcMD5��
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
	/* ��ȡ���ػ����豸�б� */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}
	counter=0;
	/* ��ӡ�б� */
	//���������б����
	cout.setf(ios::left);
	cout<<"��ѡ����Ҫʹ�õ�������"<<endl;
	cout<<setw(5)<<"��� "<<setw(70)<<"��������"<<"��������"<<endl;
	for(d=alldevs; d != NULL; d= d->next)
	{
		//�����ʽ��
		cout<<setw(5)<<++i;
		cout<<setw(69)<<d->name;
		dNameList[counter]=d->name;
		counter++;
		if (d->description)printf(" (%s)\n", d->description);
		else printf(" (No description available)\n");
	}
	if (i == 0)//�Ҳ�������ʱ����
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return "";
	}
	/* ������Ҫ�豸�б��ˣ��ͷ��� */
	pcap_freealldevs(alldevs);

	//�û�ѡ��ʹ�õ�����
	int selection = 0;
	const char *DeviceName;
	cout<<"��ѡ����ţ�";
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
	if(GoAuth)PrepareAuth(DeviceName);//�����������֤��������֤
	string retstr(DeviceName); //���޵�����޷�����const char*,��string�滻��
	return retstr;
}

const char * GetDeviceList(bool GoAuth,const char *usr,const char *psw,const char *dname)
{
	//�����Ѹ����û��������뼰�豸PcapID��ʱ��ʹ��
	if (dname != "")cout<<Authentication(usr,psw,dname);
	return dname;
}


static void PrepareAuth(const char *DeviceName)
{
	//û�и����û��������룬��ȡ�û���������
	const char *au ,*bp,*dName;
	char a[32],b[128];
	cout<<"�������û���:";
	scanf("%s",a);
	cout<<"���������룺";
	scanf("%s",b);
	au=a;
	bp=b;
	if (DeviceName != "")cout<<Authentication(a,b,DeviceName);
}

static void SendResponseH3C(pcap_t *handle,const uint8_t request[],const uint8_t ethhdr[],const char username[],const char passwd[])
{
	if (username == NULL || passwd == NULL){cout<<"Username or password does not exist.quit."<<endl;EXIT(0);}//�ж��û��������벻Ϊ��
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
