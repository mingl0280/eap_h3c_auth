#include "ip.h"

void GetIpFromDevice(uint8_t ip[4], const char DeviceName[])
{
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
                if (pIpAdapterInfo->AdapterName == DeviceName)
                {
                    IP_ADDR_STRING *pIpAddrString =&(pIpAdapterInfo->IpAddressList);
                    memcpy(ip,pIpAddrString->IpAddress.String,sizeof(ip)/sizeof(uint8_t));
                    break;
                }
            }
            pIpAdapterInfo = pIpAdapterInfo->Next;
        }
    }
    //�ͷ��ڴ�ռ�
    if (pIpAdapterInfo)
    {
        delete pIpAdapterInfo;
    }
    return;
}


