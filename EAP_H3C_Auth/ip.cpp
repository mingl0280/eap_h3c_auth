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
    //释放内存空间
    if (pIpAdapterInfo)
    {
        delete pIpAdapterInfo;
    }
    return;
}


