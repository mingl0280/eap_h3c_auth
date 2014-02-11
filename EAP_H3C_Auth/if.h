#ifndef IF_H
#define IF_H

#define IFNAMSIZ 16
#define PF_PACKET 0x0011
#define SIOCGIFHWADDR 0x8927

struct ifmap
{
    unsigned long mem_start;
    unsigned long mem_end;
    unsigned short base_addr;
    unsigned char irq;
    unsigned char dma;
    unsigned char port;
    /* 3 bytes spare */
};
/*
struct if_settings {
    unsigned int type; // Type of physical device or protocol 
    unsigned int size; // Size of the data allocated by the caller 
    union {
        // {atm/eth/dsl}_settings anyone ? 
        raw_hdlc_proto__user *raw_hdlc;
        cisco_proto   __user *cisco;
        fr_proto __user *fr;
        fr_proto_pvc  __user *fr_pvc;
        fr_proto_pvc_info  __user *fr_pvc_info;

        // interface settings 
        sync_serial_settings    __user *sync;
        te1_settings  __user *te1;
    } ifs_ifsu;
};*/
struct ifreq
{
#define IFHWADDRLEN 6
    union
    {
        char ifrn_name[IFNAMSIZ];  
    } ifr_ifrn;

    union {
        struct sockaddr ifru_addr;
        struct sockaddr ifru_dstaddr;
        struct sockaddr ifru_broadaddr;
        struct sockaddr ifru_netmask;
        struct  sockaddr ifru_hwaddr;
        short ifru_flags;
        int ifru_ivalue;
        int ifru_mtu;
        struct  ifmap ifru_map;
        char ifru_slave[IFNAMSIZ]; 
        char ifru_newname[IFNAMSIZ];
        //void __user * ifru_data;
        //struct if_settings ifru_settings;
    } ifr_ifru;
};

#define ifr_name ifr_ifrn.ifrn_name 
#define ifr_hwaddr ifr_ifru.ifru_hwaddr 
#define ifr_addr ifr_ifru.ifru_addr 
#define ifr_dstaddr ifr_ifru.ifru_dstaddr 
#define ifr_broadaddr ifr_ifru.ifru_broadaddr 
#define ifr_netmask ifr_ifru.ifru_netmask 
#define ifr_flags ifr_ifru.ifru_flags 
#define ifr_metric ifr_ifru.ifru_ivalue 
#define ifr_mtu  ifr_ifru.ifru_mtu 
#define ifr_map  ifr_ifru.ifru_map 
#define ifr_slave ifr_ifru.ifru_slave 
//#define ifr_data ifr_ifru.ifru_data 
#define ifr_ifindex ifr_ifru.ifru_ivalue 
#define ifr_bandwidth ifr_ifru.ifru_ivalue    
#define ifr_qlen ifr_ifru.ifru_ivalue 
#define ifr_newname ifr_ifru.ifru_newname 
//#define ifr_settings ifr_ifru.ifru_settings 

#endif
