#include <Winsock2.h>
#include<iostream>
#include "pcap.h"
#include "stdio.h"
#include<time.h>
#include <string>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)

using namespace std;

#pragma pack(1)//字节对齐方式

typedef struct FrameHeader_t {		//帧首部
	BYTE DesMAC[6];//目的地址
	BYTE SrcMAC[6];//源地址
	WORD FrameType;//帧类型
}FrameHeader_t;

typedef struct IPHeader_t {		//IP首部
	BYTE Ver_HLen;//IP协议版本和IP首部长度：高4位为版本，低4位为首部的长度
	BYTE TOS;//服务类型
	WORD TotalLen;//总长度
	WORD ID;//标识
	WORD Flag_Segment;//标志 片偏移
	BYTE TTL;//生存周期
	BYTE Protocol;//协议
	WORD Checksum;//头部校验和
	u_int SrcIP;//源IP
	u_int DstIP;//目的IP
}IPHeader_t;

typedef struct Data_t {		//数据包
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

#pragma pack()//恢复缺省对齐方式

void PacketHandle(u_char*, const struct pcap_pkthdr*, const u_char*);
void IP_Packet_Handle(const struct pcap_pkthdr*, const u_char*);

int main()
{
	pcap_if_t* alldevs;//指向设备链表首部的指针
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	int num = 0;//接口数量
	int n;
	int read_count;
	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1)
	{
		//错误处理
		cout << "获取本机设备错误" << errbuf << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}
	//显示接口列表
	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		cout << dec << num << ":" << d->name << endl;//利用d->name获取该网络接口设备的名字
		if (d->description != NULL)//利用d->description获取该网络接口设备的描述信息
		{
			cout << d->description << endl;
		}
		else
		{
			cout << "无描述信息" << endl;
		}
	}
	if (num == 0)
	{
		cout << "无可用接口" << endl;
		return 0;
	}
	cout << "请输入要打开的网络接口号" << "（1~" << num << "）：" << endl;
	cin >> n;
	num = 0;
	for (d = alldevs; num < (n - 1); num++)
	{
		d = d->next;
	}//跳转到选中的网络接口号
	pcap_t* adhandle;
	adhandle = pcap_open(d->name,		//设备名
		65536,		//要捕获的数据包的部分
		PCAP_OPENFLAG_PROMISCUOUS,		//混杂模式
		1000,			//超时时间
		NULL,		//远程机器验证
		errbuf		//错误缓冲池
	);
	if (adhandle == NULL)
	{
		cout << "产生错误，无法打开设备" << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		cout << "监听：" << d->description << endl;
		pcap_freealldevs(alldevs);

	}
	cout << "请输入你要捕获的数据包的个数：" << endl;
	cin >> read_count;
	pcap_loop(adhandle, read_count, (pcap_handler)PacketHandle, NULL);
	pcap_close(adhandle);
	return 0;
}

void PacketHandle(u_char* argunment, const struct pcap_pkthdr* pkt_head, const u_char* pkt_data)
{
	FrameHeader_t* ethernet_protocol;		//以太网协议
	u_short ethernet_type;		//以太网类型
	u_char* mac_string;			//以太网地址
	//获取以太网数据内容
	ethernet_protocol = (FrameHeader_t*)pkt_data;
	ethernet_type = ntohs(ethernet_protocol->FrameType);
	printf("以太网类型为 :\t");
	printf("%04x\n", ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800:
		printf("网络层是：IPv4协议\n");
		break;
	case 0x0806:
		printf("网络层是：ARP协议\n");
		break;
	case 0x8035:
		printf("网络层是：RARP协议\n");
		break;
	default:
		printf("网络层协议未知\n");
		break;
	}
	mac_string = ethernet_protocol->SrcMAC;
	printf("Mac源地址：\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5)
	);
	mac_string = ethernet_protocol->DesMAC;
	printf("Mac目的地址：\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5)
	);
	if (ethernet_type == 0x0800)
	{
		IP_Packet_Handle(pkt_head, pkt_data);
	}
}

void IP_Packet_Handle(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	IPHeader_t* IPHeader;
	IPHeader = (IPHeader_t*)(pkt_data + 14);//IP包的内容在原有物理帧后14字节开始
	sockaddr_in source, dest;
	char sourceIP[16], destIP[16];
	source.sin_addr.s_addr = IPHeader->SrcIP;
	dest.sin_addr.s_addr = IPHeader->DstIP;
	strncpy(sourceIP, inet_ntoa(source.sin_addr), 16);
	strncpy(destIP, inet_ntoa(dest.sin_addr), 16);
	printf("版本：%d\n", IPHeader->Ver_HLen >> 4);
	printf("IP协议首部长度：%d Bytes\n", (IPHeader->Ver_HLen & 0x0f) * 4);
	printf("服务类型：%d\n", IPHeader->TOS);
	printf("总长度：%d\n", ntohs(IPHeader->TotalLen));
	printf("标识：0x%.4x (%i)\n", ntohs(IPHeader->ID));
	printf("标志：%d\n", ntohs(IPHeader->Flag_Segment));
	printf("片偏移：%d\n", (IPHeader->Flag_Segment) & 0x8000 >> 15);
	printf("生存时间：%d\n", IPHeader->TTL);
	printf("协议号：%d\n", IPHeader->Protocol);
	printf("协议种类：");
	switch (IPHeader->Protocol)
	{
	case 1:
		printf("ICMP\n");
		break;
	case 2:
		printf("IGMP\n");
		break;
	case 6:
		printf("TCP\n");
		break;
	case 17:
		printf("UDP\n");
		break;
	default:
		break;
	}
	printf("首部检验和：0x%.4x\n", ntohs(IPHeader->Checksum));
	printf("源地址：%s\n", sourceIP);
	printf("目的地址：%s\n", destIP);
	cout << "--------------------------------------------------------------------------------" << endl;
}