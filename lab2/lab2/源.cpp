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

#pragma pack(1)//�ֽڶ��뷽ʽ

typedef struct FrameHeader_t {		//֡�ײ�
	BYTE DesMAC[6];//Ŀ�ĵ�ַ
	BYTE SrcMAC[6];//Դ��ַ
	WORD FrameType;//֡����
}FrameHeader_t;

typedef struct IPHeader_t {		//IP�ײ�
	BYTE Ver_HLen;//IPЭ��汾��IP�ײ����ȣ���4λΪ�汾����4λΪ�ײ��ĳ���
	BYTE TOS;//��������
	WORD TotalLen;//�ܳ���
	WORD ID;//��ʶ
	WORD Flag_Segment;//��־ Ƭƫ��
	BYTE TTL;//��������
	BYTE Protocol;//Э��
	WORD Checksum;//ͷ��У���
	u_int SrcIP;//ԴIP
	u_int DstIP;//Ŀ��IP
}IPHeader_t;

typedef struct Data_t {		//���ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

#pragma pack()//�ָ�ȱʡ���뷽ʽ

void PacketHandle(u_char*, const struct pcap_pkthdr*, const u_char*);
void IP_Packet_Handle(const struct pcap_pkthdr*, const u_char*);

int main()
{
	pcap_if_t* alldevs;//ָ���豸�����ײ���ָ��
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	int num = 0;//�ӿ�����
	int n;
	int read_count;
	//��ñ������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
		NULL,			       //������֤
		&alldevs, 		       //ָ���豸�б��ײ�
		errbuf			      //������Ϣ���滺����
	) == -1)
	{
		//������
		cout << "��ȡ�����豸����" << errbuf << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}
	//��ʾ�ӿ��б�
	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		cout << dec << num << ":" << d->name << endl;//����d->name��ȡ������ӿ��豸������
		if (d->description != NULL)//����d->description��ȡ������ӿ��豸��������Ϣ
		{
			cout << d->description << endl;
		}
		else
		{
			cout << "��������Ϣ" << endl;
		}
	}
	if (num == 0)
	{
		cout << "�޿��ýӿ�" << endl;
		return 0;
	}
	cout << "������Ҫ�򿪵�����ӿں�" << "��1~" << num << "����" << endl;
	cin >> n;
	num = 0;
	for (d = alldevs; num < (n - 1); num++)
	{
		d = d->next;
	}//��ת��ѡ�е�����ӿں�
	pcap_t* adhandle;
	adhandle = pcap_open(d->name,		//�豸��
		65536,		//Ҫ��������ݰ��Ĳ���
		PCAP_OPENFLAG_PROMISCUOUS,		//����ģʽ
		1000,			//��ʱʱ��
		NULL,		//Զ�̻�����֤
		errbuf		//���󻺳��
	);
	if (adhandle == NULL)
	{
		cout << "���������޷����豸" << endl;
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		cout << "������" << d->description << endl;
		pcap_freealldevs(alldevs);

	}
	cout << "��������Ҫ��������ݰ��ĸ�����" << endl;
	cin >> read_count;
	pcap_loop(adhandle, read_count, (pcap_handler)PacketHandle, NULL);
	pcap_close(adhandle);
	return 0;
}

void PacketHandle(u_char* argunment, const struct pcap_pkthdr* pkt_head, const u_char* pkt_data)
{
	FrameHeader_t* ethernet_protocol;		//��̫��Э��
	u_short ethernet_type;		//��̫������
	u_char* mac_string;			//��̫����ַ
	//��ȡ��̫����������
	ethernet_protocol = (FrameHeader_t*)pkt_data;
	ethernet_type = ntohs(ethernet_protocol->FrameType);
	printf("��̫������Ϊ :\t");
	printf("%04x\n", ethernet_type);
	switch (ethernet_type)
	{
	case 0x0800:
		printf("������ǣ�IPv4Э��\n");
		break;
	case 0x0806:
		printf("������ǣ�ARPЭ��\n");
		break;
	case 0x8035:
		printf("������ǣ�RARPЭ��\n");
		break;
	default:
		printf("�����Э��δ֪\n");
		break;
	}
	mac_string = ethernet_protocol->SrcMAC;
	printf("MacԴ��ַ��\n");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:\n",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5)
	);
	mac_string = ethernet_protocol->DesMAC;
	printf("MacĿ�ĵ�ַ��\n");
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
	IPHeader = (IPHeader_t*)(pkt_data + 14);//IP����������ԭ������֡��14�ֽڿ�ʼ
	sockaddr_in source, dest;
	char sourceIP[16], destIP[16];
	source.sin_addr.s_addr = IPHeader->SrcIP;
	dest.sin_addr.s_addr = IPHeader->DstIP;
	strncpy(sourceIP, inet_ntoa(source.sin_addr), 16);
	strncpy(destIP, inet_ntoa(dest.sin_addr), 16);
	printf("�汾��%d\n", IPHeader->Ver_HLen >> 4);
	printf("IPЭ���ײ����ȣ�%d Bytes\n", (IPHeader->Ver_HLen & 0x0f) * 4);
	printf("�������ͣ�%d\n", IPHeader->TOS);
	printf("�ܳ��ȣ�%d\n", ntohs(IPHeader->TotalLen));
	printf("��ʶ��0x%.4x (%i)\n", ntohs(IPHeader->ID));
	printf("��־��%d\n", ntohs(IPHeader->Flag_Segment));
	printf("Ƭƫ�ƣ�%d\n", (IPHeader->Flag_Segment) & 0x8000 >> 15);
	printf("����ʱ�䣺%d\n", IPHeader->TTL);
	printf("Э��ţ�%d\n", IPHeader->Protocol);
	printf("Э�����ࣺ");
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
	printf("�ײ�����ͣ�0x%.4x\n", ntohs(IPHeader->Checksum));
	printf("Դ��ַ��%s\n", sourceIP);
	printf("Ŀ�ĵ�ַ��%s\n", destIP);
	cout << "--------------------------------------------------------------------------------" << endl;
}