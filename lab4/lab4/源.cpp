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

typedef struct ARPFrame_t {//IP�ײ�
	FrameHeader_t FrameHeader;
	WORD HardwareType;//Ӳ������
	WORD ProtocolType;//Э������
	BYTE HLen;//Ӳ����ַ����
	BYTE PLen;//Э���ַ����
	WORD Operation;//��������
	BYTE SendHa[6];//���ͷ�MAC��ַ
	DWORD SendIP;//���ͷ�IP��ַ
	BYTE RecvHa[6];//���շ�MAC��ַ
	DWORD RecvIP;//���շ�IP��ַ
}ARPFrame_t;
# pragma pack()

// ARP��ʼ֡������
ARPFrame_t ARPFrame;

int main()
{
	pcap_if_t* alldevs;//ָ���豸�����ײ���ָ��
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	int num = 0;//�ӿ�����
	int n;
	char* ip = new char[20];
	char* ip1 = new char[20];
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
		//��ȡ������ӿ��豸��ip��ַ��Ϣ
		pcap_addr_t* a; // �����������ĵ�ַ
		for (a = d->addresses; a != NULL; a = a->next)
		{
			switch (a->addr->sa_family)//sa_family�����˵�ַ������
			{
			case AF_INET://IPV4
				printf("Address Family Name:AF_INET\t");
				if (a->addr != NULL)
				{
					//strcpy(ip, inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					printf("%s\t%s\n", "IP_Address:", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
				}
				break;
			case AF_INET6://IPV6
				cout << "Address Family Name:AF_INET6" << endl;
				break;
			default:
				break;
			}
		}
		cout << "----------------------------------------------------------------------------------------------------------" << endl;
	}
	if (num == 0)
	{
		cout << "�޿��ýӿ�" << endl;
		return 0;
	}
	cout << "������Ҫ�򿪵�����ӿں�" << "��1~" << num << "����" << endl;
	num = 0;
	cin >> n;
	// ��ת��ѡ�е�����ӿں�
	for (d = alldevs; num < (n - 1); num++)
	{
		d = d->next;
	}
	strcpy(ip, inet_ntoa(((struct sockaddr_in*)(d->addresses)->addr)->sin_addr));
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
	//����ARP֡������
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = 0x66;
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);// ֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	//��ARPFrame.SendHa����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.SendHa[i] = 0x66;
	}
	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr("112.112.112.112");
	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0x00;//��ʾĿ�ĵ�ַδ֪
	}
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = inet_addr(ip);
	//����������ARPFrame�е����ݣ����ĳ���Ϊsizeof(ARPFrame_t)��������ͳɹ�������0
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "����ʧ�ܣ��˳�����" << endl;
		return -1;
	}
	// �������������ARP֡
	ARPFrame_t* IPPacket;
	// ��ʼ���в���
	while (1)//���ܻ��ж�����Ϣ
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
		if (rtn == 1)
		{
			IPPacket = (ARPFrame_t*)pkt_data;
			if ((ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket->Operation) == 0x0002))//���֡����ΪARP���Ҳ���ΪARPӦ��
			{
				printf("Mac��ַ��\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					IPPacket->FrameHeader.SrcMAC[0],
					IPPacket->FrameHeader.SrcMAC[1],
					IPPacket->FrameHeader.SrcMAC[2],
					IPPacket->FrameHeader.SrcMAC[3],
					IPPacket->FrameHeader.SrcMAC[4],
					IPPacket->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
	}
	cout << "������IP��" << endl;
	cin >> ip1;
	ARPFrame.RecvIP = inet_addr(ip1);
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		cout << "����ʧ�ܣ��˳�����" << endl;
		return -1;
	}
	else
	{
		cout << "���ͳɹ�" << endl;
	}
	ARPFrame_t* IPPacket1;
	while (1)//���ܻ��ж�����Ϣ
	{
		pcap_pkthdr* pkt_header1;
		const u_char* pkt_data1;
		int rtnNew = pcap_next_ex(adhandle, &pkt_header1, &pkt_data1);
		if (rtnNew == 1)
		{
			IPPacket1 = (ARPFrame_t*)pkt_data1;
			if ((ntohs(IPPacket1->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket1->Operation) == 0x0002))//���֡����ΪARP���Ҳ���ΪARPӦ��
			{
				printf("Mac��ַ��\n");
				printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
					IPPacket1->FrameHeader.SrcMAC[0],
					IPPacket1->FrameHeader.SrcMAC[1],
					IPPacket1->FrameHeader.SrcMAC[2],
					IPPacket1->FrameHeader.SrcMAC[3],
					IPPacket1->FrameHeader.SrcMAC[4],
					IPPacket1->FrameHeader.SrcMAC[5]
				);
				break;
			}
		}
	}

	pcap_close(adhandle);
	return 0;
}