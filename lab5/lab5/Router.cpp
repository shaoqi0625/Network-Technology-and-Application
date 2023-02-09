#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Winsock2.h>
//#include<iostream>
#include "pcap.h"
#include "stdio.h"
//#include<time.h>
#include <string.h>
#include "log.h"//��־

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)

//using namespace std;

char ip[10][20];
char mask[10][20];
BYTE selfmac[6];
pcap_t* adhandle;
//���߳�
HANDLE hThread;
DWORD dwThreadId;
int n;
int Routerlog::num = 0;
Routerlog Routerlog::diary[50] = {};
FILE* Routerlog::fp = nullptr;
Routerlog LT;
BYTE broadcast[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };
/*
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

typedef struct Data_t {		//���ݰ�
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
}Data_t;

typedef struct ICMP {//ICMP����
	FrameHeader_t FrameHeader;
	IPHeader_t IPHeader;
	char buf[0x80];
}ICMP_t;

#pragma pack()//�ָ�ȱʡ���뷽ʽ
*/
void GetOtherMac(DWORD ip0, BYTE mac[])
{
	memset(mac, 0, sizeof(mac));
	ARPFrame_t ARPFrame;
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = selfmac[i];
		ARPFrame.SendHa[i] = selfmac[i];
	}
	ARPFrame.FrameHeader.FrameType = htons(0x0806);//֡����ΪARP
	ARPFrame.HardwareType = htons(0x0001);//Ӳ������Ϊ��̫��
	ARPFrame.ProtocolType = htons(0x0800);//Э������ΪIP
	ARPFrame.HLen = 6;//Ӳ����ַ����Ϊ6
	ARPFrame.PLen = 4;//Э���ַ��Ϊ4
	ARPFrame.Operation = htons(0x0001);//����ΪARP����
	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr(ip[0]);
	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0;
	}
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = ip0;
	if (adhandle == nullptr)
	{
		printf("�����ӿڴ򿪴���\n");
	}
	else
	{
		if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		{
			//���ʹ�����
			printf("���ʹ���\n");
			return;
		}
		else
		{
			//���ͳɹ�
			while (1)
			{
				pcap_pkthdr* pkt_header;
				const u_char* pkt_data;
				int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
				//pcap_sendpacket(ahandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t));
				if (rtn == 1)
				{
					ARPFrame_t* IPPacket = (ARPFrame_t*)pkt_data;
					if (ntohs(IPPacket->FrameHeader.FrameType) == 0x0806)
					{//���Ŀ��MAC��ַ
						if (ntohs(IPPacket->Operation) == 0x0002)//���֡����ΪARP���Ҳ���ΪARPӦ��
						{
							LT.WritelogARP(IPPacket);
							//���ԴMAC��ַ
							for (int i = 0; i < 6; i++)
								mac[i] = IPPacket->FrameHeader.SrcMAC[i];
							break;
						}
					}
				}
			}
		}
	}
}

#pragma pack(1)
class RouterItem//·�ɱ����
{
public:
	DWORD mask;//����
	DWORD net;//Ŀ������
	DWORD nextip;//��һ��
	BYTE nextmac[6];
	int index;//�ڼ���
	int type;//0Ϊֱ�����ӣ�1Ϊ�û����
	RouterItem* nextitem;//����������ʽ�洢
	RouterItem()
	{
		memset(this, 0, sizeof(*this));//ȫ����ʼ��Ϊ0
	}
	void PrintItem()//��ӡ�������ݣ����롢Ŀ�����硢��һ��IP������
	{
		in_addr addr;
		printf("%d ", index);
		addr.s_addr = mask;
		char* temp = inet_ntoa(addr);
		printf("%s\t", temp);
		addr.s_addr = net;
		temp = inet_ntoa(addr);
		printf("%s\t", temp);
		addr.s_addr = nextip;
		temp = inet_ntoa(addr);
		printf("%s\t", temp);
		printf("%d\n", type);
	}
};
#pragma pack()

#pragma pack(1)
class RouterTable//·�ɱ�
{
public:
	RouterItem* head, * tail;
	int num;//����
	RouterTable()//��ʼ�������ֱ������������
	{
		head = new RouterItem;
		tail = new RouterItem;
		head->nextitem = tail;
		num = 0;
		for (int i = 0; i < 2; i++)
		{
			RouterItem* temp = new RouterItem;
			temp->net = (inet_addr(ip[i])) & (inet_addr(mask[i]));//����������ip��������а�λ�뼴Ϊ��������
			temp->mask = inet_addr(mask[i]);
			temp->type = 0;//0��ʾֱ�����ӣ�����ɾ��
			this->RouterAdd(temp);
		}
	}
	void RouterAdd(RouterItem* a)//·�ɱ�����
	{
		RouterItem* pointer;
		if (!a->type)
		{
			a->nextitem = head->nextitem;
			head->nextitem = a;
			a->type = 0;
		}
		else//���������ɳ������ҵ����ʵ�λ��
		{
			for (pointer = head->nextitem; pointer != tail && pointer->nextitem != tail; pointer = pointer->nextitem)
			{
				if (a->mask < pointer->mask && a->mask >= pointer->nextitem->mask || pointer->nextitem == tail)
				{
					break;
				}
			}
			a->nextitem = pointer->nextitem;
			pointer->nextitem = a;
		}
		RouterItem* p = head->nextitem;
		for (int i = 0; p != tail; p = p->nextitem, i++)
		{
			p->index = i;
		}
		num++;
	}
	void RouterRemove(int index)//·�ɱ��ɾ��
	{
		for (RouterItem* t = head; t->nextitem != tail; t = t->nextitem)
		{
			if (t->nextitem->index == index)
			{
				if (t->nextitem->type == 0)
				{
					printf("�����ɾ��\n");
					return;
				}
				else
				{
					t->nextitem = t->nextitem->nextitem;
					return;
				}
			}
		}
		printf("�޸ñ���\n");
	}
	void print()
	{
		for (RouterItem* p = head->nextitem; p != tail; p = p->nextitem)
		{
			p->PrintItem();
		}
	}
	DWORD RouterFind(DWORD ip)//�����ǰ׺��������һ����ip
	{
		for (RouterItem* t = head->nextitem; t != tail; t = t->nextitem)
		{
			if ((t->mask & ip) == t->net)
			{
				return t->nextip;
			}
		}
		return -1;
	}
};
#pragma pack()

#pragma pack(1)
class ArpTable//ARP����IP��MAC�Ķ�Ӧ��ϵ�洢��һ�ű��
{
public:
	DWORD ip;
	BYTE mac[6];
	static int num;
	static void InsertArp(DWORD ip, BYTE mac[6])
	{
		arptable[num].ip = ip;
		GetOtherMac(ip, arptable[num].mac);
		memcpy(mac, arptable[num].mac, 6);
		num++;
	}
	static int FindArp(DWORD ip, BYTE mac[6])
	{
		memset(mac, 0, 6);
		for (int i = 0; i < num; i++)
		{
			if (ip == arptable[i].ip)
			{
				memcpy(mac, arptable[i].mac, 6);
				return 1;
			}
		}
		return 0;
	}
}arptable[50];
#pragma pack()

int ArpTable::num = 0;

void SetCheckSum(Data_t* temp)
{
	temp->IPHeader.Checksum = 0;
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;//ÿ16λΪһ��
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//������������лؾ�
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	temp->IPHeader.Checksum = ~sum;//���ȡ��
}

bool CheckSum(Data_t* temp)
{
	unsigned int sum = 0;
	WORD* t = (WORD*)&temp->IPHeader;
	for (int i = 0; i < sizeof(IPHeader_t) / 2; i++)
	{
		sum += t[i];
		while (sum >= 0x10000)//������������лؾ�
		{
			int s = sum >> 16;
			sum -= 0x10000;
			sum += s;
		}
	}
	if (sum == 65535)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

bool Compare(BYTE a[6], BYTE b[6])
{
	for (int i = 0; i < 6; i++)
	{
		if (a[i] != b[i])
		{
			return 0;
		}
	}
	return 1;
}

void resend(ICMP_t data, BYTE desmac[])
{
	Data_t* temp = (Data_t*)&data;
	memcpy(temp->FrameHeader.SrcMAC, temp->FrameHeader.DesMAC, 6);//ԴMACΪ����MAC
	memcpy(temp->FrameHeader.DesMAC, desmac, 6);//Ŀ��MACΪ��һ��MAC
	temp->IPHeader.TTL -= 1;
	if (temp->IPHeader.TTL < 0)
	{
		return;
	}
	SetCheckSum(temp);//��������У���
	int rtn = pcap_sendpacket(adhandle, (const u_char*)temp, 74);//�������ݱ�
	if (rtn == 0)
	{
		LT.WritelogIP("ת��", temp);
	}
}

//�̺߳���
DWORD WINAPI Thread(LPVOID lparam)
{
	RouterTable RT = *(RouterTable*)(LPVOID)lparam;
	while (1)
	{
		pcap_pkthdr* pkt_header;
		const u_char* pkt_data;
		while (1)
		{
			int rtn = pcap_next_ex(adhandle, &pkt_header, &pkt_data);
			if (rtn)//���յ���Ϣ
			{
				break;
			}
		}
		FrameHeader_t* header = (FrameHeader_t*)pkt_data;
		if (Compare(header->DesMAC, selfmac))//Ŀ��mac���Լ���mac
		{
			if (ntohs(header->FrameType) == 0x0806)//�յ�ARP
			{
				//do nothing
			}
			else if (ntohs(header->FrameType) == 0x0800)//�յ�IP
			{
				Data_t* data = (Data_t*)pkt_data;
				LT.WritelogIP("����", data);
				DWORD dstip = data->IPHeader.DstIP;
				DWORD IFip = RT.RouterFind(dstip);//�����Ƿ��ж�Ӧ����
				if (IFip == -1)
				{
					continue;
				}
				if (CheckSum(data))//���У��Ͳ���ȷ����ֱ�Ӷ��������д���
				{
					if (data->IPHeader.DstIP != inet_addr(ip[0]) && data->IPHeader.DstIP != inet_addr(ip[1]))
					{
						int t1 = Compare(data->FrameHeader.DesMAC, broadcast);
						int t2 = Compare(data->FrameHeader.SrcMAC, broadcast);
						if (!t1 && !t2)
						{
							//ICMP���İ���IP���ݰ���ͷ����������
							ICMP_t* temp_ = (ICMP_t*)pkt_data;
							ICMP_t temp = *temp_;
							BYTE mac[6];
							if (IFip == 0)
							{
								//���ARP����û���������ݣ�����Ҫ��ȡARP
								if (!ArpTable::FindArp(dstip, mac))
								{
									ArpTable::InsertArp(dstip, mac);
								}
								resend(temp, mac);
							}

							else if (IFip != -1)//��ֱ��Ͷ�ݣ�������һ��IP��MAC
							{
								if (!ArpTable::FindArp(IFip, mac))
								{
									ArpTable::InsertArp(IFip, mac);
								}
								resend(temp, mac);
							}
						}
					}
				}
			}
		}
	}
}


int main()
{
	pcap_if_t* alldevs;//ָ���豸�����ײ���ָ��
	pcap_if_t* d;
	char errbuf[PCAP_ERRBUF_SIZE];	//������Ϣ������
	int num = 0;//�ӿ�����

	//��������ȡ˫IP

	//��ñ������豸�б�
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//��ȡ�����Ľӿ��豸
		NULL,			       //������֤
		&alldevs, 		       //ָ���豸�б��ײ�
		errbuf			      //������Ϣ���滺����
	) == -1)
	{
		//������
		printf("��ȡ�����豸����");
		printf("%d\n", errbuf);
		pcap_freealldevs(alldevs);
		return 0;
	}
	int t = 0;
	//��ʾ�ӿ��б�
	for (d = alldevs; d != NULL; d = d->next)
	{
		num++;
		printf("%d:", num);
		printf("%s\n", d->name);
		if (d->description != NULL)//����d->description��ȡ������ӿ��豸��������Ϣ
		{
			printf("%s\n", d->description);
		}
		else
		{
			printf("��������Ϣ\n");
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
					printf("%s\t%s\n", "MASK_Address:", inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
					strcpy(ip[t], inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
					strcpy(mask[t], inet_ntoa(((struct sockaddr_in*)a->netmask)->sin_addr));
					//t++;
				}
				break;
			case AF_INET6://IPV6
				printf("Address Family Name:AF_INET6\n");
				break;
			default:
				break;
			}
			t++;
		}
		printf("----------------------------------------------------------------------------------------------------------\n");
	}
	if (num == 0)
	{
		printf("�޿��ýӿ�\n");
		return 0;
	}
	printf("������Ҫ�򿪵�����ӿں�");
	printf("��1~");
	printf("%d", num);
	printf("����\n");
	num = 0;
	scanf("%d", &n);
	// ��ת��ѡ�е�����ӿں�
	for (d = alldevs; num < (n - 1); num++)
	{
		d = d->next;
	}
	//strcpy(ip0, inet_ntoa(((struct sockaddr_in*)(d->addresses)->addr)->sin_addr));
	adhandle = pcap_open(d->name,		//�豸��
		65536,		//Ҫ��������ݰ��Ĳ���
		PCAP_OPENFLAG_PROMISCUOUS,		//����ģʽ
		1000,			//��ʱʱ��
		NULL,		//Զ�̻�����֤
		errbuf		//���󻺳��
	);
	if (adhandle == NULL)
	{
		printf("���������޷����豸\n");
		pcap_freealldevs(alldevs);
		return 0;
	}
	else
	{
		printf("������%s\n", d->description);
		pcap_freealldevs(alldevs);
	}

	for (int i = 0; i < 2; i++)
	{
		printf("%s\t", ip[i]);
		printf("%s\n", mask[i]);
	}


	//α��ARP���Ļ�ȡ����MAC
	memset(selfmac, 0, sizeof(selfmac));
	//����ARP֡������
	ARPFrame_t ARPFrame;//ARP��ʼ֡������
	//��APRFrame.FrameHeader.DesMAC����Ϊ�㲥��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;
	}
	//��APRFrame.FrameHeader.SrcMAC����Ϊ����������MAC��ַ
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.SrcMAC[i] = 0x0f;
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
		ARPFrame.SendHa[i] = 0x0f;
	}
	//��ARPFrame.SendIP����Ϊ���������ϰ󶨵�IP��ַ
	ARPFrame.SendIP = inet_addr("122.122.122.122");
	//��ARPFrame.RecvHa����Ϊ0
	for (int i = 0; i < 6; i++)
	{
		ARPFrame.RecvHa[i] = 0x00;//��ʾĿ�ĵ�ַδ֪
	}
	//��ARPFrame.RecvIP����Ϊ�����IP��ַ
	ARPFrame.RecvIP = inet_addr(ip[0]);
	//����������ARPFrame�е����ݣ����ĳ���Ϊsizeof(ARPFrame_t)��������ͳɹ�������0
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
	{
		printf("����ʧ�ܣ��˳�����\n");
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
			for (int i = 0; i < 6; i++)
			{
				selfmac[i] = IPPacket->FrameHeader.SrcMAC[i];
			}
			if ((ntohs(IPPacket->FrameHeader.FrameType) == 0x0806) && (ntohs(IPPacket->Operation) == 0x0002))//���֡����ΪARP���Ҳ���ΪARPӦ��
			{
				LT.WritelogARP(IPPacket);
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
	RouterTable RT;
	hThread = CreateThread(NULL, NULL, Thread, LPVOID(&RT), 0, &dwThreadId);
	int op;
	while (1)
	{
		printf("����������Ҫ���еĲ�����");
		printf("1����ӡ·�ɱ�2�����·�ɱ��3��ɾ��·�ɱ��0���˳�");
		scanf("%d", &op);
		if (op == 1)
		{
			RT.print();
		}
		else if (op == 2)
		{
			RouterItem ri;
			char temp[30];
			printf("������Ŀ�����磺");
			scanf("%s", &temp);
			ri.net = inet_addr(temp);
			printf("���������룺");
			scanf("%s", &temp);
			ri.mask = inet_addr(temp);
			printf("��������һ����ַ��");
			scanf("%s", &temp);
			ri.nextip = inet_addr(temp);
			ri.type = 1;
			RT.RouterAdd(&ri);
		}
		else if (op == 3)
		{
			printf("������ɾ�������ţ�");
			int index;
			scanf("%d", &index);
			RT.RouterRemove(index);
		}
		else if (op == 0)
		{
			break;
		}
		else
		{
			printf("��Ч������������ѡ��\n");
		}
	}

	pcap_close(adhandle);
	return 0;
}