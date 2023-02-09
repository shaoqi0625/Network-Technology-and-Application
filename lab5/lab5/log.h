#pragma once
#include <Winsock2.h>
//#include<iostream>
#include "pcap.h"
#include "stdio.h"
//#include<time.h>
#include <string.h>
//#include "log.h"//��־

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"wsock32.lib")
#pragma warning(disable : 4996)

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

class arpitem
{
public:
	DWORD ip;
	BYTE mac[6];
};

class ipitem
{
public:
	DWORD sip, dip;
	BYTE smac[6], dmac[6];
};

class Routerlog //��־
{
public:
	int index;//����
	char type[5];//���ͣ�arp ip��
	ipitem ip;
	arpitem arp;
	Routerlog()
	{
		fp = fopen("log.txt", "a+");//�ļ��Լ��򿪷�ʽ
	}
	~Routerlog()
	{
		fclose(fp);
	}
	static int num;
	static Routerlog diary[50];
	static FILE* fp;
	static void WritelogARP(ARPFrame_t* t)
	{
		fprintf(fp, "ARP\t");
		in_addr addr;
		addr.s_addr = t->SendIP;
		char* temp = inet_ntoa(addr);
		fprintf(fp, "IP:\t");
		fprintf(fp, "%s\t", temp);
		fprintf(fp, "MAC:\t");
		for (int i = 0; i < 6; i++)
		{
			fprintf(fp, "%02x:", t->SendHa[i]);
		}
		fprintf(fp, "\n");
		//printf("end\n");
	}
	static void WritelogIP(const char* a, Data_t* t)
	{
		fprintf(fp, "IP\t");
		fprintf(fp, a);
		fprintf(fp, "\t");
		in_addr addr;
		addr.s_addr = t->IPHeader.SrcIP;
		char* temp = inet_ntoa(addr);
		fprintf(fp, "ԴIP��\t");
		fprintf(fp, "%s\t", temp);
		fprintf(fp, "Ŀ��IP��\t");
		addr.s_addr = t->IPHeader.DstIP;
		fprintf(fp, "%s\t", temp);
		fprintf(fp, "ԴMAC��\t");
		for (int i = 0; i < 6; i++)
			fprintf(fp, "%02x:", t->FrameHeader.SrcMAC[i]);
		fprintf(fp, "Ŀ��MAC��\t");
		for (int i = 0; i < 6; i++)
			fprintf(fp, "%02x:", t->FrameHeader.DesMAC[i]);
		fprintf(fp, "\n");
		//printf("end\n");
	}
	static void print()
	{
		for (int i = 0; i < num; i++)
		{
			printf("%d ", diary[i].index);
			printf("%s\t ", diary[i].type);
			if (strcmp(diary[i].type, "ARP") == 0)
			{
				in_addr addr;
				addr.s_addr = diary[i].arp.ip;
				char* temp = inet_ntoa(addr);
				printf("%s\t", temp);
				for (int i = 0; i < 6; i++)
				{
					printf("%02x.", diary[i].arp.mac[i]);
				}
				//fprintf(fp, "/n");
				//printf("end\n");
			}
			else if (strcmp(diary[i].type, "IP") == 0)
			{
				in_addr addr;
				addr.s_addr = diary[i].ip.sip;
				char* temp = inet_ntoa(addr);
				printf("ԴIP��%s\t", temp);
				addr.s_addr = diary[i].ip.dip;
				temp = inet_ntoa(addr);
				printf("Ŀ��IP��%s\t", temp);
				printf("ԴMAC: ");
				for (int i = 0; i < 6; i++)
				{
					printf("%02x.", diary[i].ip.smac[i]);
				}
				printf("Ŀ��MAC: ");
				for (int i = 0; i < 6; i++)
				{
					printf("%02x.", diary[i].ip.dmac[i]);
				}
				//fprintf(fp, "/n");
				//printf("end\n");
			}
		}
	}
};