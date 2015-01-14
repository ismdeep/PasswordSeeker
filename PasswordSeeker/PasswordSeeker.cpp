// PasswordSeeker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <pcap.h>

int _tmain(int argc, _TCHAR* argv[])

{

	pcap_if_t * allAdapters;//�������б�

	pcap_if_t * adapter;

	pcap_t           * adapterHandle;//���������

	struct pcap_pkthdr * packetHeader;

	const u_char       * packetData;

	char errorBuffer[PCAP_ERRBUF_SIZE];//������Ϣ������

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,

		&allAdapters, errorBuffer) == -1)

	{//�����������ӵ���������������

		fprintf(stderr, "Error in pcap_findalldevs_ex function: %s\n", errorBuffer);

		return -1;

	}

	if (allAdapters == NULL)

	{//�������κ�������

		printf("\nNo adapters found! Make sure WinPcap is installed.\n");

		return 0;

	}

	int crtAdapter = 0;

	for (adapter = allAdapters; adapter != NULL; adapter = adapter->next)

	{//����������������Ϣ(���ƺ�������Ϣ)

		printf("\n%d.%s ", ++crtAdapter, adapter->name);

		printf("-- %s\n", adapter->description);

	}

	printf("\n");

	//ѡ��Ҫ�������ݰ���������

	int adapterNumber;

	printf("Enter the adapter number between 1 and %d:", crtAdapter);

	scanf_s("%d", &adapterNumber);

	if (adapterNumber < 1 || adapterNumber > crtAdapter)

	{

		printf("\nAdapter number out of range.\n");

		// �ͷ��������б�

		pcap_freealldevs(allAdapters);

		return -1;

	}

	adapter = allAdapters;

	for (crtAdapter = 0; crtAdapter < adapterNumber - 1; crtAdapter++)

		adapter = adapter->next;

	// ��ָ��������

	adapterHandle = pcap_open(adapter->name, // name of the adapter

		65536,         // portion of the packet to capture

		// 65536 guarantees that the whole 

		// packet will be captured

		PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode

		1000,             // read timeout - 1 millisecond

		NULL,          // authentication on the remote machine

		errorBuffer    // error buffer

		);

	if (adapterHandle == NULL)

	{//ָ����������ʧ��

		fprintf(stderr, "\nUnable to open the adapter\n", adapter->name);

		// �ͷ��������б�

		pcap_freealldevs(allAdapters);

		return -1;

	}

	printf("\nCapture session started on  adapter %s\n", adapter->name);

	pcap_freealldevs(allAdapters);//�ͷ��������б�

	// ��ʼ�������ݰ�

	int retValue;

	while ((retValue = pcap_next_ex(adapterHandle,

		&packetHeader,

		&packetData)) >= 0)

	{

		// timeout elapsed if we reach this point

		if (retValue == 0)

			continue;

		//��ӡ�������ݰ�����Ϣ

		printf("length of packet: %d\n", packetHeader->len);

	}

	// if we get here, there was an error reading the packets

	if (retValue == -1)

	{

		printf("Error reading the packets: %s\n", pcap_geterr(adapterHandle));

		return -1;

	}

	system("PAUSE");

	return 0;

}
