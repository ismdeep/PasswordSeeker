// PasswordSeeker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <pcap.h>

int _tmain(int argc, _TCHAR* argv[])

{

	pcap_if_t * allAdapters;//适配器列表

	pcap_if_t * adapter;

	pcap_t           * adapterHandle;//适配器句柄

	struct pcap_pkthdr * packetHeader;

	const u_char       * packetData;

	char errorBuffer[PCAP_ERRBUF_SIZE];//错误信息缓冲区

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL,

		&allAdapters, errorBuffer) == -1)

	{//检索机器连接的所有网络适配器

		fprintf(stderr, "Error in pcap_findalldevs_ex function: %s\n", errorBuffer);

		return -1;

	}

	if (allAdapters == NULL)

	{//不存在任何适配器

		printf("\nNo adapters found! Make sure WinPcap is installed.\n");

		return 0;

	}

	int crtAdapter = 0;

	for (adapter = allAdapters; adapter != NULL; adapter = adapter->next)

	{//遍历输入适配器信息(名称和描述信息)

		printf("\n%d.%s ", ++crtAdapter, adapter->name);

		printf("-- %s\n", adapter->description);

	}

	printf("\n");

	//选择要捕获数据包的适配器

	int adapterNumber;

	printf("Enter the adapter number between 1 and %d:", crtAdapter);

	scanf_s("%d", &adapterNumber);

	if (adapterNumber < 1 || adapterNumber > crtAdapter)

	{

		printf("\nAdapter number out of range.\n");

		// 释放适配器列表

		pcap_freealldevs(allAdapters);

		return -1;

	}

	adapter = allAdapters;

	for (crtAdapter = 0; crtAdapter < adapterNumber - 1; crtAdapter++)

		adapter = adapter->next;

	// 打开指定适配器

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

	{//指定适配器打开失败

		fprintf(stderr, "\nUnable to open the adapter\n", adapter->name);

		// 释放适配器列表

		pcap_freealldevs(allAdapters);

		return -1;

	}

	printf("\nCapture session started on  adapter %s\n", adapter->name);

	pcap_freealldevs(allAdapters);//释放适配器列表

	// 开始捕获数据包

	int retValue;

	while ((retValue = pcap_next_ex(adapterHandle,

		&packetHeader,

		&packetData)) >= 0)

	{

		// timeout elapsed if we reach this point

		if (retValue == 0)

			continue;

		//打印捕获数据包的信息

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
