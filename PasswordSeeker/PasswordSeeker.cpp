// PasswordSeeker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

/* 以上这些乱七八糟的东西管我鸟事啊 */

#include <pcap.h>

using namespace std;

int main()
{
	pcap_if_t * all_adapters;
	pcap_if_t * adapter;
	char error_buffer[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_adapters, error_buffer) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex function: %s\n", error_buffer);
		return -1;
	}

	if (all_adapters == NULL)
	{
		fprintf(stdout, "\nNo adapters found! Make sure WinPcap is installed.\n");
		return 0;
	}

	int crt_adapter = 0;
	for (adapter = all_adapters; adapter != NULL; adapter = adapter->next)
	{
		fprintf(stdout, "\n%d.%s ", ++crt_adapter, adapter->name);
		fprintf(stdout, "-- %s\n", adapter->description);
	}
	
	printf("\n");



	pcap_freealldevs(all_adapters);//释放适配器列表

	return 0;

}

