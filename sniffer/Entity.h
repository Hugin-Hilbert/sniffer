#pragma once
#include"pch.h"
using namespace System;
using namespace System::Windows;
ref class InterfaceInfo
{
public:
	String^ description;
	pcap_if_t* device;
	String^ ToString() override{
		return description;
	}
	InterfaceInfo(pcap_if_t* dev);
	~InterfaceInfo();
private:

};
#include<msclr/gcroot.h>
#include<msclr/lock.h>
using namespace System;
#include<string>
#include<vector>
#include<WinSock2.h>
#include<tchar.h>
#include<time.h>
struct PackageInfo
{
	struct pcap_pkthdr header;
	u_char* pkt_data;
	PackageInfo(PackageInfo&& rhs) {
		header = rhs.header;
		pkt_data = rhs.pkt_data;
		rhs.pkt_data = NULL;
	}
	PackageInfo(const pcap_pkthdr* h,const u_char* d) {
		header = *h;
		pkt_data = new u_char[header.caplen];
		memcpy(pkt_data, d,header.caplen);
	}
	~PackageInfo() {
		delete[] pkt_data;
	}
};