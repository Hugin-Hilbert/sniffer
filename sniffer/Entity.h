#pragma once
#include"pch.h"
using namespace System;
using namespace System::Windows;
ref class InterfaceInfo
{
public:
	String^ name, ^ description;
	char* id;
	InterfaceInfo(pcap_if_t* dev);
	~InterfaceInfo();
private:

};
#include<msclr/lock.h>
ref class syncBool
{
public:
	bool^ val;
	msclr::lock locker;
	syncBool(bool _val):val(_val),locker(val) {
	}
	void set(bool^ _val) {
		locker.acquire();
		val = _val;
	}
	bool^ tryGet(int time_out, bool^ default_val) {
		if (locker.try_acquire(time_out)) {
			return val;
		}
		return default_val;
	}
	bool^ get() {
		locker.acquire();
		return val;
	}
	~syncBool() {

	}
};
#include<string>
#include<vector>
#include<WinSock2.h>
#include<tchar.h>
#include<time.h>
struct PackageInfo
{
	struct pcap_pkthdr header;
	std::vector<u_char> pkt_data;
	PackageInfo(const pcap_pkthdr* h,const u_char* d) {
		header = *h;
		for (int i=0;d[i];i++) {
			pkt_data.push_back(d[i]);
		}
	}
};