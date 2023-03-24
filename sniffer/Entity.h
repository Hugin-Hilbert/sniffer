#pragma once
#include"pch.h"
using namespace System;
using namespace System::Windows;
namespace Entity {
	ref class InterfaceInfo
	{
	public:
		String^ name, ^ description;
		char* id;
		InterfaceInfo(pcap_if_t* dev);
		~InterfaceInfo();
		String^ ToString()override {
			return description;
		}
	private:

	};

	InterfaceInfo::InterfaceInfo(pcap_if_t* dev)
	{
		id = dev->name;
		name = gcnew String(dev->name);
		description = gcnew String(dev->description);
		int end = description->LastIndexOf("'");
		int start = description->IndexOf("'");
		description=description->Substring(start+1,end-start-1);
	}
	InterfaceInfo::~InterfaceInfo()
	{
		
	}
};
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
struct PackageInfo
{
	struct pcap_pkthdr header;
	std::vector<byte> pkt_data;
	PackageInfo(const pcap_pkthdr* h,const u_char* d) {
		header = *h;
		for (int i=0;d[i];i++) {
			pkt_data.push_back(d[i]);
		}
	}
};