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
struct PackageInfo
{
	const struct pcap_pkthdr* header;
	const u_char* pkt_data;
};