#pragma once
#include"pch.h"
using namespace System;
using namespace System::Windows;
ref class InterfaceInfo
{
public:
	String^ name, ^ description;
	char* id;
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
ref class syncPcap_tPtr {
	IntPtr^ ptr;
	msclr::lock locker;
public :
	syncPcap_tPtr(IntPtr^ _ptr):ptr(_ptr),locker(ptr) {

	}
	~syncPcap_tPtr() {
		pcap_close((pcap_t*)ptr->ToPointer());
	}
	pcap_t* get() {
		locker.acquire();
		return (pcap_t*)ptr->ToPointer();
	}
	void release() {
		locker.release();
	}
};
ref class syncBool
{
public:
	bool^ val;
	msclr::lock locker;
	syncBool(bool _val):val(_val),locker(val) {
	}
	void release() {
		locker.release();
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