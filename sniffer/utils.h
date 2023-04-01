#pragma once
#include<msclr/gcroot.h>
#include<cliext/vector>
#include<msclr/lock.h>
#include"Entity.h"
#include<vector>
#include<msclr/marshal.h>
using namespace System;
using namespace System::ComponentModel;
using namespace System::Collections;
using namespace System::Windows::Forms;
using namespace System::Data;
using namespace System::Drawing;
const int supportDLT[]={DLT_EN10MB};
ref class MainForm;
ref class syncPcap_tPtr {
	IntPtr^ ptr;
	msclr::lock locker;
public:
	syncPcap_tPtr(IntPtr^ _ptr) :ptr(_ptr), locker(ptr) {

	}
	~syncPcap_tPtr() {
		pcap_close((pcap_t*)ptr->ToPointer());
	}
	pcap_t* get() {
		locker.acquire();
		return (pcap_t*)ptr->ToPointer();
	}
};
ref class syncBool
{
public:
	bool^ val;
	msclr::lock locker;
	syncBool(bool _val) :val(_val), locker(val) {
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

ref class UnpackedPackageInfo {
public:
	String^ timeStr,^ src,^ des, ^protocol;
	String^ description;
	String^ payload;
public:UnpackedPackageInfo(const PackageInfo& info,int DLT); 
};
ref class recvPack
{
public:
	MainForm^ form;
	syncPcap_tPtr^ adhandle;
	int DLT;
	void updateUI(UnpackedPackageInfo^ text);
	void handleUse(u_char* param,
		const struct pcap_pkthdr* header,
		const u_char* pkt_data);
	recvPack(MainForm^ _form, syncPcap_tPtr^ _adhandle,int _DLT);
	~recvPack() {

	}
};	
void recvPackFun(u_char* param,const struct pcap_pkthdr* header,const u_char* pkt_data);
ref class DataManager
{
public:
	syncBool^ keepAlive,^procAlive;
	DataManager(MainForm^ form, int DLT, syncPcap_tPtr^ _adhandle, syncBool^ keep, syncBool^ proc);
	void run(Object^);
	~DataManager(){}

private:

};