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
static std::vector<PackageInfo> data;
const int supportDLT[]={DLT_EN10MB};
ref class MainForm;
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