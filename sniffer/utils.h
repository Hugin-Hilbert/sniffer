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
	String^ timeStr;
	String^ description;
public:UnpackedPackageInfo(const PackageInfo& info,int DLT); 
};
ref class recvPack
{
public:
	MainForm^ form;
	pcap_t*  adhandle;
	int DLT;
	void updateUI(UnpackedPackageInfo^ text);
	void handleUse(u_char* param,
		const struct pcap_pkthdr* header,
		const u_char* pkt_data);
	recvPack(MainForm^ _form,pcap_t* _adhandle) {
		DLT=pcap_datalink(adhandle);
		form=_form, adhandle = _adhandle;
	}
	~recvPack() {

	}
};	
msclr::gcroot<recvPack^> handle;	
void recvPackFun(u_char* param,const struct pcap_pkthdr* header,const u_char* pkt_data);
ref class DataManager
{
public:
	syncBool^ keepAlive,^procAlive;
	DataManager(MainForm^ form,pcap_t* _adhandle,syncBool^ keep,syncBool^ proc){
		handle = gcnew recvPack(form,_adhandle);
		keepAlive = keep;
		procAlive = proc;
	}
	void run() {
		pcap_t* adhandle = handle->adhandle;
		while (1) {
			int status = pcap_dispatch(adhandle, 0, recvPackFun, (u_char*)adhandle); 
			if(status==-1) {
				MessageBox::Show("pcap_dispatch:err" + gcnew String(pcap_geterr(adhandle)));
			}
			if (keepAlive->get()->Equals(false) || procAlive->get()->Equals(false)) {
				MessageBox::Show("capture ended");
				break;
			}

		}
		pcap_close(adhandle);
	}
	~DataManager(){}

private:

};