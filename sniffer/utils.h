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
std::vector<PackageInfo> data;	
ref class recvPack
{
public:
	ListView^ list;
	void updateList(String^ text) {
		list->Items->Add(text);
	}
	void handleUse(u_char* param,
		const struct pcap_pkthdr* header,
		const u_char* pkt_data) {
		data.push_back(PackageInfo(header, pkt_data));
		String^ res;
		for (int i = 0; pkt_data[i]; i++) {
			res += pkt_data[i].ToString("X2");
		}
		auto act = gcnew Action<String^>(this,&recvPack::updateList);
		if(list->InvokeRequired)
			list->Invoke(act,res);
		else {
			updateList(res);
		}
	}
	recvPack(ListView^ _list) {
		list = _list;
	}
	~recvPack() {

	}
};	
msclr::gcroot<recvPack^> handle;	
void recvPackFun(u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data) {
	handle->handleUse(param, header, pkt_data);
}
ref class DataManager
{
public:
	syncBool^ keepAlive,^procAlive;
	DataManager(ListView^ list,syncBool^ keep,syncBool^ proc){
		handle = gcnew recvPack(list);
		keepAlive = keep;
		procAlive = proc;
	}

	void run(Object^ parma) {
		pcap_t* adhandle = (pcap_t*)((IntPtr)parma).ToPointer();
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