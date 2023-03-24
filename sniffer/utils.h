#pragma once
#include<msclr/gcroot.h>
#include<cliext/vector>
using namespace System;
using namespace System::ComponentModel;
using namespace System::Collections;
using namespace System::Windows::Forms;
using namespace System::Data;
using namespace System::Drawing;
ref class recvPack
{
public:
	ListView^ list;
	cliext::vector<PackageInfo> data;
	void handleUse(u_char* param,
		const struct pcap_pkthdr* header,
		const u_char* pkt_data) {
		String^ res;
		for (int i = 0; pkt_data[i]; i++) {
			res += pkt_data[i].ToString("X2");
		}

	}
	recvPack(ListView^ l) {
		list = l;
	}
	~recvPack();
};
msclr::gcroot<recvPack^> handle;
void wrap(ListView^ l) {
	handle = gcnew recvPack(l);
}
void recvPackFun(u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data) {
	handle->handleUse(param,header,pkt_data);
}
