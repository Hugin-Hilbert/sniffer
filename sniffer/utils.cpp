#include"pch.h"
#include"utils.h"
#include"MainForm.h"
msclr::gcroot<recvPack^> handle;
std::vector<PackageInfo> data;
struct Layer{
	virtual String^ to_string() const =0;
	virtual String^ protocol() const=0;
	virtual String^ source() const =0;
	virtual String^ destination() const =0;
	u_char* payload() const{
		return next ? next->payload() : data;
	}
	const Layer* next;
	u_char* data;
	~Layer() {
		delete next;
		next = nullptr;
	}
};
struct UDPlayer :Layer {
	struct head{
		uint16_t sport, dport, len, crc;
	}*header;
	UDPlayer(u_char* _data) {
		data = _data;
		header = (head*)_data;
		data = data + 8;
		next = nullptr;
	}
	String^ source() const{
		String^ res="/"+ntohs(header->sport);
		return res;
	}
	String^ destination() const{
		String^ res ="/"+ ntohs(header->dport);
		return res;
	}
	String^ protocol() const{
		return "UDP";
	}
	String^ to_string() const{
		String^ res = gcnew String("UDP:")+Environment::NewLine;
		res += "源:"+ntohs(header->sport) + ",目的:"+ntohs(header->dport)+Environment::NewLine;
		return res;
	}
};
struct TCPlayer:Layer{
	struct head{
		uint16_t src, dst;
		uint32_t seq, ack_num;
#if (REG_DWORD==REG_DWORD_LITTLE_ENDIAN)
			uint16_t reserved : 4,offset : 4,
					 fin:1,syn : 1,rst: 1,psh : 1,ack: 1,urg : 1,ece : 1,cwr : 1;
#else
		uint16_t offset : 4,reserved : 4, 
					 cwr : 1,ece : 1, urg : 1, ack : 1,psh : 1, rst : 1, syn : 1,fin : 1;
#endif
		uint16_t windowSize, checkSum, urgPtr;
		uint32_t option_pad;
	}*header;
	String^ protocol() const{
		return next?next->protocol() : "TCP";
	}
	TCPlayer(u_char* _data) {
		header = (head*)_data;
		data = _data+header->offset*4;
		next = NULL;
	}
	String^ source() const {
		String^ res = "/" + ntohs(header->src);
		return res;
	}
	String^ destination() const {
		String^ res = "/" + ntohs(header->dst);
		return res;
	}
	String^ to_string()const {
		String^ res = "TCP:" + Environment::NewLine;
		res += "源:" + ntohs(header->src)+","+"目的:"+ntohs(header->dst)+Environment::NewLine;
		res += "seq:"+(header->seq)+","+"ack:"+(header->ack_num)+Environment::NewLine;

		res += "flags:";
		if (header->fin)res+="FIN ";
		if (header->syn)res+="SYN ";
		if (header->rst)res+="RST ";
		if (header->psh)res+="PSH ";
		if (header->ack)res+="ACK ";
		if (header->urg)res+="URG ";
		if (header->ece)res+="ECE ";
		if (header->cwr)res+="CWR ";
		res += Environment::NewLine;
		res += "窗口大小:"+header->windowSize+",校验和:"+header->checkSum+Environment::NewLine;
		res += "紧急指针:" + header->urgPtr+Environment::NewLine;
		return res;
	}
};
struct IPV4layer:Layer {
	struct address{
		uint8_t ip[4];
		String^ to_string() {
			String^ res = ip[0].ToString("D3");
			for (int i = 1; i < 4; i++)res += ":" + ip[i].ToString("D3");
			return res;
		}
	};
	struct head {
#if (REG_DWORD==REG_DWORD_LITTLE_ENDIAN)
		uint8_t header_length : 4, version : 4;
#else
		uint8_t version : 4, header_length : 4;
#endif
		uint8_t type_of_service;
		uint16_t total_length;
		uint16_t ident;
		uint16_t flags_and_offset;
		uint8_t ttl;
		uint8_t protocol;
		uint16_t crc;
		address src_addr;
		address des_addr;
		uint32_t op_pad;
	}*header;
	String^ to_string() const {
		String^ res = "IP报文:"+ Environment::NewLine;
		res += "版本:"+header->version+Environment::NewLine;
		res += "总长度:"+ntohs(header->total_length)+Environment::NewLine;
		res += "标识:" + header->ident+Environment::NewLine;
		bool DF = (ntohs(header->flags_and_offset)>>13)&0b010;
		bool MF = (ntohs(header->flags_and_offset) >> 13) & 0b001;
		res += "DF:" + DF+",MF:"+MF+Environment::NewLine;
		res += "偏移:" + (ntohs(header->flags_and_offset) & 0x1fff)*8+"byte" + Environment::NewLine;
		res += "TTL:"+header->ttl+Environment::NewLine;
		res += "源:"+header->src_addr.to_string() + Environment::NewLine;
		res += "目的:" + header->des_addr.to_string() + Environment::NewLine;
		if (next)res += next->to_string();
		return res;
	}
	String^ source() const {
		String^ res = "/" + gcnew String(header->src_addr.to_string());
		if (next)res +=next->source();
		return res;
	}
	String^ destination()const {
		String^ res = "/" + gcnew String(header->des_addr.to_string());
		if (next)res += next->destination();
		return res;
	}
	String^ protocol() const{
		return next?next->protocol() : "IPV4";
	}
	enum PayLoadProtocol {
		TCP = 6,
		UDP = 17,
		Unkown = -1
	};
	~IPV4layer() {
		delete next;
	}
	IPV4layer(u_char* _data) {
		header = (head*)_data;
		data=_data+header->header_length*4;
		switch (header->protocol)
		{
		case PayLoadProtocol::UDP:
			next = new UDPlayer(data);
			break;
		case PayLoadProtocol::TCP:
			next = new TCPlayer(data);
			break;
		default:
			next = nullptr;
			break;
		}
	}
};
struct ETHlayer:Layer{
	struct address{
		uint8_t mac[6];
		String^ to_string() {
			String^ res = "";
			res += mac[0].ToString("X2");
			for (int i = 1; i < 6; i++) {
				res += ":" + mac[i].ToString("X2");
			}
			return res;
		}
	};
	String^ source() const{
		String^ res = header->source.to_string();
		if (next)res += next->source();
		return res;
	}
	String^ destination() const{
		String^ res = header->destination.to_string();
		if (next)res += next->destination();
		return res;
	}
	String^ to_string() const{
		String^ res = "Ethernet II:"+ Environment::NewLine;
		res += "源:"+source()+Environment::NewLine+"目的:"+destination()+Environment::NewLine;
		return next ? res += next->to_string() : res;
	}
	String^ protocol()const {
		return next ? next->protocol() : "Ethernet II";
	}
	enum PayLoadProtocol {
		IPV4=0x0800,
	};
	struct head{
		address destination, source;
		uint16_t protocol;
	}*header;
	ETHlayer(u_char* _data) {
		header = (head*)_data;		
		data = _data+14;
		switch (ntohs(header->protocol))
		{
		case PayLoadProtocol::IPV4:
			next = new IPV4layer(data);
			break;
		default:
			next = nullptr;
			break;
		}	
	}
};
UnpackedPackageInfo::UnpackedPackageInfo(const PackageInfo& info,int DLT){
	time_t local_tv_sec = info.header.ts.tv_sec;
	tm ltime;
	localtime_s(&ltime, &local_tv_sec);
	char buf[32];
	strftime(buf, sizeof buf, "%x %X", &ltime);
	timeStr = gcnew String(buf);
	Layer* bootStrap=nullptr;
	switch (DLT)
	{
	case DLT_EN10MB:
		bootStrap = new ETHlayer(info.pkt_data);
	default:
		break;
	}
	if (bootStrap) {
		src = bootStrap->source();
		des = bootStrap->destination();
		protocol = bootStrap->protocol();
		description = bootStrap->to_string();
		u_char* data = bootStrap->payload();
		int len = info.header.len-(data-info.pkt_data);
		System::Text::ASCIIEncoding^ decoder=gcnew System::Text::ASCIIEncoding();
		payload = decoder->GetString(data,len);
	}
}
void recvPack::updateUI(UnpackedPackageInfo^ text) {
	ListViewItem^ item = gcnew ListViewItem(text->timeStr);	
	item->SubItems->Add(text->protocol);
	item->SubItems->Add(text->src);
	item->SubItems->Add(text->des);
	//hidden field
	item->SubItems->Add(text->description);
	item->SubItems->Add(text->payload);
	form->dataView->Items->Add(item);

}
void recvPackFun(u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data) {
	handle->handleUse(param, header, pkt_data);
}
recvPack::recvPack(MainForm^ _form, syncPcap_tPtr^ _adhandle,int _DLT) {
	form = _form, adhandle = _adhandle;
	DLT = _DLT;
}
void recvPack::handleUse(u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data){
	data.push_back(PackageInfo(header, pkt_data));
	UnpackedPackageInfo^ res=gcnew UnpackedPackageInfo(data.back(), this->DLT);
	auto act = gcnew Action<UnpackedPackageInfo^>(this, &recvPack::updateUI);
	if (form->InvokeRequired)
		form->Invoke(act, res);
	else {
		updateUI(res);
	}
}
DataManager::DataManager(MainForm^ form, int DLT, syncPcap_tPtr^ _adhandle, syncBool^ keep, syncBool^ proc) {
	handle = gcnew recvPack(form, _adhandle, DLT);
	keepAlive = keep;
	procAlive = proc;
}
#include<msclr/marshal_cppstd.h>
void DataManager::run(Object^ param) {
	auto tup = (Tuple<String^, u_int>^)param;
	String^ rule=tup->Item1;
	std::string str = msclr::interop::marshal_as<std::string>(rule);
	u_int netmask = tup->Item2;
	pcap_t* adhandle = (pcap_t*)handle->adhandle->get();
	bpf_program fcode;
	if (pcap_compile(adhandle, &fcode, str.c_str(), 1, netmask) < 0) {
		MessageBox::Show("error in compile filter:"+gcnew String(pcap_geterr(adhandle)));
		pcap_close(adhandle), keepAlive->set(false);
		return;
	}
	if (pcap_setfilter(adhandle, &fcode)<0) {
		MessageBox::Show("error in set filter:"+gcnew String(pcap_geterr(adhandle)));
		pcap_close(adhandle),keepAlive->set(false);
		return;
	}
	MessageBox::Show("开始监听");
	while (1) {
		int status = pcap_dispatch(adhandle, 0, recvPackFun, NULL);
		if (status == -1) {
			MessageBox::Show("pcap_dispatch:err" + gcnew String(pcap_geterr(adhandle)));
		}
		bool^ tmp1=keepAlive->get(),^tmp2=procAlive->get();
		if (tmp1->Equals(false) || tmp2->Equals(false)) {	
			break;
		}
	}
	//pcap_close(adhandle);
	keepAlive->set(false);	
	MessageBox::Show("capture ended");
}