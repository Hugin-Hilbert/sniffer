#include"pch.h"
#include"utils.h"
#include"MainForm.h"
struct Layer{
	virtual String^ to_string()=0;
	virtual String^ protocol()=0;
	virtual String^ source()=0;
	virtual String^ destination()=0;
	Layer* next;
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
		header = (head*)data;
		next = nullptr;
	}
	String^ source() {
		String^ res=gcnew String(header->sport.ToString());
		return res;
	}
	String^ destination() {
		String^ res = gcnew String(header->dport.ToString());
		return res;
	}
	String^ protocol() {
		return "UDP";
	}
	String^ to_string() {
		String^ res = gcnew String("UDP:\n");
		res += "源:"+header->sport + ",目的:"+header->dport+"\n";
		return res;
	}
};
struct TCPlayer:Layer{
	TCPlayer(u_char* _data);
	String^ to_string();
};
struct IPV4layer:Layer {
	struct address{
		uint8_t ip[4];
		String^ to_string() {
			String^ res = ip[0].ToString("%03d");
			for (int i = 1; i < 3; i++)res += ":" + ip[i].ToString("%03d");
			return res;
		}
	};
	struct head {
		uint8_t version : 4;
		uint8_t header_length : 4;
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
	String^ to_string() {
		String^ res = gcnew String("IP报文:\n");
		res += "版本:"+header->version+"\n";
		res += "总长度:"+header->total_length+"\n";
		res += "标识:" + header->ident+"\n";
		bool DF = (header->flags_and_offset>>13)&0b010;
		bool MF = (header->flags_and_offset >> 13) & 0b001;
		res += "DF:" + DF+",MF:"+MF+"\n";
		res += "偏移:" + (header->flags_and_offset & 0x1fff)*8+"byte" + "\n";
		res += "TTL:"+header->ttl+"\n";
		res += "源:"+header->src_addr.to_string() + "\n";
		res += "目的:" + header->des_addr.to_string() + "\n";
		if (next)res += next->to_string();
		return res;
	}
	String^ source() {
		String^ res = '/'+gcnew String(header->src_addr.to_string());
		if (next)res +=next->source();
		return res;
	}
	String^ destination() {
		String^ res = '/'+gcnew String(header->des_addr.to_string());
		if (next)res += next->destination();
		return res;
	}
	String^ protocol() {
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
		data = _data;
		header = (head*)data;
		u_char* payLoad=data+header->header_length*4;
		switch (header->protocol)
		{
		case PayLoadProtocol::UDP:
			next = new UDPlayer(payLoad);
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
	String^ source() {
		String^ res = header->source.to_string();
		if (next)res += next->source();
		return res;
	}
	String^ destination() {
		String^ res = header->destination.to_string();
		if (next)res += next->destination();
		return res;
	}
	enum PayLoadProtocol {

	};
	struct head{
		address destination, source;
		uint16_t protocol;
	}*header;
	ETHlayer(u_char* _data) {
		data = _data;
		header = (head*)data;
		next = new IPV4layer(data+14);
	}
};
UnpackedPackageInfo::UnpackedPackageInfo(const PackageInfo& info,int DLT){
	time_t local_tv_sec = info.header.ts.tv_sec;
	tm ltime;
	localtime_s(&ltime, &local_tv_sec);
	char buf[32];
	strftime(buf, sizeof buf, "%x %X", &ltime);
	timeStr = gcnew String(buf);
	ETHlayer start(&info.pkt_data[0]);

}
void recvPack::updateUI(UnpackedPackageInfo^ text) {

}
void recvPackFun(u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data) {
	handle->handleUse(param, header, pkt_data);
}

void recvPack::handleUse(u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data){
	PackageInfo info = PackageInfo(header, pkt_data);
	data.push_back(info);
	UnpackedPackageInfo^ res=gcnew UnpackedPackageInfo(info,this->DLT);
	auto act = gcnew Action<UnpackedPackageInfo^>(this, &recvPack::updateUI);
	if (form->InvokeRequired)
		form->Invoke(act, res);
	else {
		updateUI(res);
	}
}
