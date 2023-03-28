#include"pch.h"
#include "Entity.h"


InterfaceInfo::InterfaceInfo(pcap_if_t* dev)
{
	id = dev->name;
	name = gcnew String(dev->name);
	description = gcnew String(dev->description);
	int end = description->LastIndexOf("'");
	int start = description->IndexOf("'");
	description = description->Substring(start + 1, end - start - 1);
}


InterfaceInfo::~InterfaceInfo()
{

}
