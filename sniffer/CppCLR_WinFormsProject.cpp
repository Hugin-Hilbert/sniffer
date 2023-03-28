#include "pch.h"
using namespace System;
extern void recvPackFun(u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data);
#include "MainForm.h"

using namespace System::Windows::Forms;
#include"pcap.h"
[STAThread]
int main()
{
  Application::EnableVisualStyles();
  Application::SetCompatibleTextRenderingDefault(false);
  Application::Run(gcnew MainForm());


  return 0;
}