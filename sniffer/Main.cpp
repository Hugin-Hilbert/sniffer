#include "pch.h"
using namespace System;
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