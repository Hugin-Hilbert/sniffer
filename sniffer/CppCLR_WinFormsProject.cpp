#include "pch.h"

using namespace System;

// int main(array<System::String ^> ^args)
// {
//    return 0;
// }

#include "MainForm.h"

using namespace System::Windows::Forms;
#include"pcap.h"
[STAThread]
int main()
{
  Application::EnableVisualStyles();
  Application::SetCompatibleTextRenderingDefault(false);
  Application::Run(gcnew Sniffer::MainForm());


  return 0;
}