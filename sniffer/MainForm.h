#include"Entity.h"
#include<msclr/gcroot.h>
#include<msclr/lock.h>
#include"utils.h"
#pragma once
extern void recvPackFun(u_char* param,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data);

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	public ref class MainForm : public System::Windows::Forms::Form
	{
	public:
		/// <summary>
		/// user region
		/// </summary>
		syncBool^ keepAlive,^procAlive;
	private: System::Windows::Forms::ColumnHeader^ timeStr;
	private: System::Windows::Forms::ColumnHeader^ protocol;
	private: System::Windows::Forms::ColumnHeader^ sourceAddr;
	private: System::Windows::Forms::TextBox^ descriptionText;
	private: System::Windows::Forms::TextBox^ payloadText;


	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::Label^ label2;
	private: System::Windows::Forms::Button^ clearBtn;

	private: System::Windows::Forms::Label^ label3;
	private: System::Windows::Forms::Label^ label4;
	private: System::Windows::Forms::TextBox^ filterRule;




	private: System::Windows::Forms::ColumnHeader^ destinationAddr;
	public:
		MainForm(void)
		{
			InitializeComponent();
			this->keepAlive =gcnew syncBool(false);
			this->procAlive = gcnew syncBool(true);
			pcap_if_t* all_dev;
			char err[PCAP_ERRBUF_SIZE];
			if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_dev, err) == -1) {
				MessageBox::Show(gcnew String(err));
				exit(1);
			}
			for (auto cur_dev = all_dev; cur_dev; cur_dev = cur_dev->next) {
				InterfaceInfo^ info = gcnew InterfaceInfo(cur_dev);
				this->adapterList->Items->Add(info);
			}
		}
		/// <summary>
		/// Summary for MainForm
		/// </summary>

	protected:
		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		~MainForm()
		{
			if (components)
			{
				delete components;
			}
			procAlive->set(false);
		}
	private: System::Windows::Forms::Button^ btnStartSniff;
	public: System::Windows::Forms::ListView^ dataView;

	public:
	protected:



	private: System::Windows::Forms::ComboBox^ adapterList;
	private: System::Windows::Forms::Button^ stopSniffer;

	
	private: System::ComponentModel::IContainer^ components;




	private:
		/// <summary>
		/// Required designer variable.
		/// </summary>

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
	
		
		
		void InitializeComponent(void)
		{
			this->btnStartSniff = (gcnew System::Windows::Forms::Button());
			this->dataView = (gcnew System::Windows::Forms::ListView());
			this->timeStr = (gcnew System::Windows::Forms::ColumnHeader());
			this->protocol = (gcnew System::Windows::Forms::ColumnHeader());
			this->sourceAddr = (gcnew System::Windows::Forms::ColumnHeader());
			this->destinationAddr = (gcnew System::Windows::Forms::ColumnHeader());
			this->adapterList = (gcnew System::Windows::Forms::ComboBox());
			this->stopSniffer = (gcnew System::Windows::Forms::Button());
			this->descriptionText = (gcnew System::Windows::Forms::TextBox());
			this->payloadText = (gcnew System::Windows::Forms::TextBox());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->clearBtn = (gcnew System::Windows::Forms::Button());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->filterRule = (gcnew System::Windows::Forms::TextBox());
			this->SuspendLayout();
			// 
			// btnStartSniff
			// 
			this->btnStartSniff->Location = System::Drawing::Point(644, 29);
			this->btnStartSniff->Name = L"btnStartSniff";
			this->btnStartSniff->Size = System::Drawing::Size(113, 49);
			this->btnStartSniff->TabIndex = 0;
			this->btnStartSniff->Text = L"开始抓包";
			this->btnStartSniff->UseVisualStyleBackColor = true;
			this->btnStartSniff->Click += gcnew System::EventHandler(this, &MainForm::btnStartSniff_Click);
			// 
			// dataView
			// 
			this->dataView->Columns->AddRange(gcnew cli::array< System::Windows::Forms::ColumnHeader^  >(4) {
				this->timeStr, this->protocol,
					this->sourceAddr, this->destinationAddr
			});
			this->dataView->HideSelection = false;
			this->dataView->Location = System::Drawing::Point(49, 91);
			this->dataView->Name = L"dataView";
			this->dataView->Size = System::Drawing::Size(547, 231);
			this->dataView->TabIndex = 1;
			this->dataView->UseCompatibleStateImageBehavior = false;
			this->dataView->View = System::Windows::Forms::View::Details;
			this->dataView->SelectedIndexChanged += gcnew System::EventHandler(this, &MainForm::dataView_SelectedIndexChanged);
			// 
			// timeStr
			// 
			this->timeStr->Text = L"时间";
			this->timeStr->Width = 107;
			// 
			// protocol
			// 
			this->protocol->Text = L"协议";
			// 
			// sourceAddr
			// 
			this->sourceAddr->Text = L"源";
			// 
			// destinationAddr
			// 
			this->destinationAddr->Text = L"目的";
			// 
			// adapterList
			// 
			this->adapterList->DropDownStyle = System::Windows::Forms::ComboBoxStyle::DropDownList;
			this->adapterList->FormattingEnabled = true;
			this->adapterList->Location = System::Drawing::Point(49, 40);
			this->adapterList->Name = L"adapterList";
			this->adapterList->Size = System::Drawing::Size(307, 45);
			this->adapterList->TabIndex = 2;
			// 
			// stopSniffer
			// 
			this->stopSniffer->Location = System::Drawing::Point(644, 91);
			this->stopSniffer->Name = L"stopSniffer";
			this->stopSniffer->Size = System::Drawing::Size(113, 58);
			this->stopSniffer->TabIndex = 3;
			this->stopSniffer->Text = L"停止监听";
			this->stopSniffer->UseVisualStyleBackColor = true;
			this->stopSniffer->Click += gcnew System::EventHandler(this, &MainForm::stopSniffer_Click);
			// 
			// descriptionText
			// 
			this->descriptionText->Location = System::Drawing::Point(49, 366);
			this->descriptionText->Multiline = true;
			this->descriptionText->Name = L"descriptionText";
			this->descriptionText->ReadOnly = true;
			this->descriptionText->Size = System::Drawing::Size(237, 96);
			this->descriptionText->TabIndex = 4;
			// 
			// payloadText
			// 
			this->payloadText->Location = System::Drawing::Point(378, 366);
			this->payloadText->Multiline = true;
			this->payloadText->Name = L"payloadText";
			this->payloadText->ReadOnly = true;
			this->payloadText->Size = System::Drawing::Size(218, 96);
			this->payloadText->TabIndex = 5;
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Location = System::Drawing::Point(42, 326);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(81, 37);
			this->label1->TabIndex = 6;
			this->label1->Text = L"描述";
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Location = System::Drawing::Point(378, 325);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(81, 37);
			this->label2->TabIndex = 7;
			this->label2->Text = L"负载";
			// 
			// clearBtn
			// 
			this->clearBtn->Location = System::Drawing::Point(644, 169);
			this->clearBtn->Name = L"clearBtn";
			this->clearBtn->Size = System::Drawing::Size(113, 49);
			this->clearBtn->TabIndex = 8;
			this->clearBtn->Text = L"清空";
			this->clearBtn->UseVisualStyleBackColor = true;
			this->clearBtn->Click += gcnew System::EventHandler(this, &MainForm::clearBtn_Click);
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Location = System::Drawing::Point(55, 9);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(81, 37);
			this->label3->TabIndex = 10;
			this->label3->Text = L"接口";
			// 
			// label4
			// 
			this->label4->AutoSize = true;
			this->label4->Location = System::Drawing::Point(362, 9);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(113, 37);
			this->label4->TabIndex = 11;
			this->label4->Text = L"过滤器";
			// 
			// filterRule
			// 
			this->filterRule->Location = System::Drawing::Point(369, 40);
			this->filterRule->Name = L"filterRule";
			this->filterRule->Size = System::Drawing::Size(227, 44);
			this->filterRule->TabIndex = 12;
			// 
			// MainForm
			// 
			this->ClientSize = System::Drawing::Size(772, 514);
			this->Controls->Add(this->filterRule);
			this->Controls->Add(this->label4);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->clearBtn);
			this->Controls->Add(this->label2);
			this->Controls->Add(this->label1);
			this->Controls->Add(this->payloadText);
			this->Controls->Add(this->descriptionText);
			this->Controls->Add(this->stopSniffer);
			this->Controls->Add(this->adapterList);
			this->Controls->Add(this->dataView);
			this->Controls->Add(this->btnStartSniff);
			this->Name = L"MainForm";
			this->Text = L"Sniffer";
			this->Load += gcnew System::EventHandler(this, &MainForm::MainForm_Load);
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion


		void MainForm::startListen(pcap_if_t* dev) {
			char err[PCAP_ERRBUF_SIZE];
			syncPcap_tPtr^  adhandle = gcnew syncPcap_tPtr((IntPtr)pcap_open(dev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, err));
			pcap_t* ptr = adhandle->get();
			if (ptr == NULL) {
				MessageBox::Show(gcnew String(err));
				exit(1);
			}
			
			int curDLT = pcap_datalink(ptr);
			//DLT_EN10MB;
			bool isSupport = false;
			for (auto& i : supportDLT) isSupport |= i == curDLT;
			if (!isSupport) {
				MessageBox::Show("不支持的链接层协议");
				return;
			}
			u_int netmask;
			if (dev->addresses != nullptr) {
				netmask= ((struct sockaddr_in*)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
			}
			else {
				netmask = 0xffffff;
			}
			this->keepAlive->set(true);
			adhandle->release();
			DataManager^ manager = gcnew DataManager(this,curDLT,adhandle, this->keepAlive, this->procAlive);
			auto thstart = gcnew Threading::ParameterizedThreadStart(manager, &DataManager::run);
			//gcnew Threading::ThreadStart(manager, &DataManager::run);
			Threading::Thread^ th = gcnew Threading::Thread(thstart);
			String^ rule=filterRule->Text;
			th->Start(gcnew Tuple<String^,u_int>(rule,netmask));
			//MessageBox::Show("监听结束");
		}
private: System::Void btnStartSniff_Click(System::Object^ sender, System::EventArgs^ e) {
	if (adapterList->SelectedItem==nullptr) {
		MessageBox::Show("先选一个接口");
		return;
	}
	if (keepAlive->get()->Equals(true)) {
		procAlive->set(false);
		while (keepAlive->get()->Equals(true));
		procAlive->set(true);
	}
	InterfaceInfo^ info=(InterfaceInfo^)adapterList->SelectedItem;
	startListen(info->device);
}
private: System::Void stopSniffer_Click(System::Object^ sender, System::EventArgs^ e) {
	keepAlive->set(false);
	//MessageBox::Show("mainProc:keepAlive:"+keepAlive->get()->ToString());
}
private: System::Void MainForm_Load(System::Object^ sender, System::EventArgs^ e) {
}
private: System::Void dataView_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e) {
	auto items = dataView->SelectedItems;
	if (items->Count == 0) {
		descriptionText->Clear();
		payloadText->Clear();
	}
	else {
		auto item = items[0];
		descriptionText->Text = item->SubItems[4]->Text;
		payloadText->Text = item->SubItems[5]->Text;
	}
}
private: System::Void clearBtn_Click(System::Object^ sender, System::EventArgs^ e) {
	data.clear();
	dataView->Items->Clear();
}
};
