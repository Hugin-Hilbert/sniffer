#include"utils.h"
#include"entity.h"
#include<msclr/gcroot.h>
#include<msclr/lock.h>
#pragma once
namespace Sniffer {

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
				Entity::InterfaceInfo^ info = gcnew Entity::InterfaceInfo(cur_dev);
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
	protected:


	private: System::Windows::Forms::ColumnHeader^ binary;
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
			this->binary = (gcnew System::Windows::Forms::ColumnHeader());
			this->adapterList = (gcnew System::Windows::Forms::ComboBox());
			this->stopSniffer = (gcnew System::Windows::Forms::Button());
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
			this->dataView->Columns->AddRange(gcnew cli::array< System::Windows::Forms::ColumnHeader^  >(1) { this->binary });
			this->dataView->HideSelection = false;
			this->dataView->Location = System::Drawing::Point(49, 91);
			this->dataView->Name = L"dataView";
			this->dataView->Size = System::Drawing::Size(547, 362);
			this->dataView->TabIndex = 1;
			this->dataView->UseCompatibleStateImageBehavior = false;
			this->dataView->View = System::Windows::Forms::View::Details;
			// 
			// binary
			// 
			this->binary->Text = L"binary";
			this->binary->Width = 593;
			// 
			// adapterList
			// 
			this->adapterList->DropDownStyle = System::Windows::Forms::ComboBoxStyle::DropDownList;
			this->adapterList->FormattingEnabled = true;
			this->adapterList->Location = System::Drawing::Point(49, 33);
			this->adapterList->Name = L"adapterList";
			this->adapterList->Size = System::Drawing::Size(325, 45);
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
			// MainForm
			// 
			this->ClientSize = System::Drawing::Size(772, 514);
			this->Controls->Add(this->stopSniffer);
			this->Controls->Add(this->adapterList);
			this->Controls->Add(this->dataView);
			this->Controls->Add(this->btnStartSniff);
			this->Name = L"MainForm";
			this->Text = L"Sniffer";
			this->Load += gcnew System::EventHandler(this, &MainForm::MainForm_Load);
			this->ResumeLayout(false);

		}
#pragma endregion
	void  startListen(const char* id) {
		char err[PCAP_ERRBUF_SIZE];
		pcap_t* adhandle = pcap_open(id, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, err);
		if (adhandle == NULL) {
			exit(1);
		}
		MessageBox::Show("开始监听：" + gcnew String(id));
		this->keepAlive->set(true);
		DataManager^ manager=gcnew DataManager(dataView,this->keepAlive,this->procAlive);
		auto thstart = gcnew Threading::ParameterizedThreadStart(manager, &DataManager::run);
		Threading::Thread^ th = gcnew Threading::Thread(thstart);
		th->Start((IntPtr)adhandle);
		//MessageBox::Show("监听结束");
	}
private: System::Void btnStartSniff_Click(System::Object^ sender, System::EventArgs^ e) {
	Entity::InterfaceInfo^ info=(Entity::InterfaceInfo^)adapterList->SelectedItem;
	auto id=info->id;
	startListen(id);
}
private: System::Void stopSniffer_Click(System::Object^ sender, System::EventArgs^ e) {
	keepAlive->set(false);
	//MessageBox::Show("mainProc:keepAlive:"+keepAlive->get()->ToString());
}
private: System::Void MainForm_Load(System::Object^ sender, System::EventArgs^ e) {
}
};
}

