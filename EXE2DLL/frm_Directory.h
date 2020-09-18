#pragma once

namespace EXE2DLL {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	/// <summary>
	/// frm_Directory 摘要
	/// </summary>
	public ref class frm_Directory : public System::Windows::Forms::Form
	{
	public:
		frm_Directory(void)
		{
			InitializeComponent();
			//
			//TODO:  在此处添加构造函数代码
			//
		}

	protected:
		/// <summary>
		/// 清理所有正在使用的资源。
		/// </summary>
		~frm_Directory()
		{
			if (components)
			{
				delete components;
			}
		}

	protected:
	private: System::Windows::Forms::Label^ label2;
	private: System::Windows::Forms::Label^ label3;
	private: System::Windows::Forms::TextBox^ text_EAT2;



	private: System::Windows::Forms::TextBox^ text_EAT;

	private: System::Windows::Forms::Label^ label4;
	private: System::Windows::Forms::TextBox^ text_IAT2;

	private: System::Windows::Forms::TextBox^ text_IAT;

	private: System::Windows::Forms::Label^ label5;
	private: System::Windows::Forms::TextBox^ text_Resource2;

	private: System::Windows::Forms::TextBox^ text_Resource;



	private: System::Windows::Forms::Label^ label6;
	private: System::Windows::Forms::TextBox^ text_Exception2;

	private: System::Windows::Forms::TextBox^ text_Exception;

	private: System::Windows::Forms::Label^ label7;
	private: System::Windows::Forms::TextBox^ text_Certificate2;

	private: System::Windows::Forms::TextBox^ text_Certificate;

	private: System::Windows::Forms::Label^ label8;
	private: System::Windows::Forms::TextBox^ text_Relocation2;

	private: System::Windows::Forms::TextBox^ text_Relocation;

	private: System::Windows::Forms::Label^ label9;
	private: System::Windows::Forms::TextBox^ text_Debug2;

	private: System::Windows::Forms::TextBox^ text_Debug;

	private: System::Windows::Forms::Label^ label10;
	private: System::Windows::Forms::TextBox^ text_Architecture2;

	private: System::Windows::Forms::TextBox^ text_Architecture;

	private: System::Windows::Forms::Label^ label11;
	private: System::Windows::Forms::TextBox^ text_GlobalPtr2;

	private: System::Windows::Forms::TextBox^ text_GlobalPtr;

	private: System::Windows::Forms::Label^ label12;
	private: System::Windows::Forms::TextBox^ text_TLS2;

	private: System::Windows::Forms::TextBox^ text_TLS;

	private: System::Windows::Forms::Label^ label13;
	private: System::Windows::Forms::TextBox^ text_LoadConfig2;

	private: System::Windows::Forms::TextBox^ text_LoadConfig;

	private: System::Windows::Forms::Label^ label14;
	private: System::Windows::Forms::TextBox^ text_Bound2;

	private: System::Windows::Forms::TextBox^ text_Bound;

	private: System::Windows::Forms::Label^ label15;
	private: System::Windows::Forms::TextBox^ text_Delay2;

	private: System::Windows::Forms::TextBox^ text_Delay;

	private: System::Windows::Forms::Label^ label16;
	private: System::Windows::Forms::TextBox^ text_COM2;

	private: System::Windows::Forms::TextBox^ text_COM;

	private: System::Windows::Forms::Label^ label17;
	private: System::Windows::Forms::TextBox^ text_Reserve2;

	private: System::Windows::Forms::TextBox^ text_Reserve;

	private: System::Windows::Forms::Label^ label18;

	private:
		/// <summary>
		/// 必需的设计器变量。
		/// </summary>
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// 设计器支持所需的方法 - 不要修改
		/// 使用代码编辑器修改此方法的内容。
		/// </summary>
		void InitializeComponent(void)
		{
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(frm_Directory::typeid));
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->text_EAT2 = (gcnew System::Windows::Forms::TextBox());
			this->text_EAT = (gcnew System::Windows::Forms::TextBox());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->text_IAT2 = (gcnew System::Windows::Forms::TextBox());
			this->text_IAT = (gcnew System::Windows::Forms::TextBox());
			this->label5 = (gcnew System::Windows::Forms::Label());
			this->text_Resource2 = (gcnew System::Windows::Forms::TextBox());
			this->text_Resource = (gcnew System::Windows::Forms::TextBox());
			this->label6 = (gcnew System::Windows::Forms::Label());
			this->text_Exception2 = (gcnew System::Windows::Forms::TextBox());
			this->text_Exception = (gcnew System::Windows::Forms::TextBox());
			this->label7 = (gcnew System::Windows::Forms::Label());
			this->text_Certificate2 = (gcnew System::Windows::Forms::TextBox());
			this->text_Certificate = (gcnew System::Windows::Forms::TextBox());
			this->label8 = (gcnew System::Windows::Forms::Label());
			this->text_Relocation2 = (gcnew System::Windows::Forms::TextBox());
			this->text_Relocation = (gcnew System::Windows::Forms::TextBox());
			this->label9 = (gcnew System::Windows::Forms::Label());
			this->text_Debug2 = (gcnew System::Windows::Forms::TextBox());
			this->text_Debug = (gcnew System::Windows::Forms::TextBox());
			this->label10 = (gcnew System::Windows::Forms::Label());
			this->text_Architecture2 = (gcnew System::Windows::Forms::TextBox());
			this->text_Architecture = (gcnew System::Windows::Forms::TextBox());
			this->label11 = (gcnew System::Windows::Forms::Label());
			this->text_GlobalPtr2 = (gcnew System::Windows::Forms::TextBox());
			this->text_GlobalPtr = (gcnew System::Windows::Forms::TextBox());
			this->label12 = (gcnew System::Windows::Forms::Label());
			this->text_TLS2 = (gcnew System::Windows::Forms::TextBox());
			this->text_TLS = (gcnew System::Windows::Forms::TextBox());
			this->label13 = (gcnew System::Windows::Forms::Label());
			this->text_LoadConfig2 = (gcnew System::Windows::Forms::TextBox());
			this->text_LoadConfig = (gcnew System::Windows::Forms::TextBox());
			this->label14 = (gcnew System::Windows::Forms::Label());
			this->text_Bound2 = (gcnew System::Windows::Forms::TextBox());
			this->text_Bound = (gcnew System::Windows::Forms::TextBox());
			this->label15 = (gcnew System::Windows::Forms::Label());
			this->text_Delay2 = (gcnew System::Windows::Forms::TextBox());
			this->text_Delay = (gcnew System::Windows::Forms::TextBox());
			this->label16 = (gcnew System::Windows::Forms::Label());
			this->text_COM2 = (gcnew System::Windows::Forms::TextBox());
			this->text_COM = (gcnew System::Windows::Forms::TextBox());
			this->label17 = (gcnew System::Windows::Forms::Label());
			this->text_Reserve2 = (gcnew System::Windows::Forms::TextBox());
			this->text_Reserve = (gcnew System::Windows::Forms::TextBox());
			this->label18 = (gcnew System::Windows::Forms::Label());
			this->SuspendLayout();
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Location = System::Drawing::Point(126, 14);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(29, 13);
			this->label2->TabIndex = 1;
			this->label2->Text = L"RVA";
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Location = System::Drawing::Point(234, 14);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(27, 13);
			this->label3->TabIndex = 2;
			this->label3->Text = L"Size";
			// 
			// text_EAT2
			// 
			this->text_EAT2->Location = System::Drawing::Point(199, 36);
			this->text_EAT2->Name = L"text_EAT2";
			this->text_EAT2->Size = System::Drawing::Size(97, 20);
			this->text_EAT2->TabIndex = 7;
			// 
			// text_EAT
			// 
			this->text_EAT->Location = System::Drawing::Point(96, 36);
			this->text_EAT->Name = L"text_EAT";
			this->text_EAT->Size = System::Drawing::Size(97, 20);
			this->text_EAT->TabIndex = 6;
			// 
			// label4
			// 
			this->label4->AutoSize = true;
			this->label4->Location = System::Drawing::Point(12, 39);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(67, 13);
			this->label4->TabIndex = 5;
			this->label4->Text = L"Export Table";
			// 
			// text_IAT2
			// 
			this->text_IAT2->Location = System::Drawing::Point(199, 62);
			this->text_IAT2->Name = L"text_IAT2";
			this->text_IAT2->Size = System::Drawing::Size(97, 20);
			this->text_IAT2->TabIndex = 10;
			// 
			// text_IAT
			// 
			this->text_IAT->Location = System::Drawing::Point(96, 62);
			this->text_IAT->Name = L"text_IAT";
			this->text_IAT->Size = System::Drawing::Size(97, 20);
			this->text_IAT->TabIndex = 9;
			// 
			// label5
			// 
			this->label5->AutoSize = true;
			this->label5->Location = System::Drawing::Point(16, 65);
			this->label5->Name = L"label5";
			this->label5->Size = System::Drawing::Size(66, 13);
			this->label5->TabIndex = 8;
			this->label5->Text = L"Import Table";
			// 
			// text_Resource2
			// 
			this->text_Resource2->Location = System::Drawing::Point(199, 88);
			this->text_Resource2->Name = L"text_Resource2";
			this->text_Resource2->Size = System::Drawing::Size(97, 20);
			this->text_Resource2->TabIndex = 13;
			// 
			// text_Resource
			// 
			this->text_Resource->Location = System::Drawing::Point(96, 88);
			this->text_Resource->Name = L"text_Resource";
			this->text_Resource->Size = System::Drawing::Size(97, 20);
			this->text_Resource->TabIndex = 12;
			// 
			// label6
			// 
			this->label6->AutoSize = true;
			this->label6->Location = System::Drawing::Point(16, 91);
			this->label6->Name = L"label6";
			this->label6->Size = System::Drawing::Size(53, 13);
			this->label6->TabIndex = 11;
			this->label6->Text = L"Resource";
			// 
			// text_Exception2
			// 
			this->text_Exception2->Location = System::Drawing::Point(199, 114);
			this->text_Exception2->Name = L"text_Exception2";
			this->text_Exception2->Size = System::Drawing::Size(97, 20);
			this->text_Exception2->TabIndex = 16;
			// 
			// text_Exception
			// 
			this->text_Exception->Location = System::Drawing::Point(96, 114);
			this->text_Exception->Name = L"text_Exception";
			this->text_Exception->Size = System::Drawing::Size(97, 20);
			this->text_Exception->TabIndex = 15;
			// 
			// label7
			// 
			this->label7->AutoSize = true;
			this->label7->Location = System::Drawing::Point(16, 117);
			this->label7->Name = L"label7";
			this->label7->Size = System::Drawing::Size(54, 13);
			this->label7->TabIndex = 14;
			this->label7->Text = L"Exception";
			// 
			// text_Certificate2
			// 
			this->text_Certificate2->Location = System::Drawing::Point(199, 140);
			this->text_Certificate2->Name = L"text_Certificate2";
			this->text_Certificate2->Size = System::Drawing::Size(97, 20);
			this->text_Certificate2->TabIndex = 19;
			// 
			// text_Certificate
			// 
			this->text_Certificate->Location = System::Drawing::Point(96, 140);
			this->text_Certificate->Name = L"text_Certificate";
			this->text_Certificate->Size = System::Drawing::Size(97, 20);
			this->text_Certificate->TabIndex = 18;
			// 
			// label8
			// 
			this->label8->AutoSize = true;
			this->label8->Location = System::Drawing::Point(16, 143);
			this->label8->Name = L"label8";
			this->label8->Size = System::Drawing::Size(54, 13);
			this->label8->TabIndex = 17;
			this->label8->Text = L"Certificate";
			// 
			// text_Relocation2
			// 
			this->text_Relocation2->Location = System::Drawing::Point(199, 166);
			this->text_Relocation2->Name = L"text_Relocation2";
			this->text_Relocation2->Size = System::Drawing::Size(97, 20);
			this->text_Relocation2->TabIndex = 22;
			// 
			// text_Relocation
			// 
			this->text_Relocation->Location = System::Drawing::Point(96, 166);
			this->text_Relocation->Name = L"text_Relocation";
			this->text_Relocation->Size = System::Drawing::Size(97, 20);
			this->text_Relocation->TabIndex = 21;
			// 
			// label9
			// 
			this->label9->AutoSize = true;
			this->label9->Location = System::Drawing::Point(12, 169);
			this->label9->Name = L"label9";
			this->label9->Size = System::Drawing::Size(58, 13);
			this->label9->TabIndex = 20;
			this->label9->Text = L"Relocation";
			// 
			// text_Debug2
			// 
			this->text_Debug2->Location = System::Drawing::Point(199, 192);
			this->text_Debug2->Name = L"text_Debug2";
			this->text_Debug2->Size = System::Drawing::Size(97, 20);
			this->text_Debug2->TabIndex = 25;
			// 
			// text_Debug
			// 
			this->text_Debug->Location = System::Drawing::Point(96, 192);
			this->text_Debug->Name = L"text_Debug";
			this->text_Debug->Size = System::Drawing::Size(97, 20);
			this->text_Debug->TabIndex = 24;
			// 
			// label10
			// 
			this->label10->AutoSize = true;
			this->label10->Location = System::Drawing::Point(22, 195);
			this->label10->Name = L"label10";
			this->label10->Size = System::Drawing::Size(39, 13);
			this->label10->TabIndex = 23;
			this->label10->Text = L"Debug";
			// 
			// text_Architecture2
			// 
			this->text_Architecture2->Location = System::Drawing::Point(199, 218);
			this->text_Architecture2->Name = L"text_Architecture2";
			this->text_Architecture2->Size = System::Drawing::Size(97, 20);
			this->text_Architecture2->TabIndex = 28;
			// 
			// text_Architecture
			// 
			this->text_Architecture->Location = System::Drawing::Point(96, 218);
			this->text_Architecture->Name = L"text_Architecture";
			this->text_Architecture->Size = System::Drawing::Size(97, 20);
			this->text_Architecture->TabIndex = 27;
			// 
			// label11
			// 
			this->label11->AutoSize = true;
			this->label11->Location = System::Drawing::Point(12, 221);
			this->label11->Name = L"label11";
			this->label11->Size = System::Drawing::Size(64, 13);
			this->label11->TabIndex = 26;
			this->label11->Text = L"Architecture";
			// 
			// text_GlobalPtr2
			// 
			this->text_GlobalPtr2->Location = System::Drawing::Point(199, 244);
			this->text_GlobalPtr2->Name = L"text_GlobalPtr2";
			this->text_GlobalPtr2->Size = System::Drawing::Size(97, 20);
			this->text_GlobalPtr2->TabIndex = 31;
			// 
			// text_GlobalPtr
			// 
			this->text_GlobalPtr->Location = System::Drawing::Point(96, 244);
			this->text_GlobalPtr->Name = L"text_GlobalPtr";
			this->text_GlobalPtr->Size = System::Drawing::Size(97, 20);
			this->text_GlobalPtr->TabIndex = 30;
			// 
			// label12
			// 
			this->label12->AutoSize = true;
			this->label12->Location = System::Drawing::Point(19, 247);
			this->label12->Name = L"label12";
			this->label12->Size = System::Drawing::Size(50, 13);
			this->label12->TabIndex = 29;
			this->label12->Text = L"GlobalPtr";
			// 
			// text_TLS2
			// 
			this->text_TLS2->Location = System::Drawing::Point(199, 270);
			this->text_TLS2->Name = L"text_TLS2";
			this->text_TLS2->Size = System::Drawing::Size(97, 20);
			this->text_TLS2->TabIndex = 34;
			// 
			// text_TLS
			// 
			this->text_TLS->Location = System::Drawing::Point(96, 270);
			this->text_TLS->Name = L"text_TLS";
			this->text_TLS->Size = System::Drawing::Size(97, 20);
			this->text_TLS->TabIndex = 33;
			// 
			// label13
			// 
			this->label13->AutoSize = true;
			this->label13->Location = System::Drawing::Point(13, 273);
			this->label13->Name = L"label13";
			this->label13->Size = System::Drawing::Size(57, 13);
			this->label13->TabIndex = 32;
			this->label13->Text = L"TLS Table";
			// 
			// text_LoadConfig2
			// 
			this->text_LoadConfig2->Location = System::Drawing::Point(199, 296);
			this->text_LoadConfig2->Name = L"text_LoadConfig2";
			this->text_LoadConfig2->Size = System::Drawing::Size(97, 20);
			this->text_LoadConfig2->TabIndex = 37;
			// 
			// text_LoadConfig
			// 
			this->text_LoadConfig->Location = System::Drawing::Point(96, 296);
			this->text_LoadConfig->Name = L"text_LoadConfig";
			this->text_LoadConfig->Size = System::Drawing::Size(97, 20);
			this->text_LoadConfig->TabIndex = 36;
			// 
			// label14
			// 
			this->label14->AutoSize = true;
			this->label14->Location = System::Drawing::Point(13, 299);
			this->label14->Name = L"label14";
			this->label14->Size = System::Drawing::Size(61, 13);
			this->label14->TabIndex = 35;
			this->label14->Text = L"LoadConfig";
			// 
			// text_Bound2
			// 
			this->text_Bound2->Location = System::Drawing::Point(199, 322);
			this->text_Bound2->Name = L"text_Bound2";
			this->text_Bound2->Size = System::Drawing::Size(97, 20);
			this->text_Bound2->TabIndex = 40;
			// 
			// text_Bound
			// 
			this->text_Bound->Location = System::Drawing::Point(96, 322);
			this->text_Bound->Name = L"text_Bound";
			this->text_Bound->Size = System::Drawing::Size(97, 20);
			this->text_Bound->TabIndex = 39;
			// 
			// label15
			// 
			this->label15->AutoSize = true;
			this->label15->Location = System::Drawing::Point(10, 325);
			this->label15->Name = L"label15";
			this->label15->Size = System::Drawing::Size(67, 13);
			this->label15->TabIndex = 38;
			this->label15->Text = L"BoundImport";
			// 
			// text_Delay2
			// 
			this->text_Delay2->Location = System::Drawing::Point(199, 348);
			this->text_Delay2->Name = L"text_Delay2";
			this->text_Delay2->Size = System::Drawing::Size(97, 20);
			this->text_Delay2->TabIndex = 43;
			// 
			// text_Delay
			// 
			this->text_Delay->Location = System::Drawing::Point(96, 348);
			this->text_Delay->Name = L"text_Delay";
			this->text_Delay->Size = System::Drawing::Size(97, 20);
			this->text_Delay->TabIndex = 42;
			// 
			// label16
			// 
			this->label16->AutoSize = true;
			this->label16->Location = System::Drawing::Point(11, 351);
			this->label16->Name = L"label16";
			this->label16->Size = System::Drawing::Size(63, 13);
			this->label16->TabIndex = 41;
			this->label16->Text = L"DelayImport";
			// 
			// text_COM2
			// 
			this->text_COM2->Location = System::Drawing::Point(199, 374);
			this->text_COM2->Name = L"text_COM2";
			this->text_COM2->Size = System::Drawing::Size(97, 20);
			this->text_COM2->TabIndex = 46;
			// 
			// text_COM
			// 
			this->text_COM->Location = System::Drawing::Point(96, 374);
			this->text_COM->Name = L"text_COM";
			this->text_COM->Size = System::Drawing::Size(97, 20);
			this->text_COM->TabIndex = 45;
			// 
			// label17
			// 
			this->label17->AutoSize = true;
			this->label17->Location = System::Drawing::Point(22, 377);
			this->label17->Name = L"label17";
			this->label17->Size = System::Drawing::Size(31, 13);
			this->label17->TabIndex = 44;
			this->label17->Text = L"COM";
			// 
			// text_Reserve2
			// 
			this->text_Reserve2->Location = System::Drawing::Point(199, 400);
			this->text_Reserve2->Name = L"text_Reserve2";
			this->text_Reserve2->Size = System::Drawing::Size(97, 20);
			this->text_Reserve2->TabIndex = 49;
			// 
			// text_Reserve
			// 
			this->text_Reserve->Location = System::Drawing::Point(96, 400);
			this->text_Reserve->Name = L"text_Reserve";
			this->text_Reserve->Size = System::Drawing::Size(97, 20);
			this->text_Reserve->TabIndex = 48;
			// 
			// label18
			// 
			this->label18->AutoSize = true;
			this->label18->Location = System::Drawing::Point(16, 403);
			this->label18->Name = L"label18";
			this->label18->Size = System::Drawing::Size(47, 13);
			this->label18->TabIndex = 47;
			this->label18->Text = L"Reserve";
			// 
			// frm_Directory
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(321, 436);
			this->Controls->Add(this->text_Reserve2);
			this->Controls->Add(this->text_Reserve);
			this->Controls->Add(this->label18);
			this->Controls->Add(this->text_COM2);
			this->Controls->Add(this->text_COM);
			this->Controls->Add(this->label17);
			this->Controls->Add(this->text_Delay2);
			this->Controls->Add(this->text_Delay);
			this->Controls->Add(this->label16);
			this->Controls->Add(this->text_Bound2);
			this->Controls->Add(this->text_Bound);
			this->Controls->Add(this->label15);
			this->Controls->Add(this->text_LoadConfig2);
			this->Controls->Add(this->text_LoadConfig);
			this->Controls->Add(this->label14);
			this->Controls->Add(this->text_TLS2);
			this->Controls->Add(this->text_TLS);
			this->Controls->Add(this->label13);
			this->Controls->Add(this->text_GlobalPtr2);
			this->Controls->Add(this->text_GlobalPtr);
			this->Controls->Add(this->label12);
			this->Controls->Add(this->text_Architecture2);
			this->Controls->Add(this->text_Architecture);
			this->Controls->Add(this->label11);
			this->Controls->Add(this->text_Debug2);
			this->Controls->Add(this->text_Debug);
			this->Controls->Add(this->label10);
			this->Controls->Add(this->text_Relocation2);
			this->Controls->Add(this->text_Relocation);
			this->Controls->Add(this->label9);
			this->Controls->Add(this->text_Certificate2);
			this->Controls->Add(this->text_Certificate);
			this->Controls->Add(this->label8);
			this->Controls->Add(this->text_Exception2);
			this->Controls->Add(this->text_Exception);
			this->Controls->Add(this->label7);
			this->Controls->Add(this->text_Resource2);
			this->Controls->Add(this->text_Resource);
			this->Controls->Add(this->label6);
			this->Controls->Add(this->text_IAT2);
			this->Controls->Add(this->text_IAT);
			this->Controls->Add(this->label5);
			this->Controls->Add(this->text_EAT2);
			this->Controls->Add(this->text_EAT);
			this->Controls->Add(this->label4);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->label2);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedToolWindow;
			this->Icon = (cli::safe_cast<System::Drawing::Icon^>(resources->GetObject(L"$this.Icon")));
			this->Name = L"frm_Directory";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"DataDirectory List";
			this->Load += gcnew System::EventHandler(this, &frm_Directory::frm_Directory_Load);
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void frm_Directory_Load(System::Object^ sender, System::EventArgs^ e) 
	{
		if (DataDirectory.size() == 0) return;
		text_EAT->Text = (gcnew String(DataDirectory[0].c_str()))->Split('#')[0]->ToString();
		text_EAT2->Text = (gcnew String(DataDirectory[0].c_str()))->Split('#')[1]->ToString();
		text_IAT->Text = (gcnew String(DataDirectory[1].c_str()))->Split('#')[0]->ToString();
		text_IAT2->Text = (gcnew String(DataDirectory[1].c_str()))->Split('#')[1]->ToString();
		text_Resource->Text = (gcnew String(DataDirectory[2].c_str()))->Split('#')[0]->ToString();
		text_Resource2->Text = (gcnew String(DataDirectory[2].c_str()))->Split('#')[1]->ToString();
		text_Exception->Text = (gcnew String(DataDirectory[3].c_str()))->Split('#')[0]->ToString();
		text_Exception2->Text = (gcnew String(DataDirectory[3].c_str()))->Split('#')[1]->ToString();
		text_Certificate->Text = (gcnew String(DataDirectory[4].c_str()))->Split('#')[0]->ToString();
		text_Certificate2->Text = (gcnew String(DataDirectory[4].c_str()))->Split('#')[1]->ToString();
		text_Relocation->Text = (gcnew String(DataDirectory[5].c_str()))->Split('#')[0]->ToString();
		text_Relocation2->Text = (gcnew String(DataDirectory[5].c_str()))->Split('#')[1]->ToString();
		text_Debug->Text = (gcnew String(DataDirectory[6].c_str()))->Split('#')[0]->ToString();
		text_Debug2->Text = (gcnew String(DataDirectory[6].c_str()))->Split('#')[1]->ToString();
		text_Architecture->Text = (gcnew String(DataDirectory[7].c_str()))->Split('#')[0]->ToString();
		text_Architecture2->Text = (gcnew String(DataDirectory[7].c_str()))->Split('#')[1]->ToString();
		text_GlobalPtr->Text = (gcnew String(DataDirectory[8].c_str()))->Split('#')[0]->ToString();
		text_GlobalPtr2->Text = (gcnew String(DataDirectory[8].c_str()))->Split('#')[1]->ToString();
		text_TLS->Text = (gcnew String(DataDirectory[9].c_str()))->Split('#')[0]->ToString();
		text_TLS2->Text = (gcnew String(DataDirectory[9].c_str()))->Split('#')[1]->ToString();
		text_LoadConfig->Text = (gcnew String(DataDirectory[10].c_str()))->Split('#')[0]->ToString();
		text_LoadConfig2->Text = (gcnew String(DataDirectory[10].c_str()))->Split('#')[1]->ToString();
		text_Bound->Text = (gcnew String(DataDirectory[11].c_str()))->Split('#')[0]->ToString();
		text_Bound2->Text = (gcnew String(DataDirectory[11].c_str()))->Split('#')[1]->ToString();
		text_Delay->Text = (gcnew String(DataDirectory[12].c_str()))->Split('#')[0]->ToString();
		text_Delay2->Text = (gcnew String(DataDirectory[12].c_str()))->Split('#')[1]->ToString();
		text_COM->Text = (gcnew String(DataDirectory[13].c_str()))->Split('#')[0]->ToString();
		text_COM2->Text = (gcnew String(DataDirectory[13].c_str()))->Split('#')[1]->ToString();
		text_Reserve->Text = (gcnew String(DataDirectory[14].c_str()))->Split('#')[0]->ToString();
		text_Reserve2->Text = (gcnew String(DataDirectory[14].c_str()))->Split('#')[1]->ToString();

	}
};
}
