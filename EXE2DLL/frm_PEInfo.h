#pragma once

namespace EXE2DLL {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	/// <summary>
	/// Summary for frm_PEInfo
	/// </summary>
	public ref class frm_PEInfo : public System::Windows::Forms::Form
	{
	public:
		frm_PEInfo(void)
		{
			InitializeComponent();
			//
			//TODO: Add the constructor code here
			//
		}

	protected:
		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		~frm_PEInfo()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::TextBox^ text_Entry;
	private: System::Windows::Forms::TextBox^ text_ImageBase;
	private: System::Windows::Forms::Label^ label2;
	private: System::Windows::Forms::TextBox^ text_ImageSize;
	private: System::Windows::Forms::Label^ label3;
	private: System::Windows::Forms::TextBox^ text_CodeBase;
	private: System::Windows::Forms::Label^ label4;
	private: System::Windows::Forms::TextBox^ text_DataBase;
	private: System::Windows::Forms::Label^ label5;
	private: System::Windows::Forms::TextBox^ text_SectionAlign;
	private: System::Windows::Forms::Label^ label6;
	private: System::Windows::Forms::TextBox^ text_FileAlign;
	private: System::Windows::Forms::Label^ label7;
	private: System::Windows::Forms::TextBox^ text_Magic;

	private: System::Windows::Forms::Label^ label8;
	private: System::Windows::Forms::TextBox^ text_RvaAndSizes;

	private: System::Windows::Forms::Label^ label9;
	private: System::Windows::Forms::TextBox^ text_SizeOfOptionalHeader;

	private: System::Windows::Forms::Label^ label10;
	private: System::Windows::Forms::TextBox^ text_CheckSum;

	private: System::Windows::Forms::Label^ label11;
	private: System::Windows::Forms::TextBox^ text_Characteristics;

	private: System::Windows::Forms::Label^ label12;
	private: System::Windows::Forms::TextBox^ text_HeadersSize;

	private: System::Windows::Forms::Label^ label13;
	private: System::Windows::Forms::TextBox^ text_TimeStamp;

	private: System::Windows::Forms::Label^ label14;
	private: System::Windows::Forms::TextBox^ text_SectionNumber;

	private: System::Windows::Forms::Label^ label15;
	private: System::Windows::Forms::TextBox^ text_Subsystem;

	private: System::Windows::Forms::Label^ label16;
	protected:


	private:
		/// <summary>
		/// Required designer variable.
		/// </summary>
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		void InitializeComponent(void)
		{
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(frm_PEInfo::typeid));
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->text_Entry = (gcnew System::Windows::Forms::TextBox());
			this->text_ImageBase = (gcnew System::Windows::Forms::TextBox());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->text_ImageSize = (gcnew System::Windows::Forms::TextBox());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->text_CodeBase = (gcnew System::Windows::Forms::TextBox());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->text_DataBase = (gcnew System::Windows::Forms::TextBox());
			this->label5 = (gcnew System::Windows::Forms::Label());
			this->text_SectionAlign = (gcnew System::Windows::Forms::TextBox());
			this->label6 = (gcnew System::Windows::Forms::Label());
			this->text_FileAlign = (gcnew System::Windows::Forms::TextBox());
			this->label7 = (gcnew System::Windows::Forms::Label());
			this->text_Magic = (gcnew System::Windows::Forms::TextBox());
			this->label8 = (gcnew System::Windows::Forms::Label());
			this->text_RvaAndSizes = (gcnew System::Windows::Forms::TextBox());
			this->label9 = (gcnew System::Windows::Forms::Label());
			this->text_SizeOfOptionalHeader = (gcnew System::Windows::Forms::TextBox());
			this->label10 = (gcnew System::Windows::Forms::Label());
			this->text_CheckSum = (gcnew System::Windows::Forms::TextBox());
			this->label11 = (gcnew System::Windows::Forms::Label());
			this->text_Characteristics = (gcnew System::Windows::Forms::TextBox());
			this->label12 = (gcnew System::Windows::Forms::Label());
			this->text_HeadersSize = (gcnew System::Windows::Forms::TextBox());
			this->label13 = (gcnew System::Windows::Forms::Label());
			this->text_TimeStamp = (gcnew System::Windows::Forms::TextBox());
			this->label14 = (gcnew System::Windows::Forms::Label());
			this->text_SectionNumber = (gcnew System::Windows::Forms::TextBox());
			this->label15 = (gcnew System::Windows::Forms::Label());
			this->text_Subsystem = (gcnew System::Windows::Forms::TextBox());
			this->label16 = (gcnew System::Windows::Forms::Label());
			this->SuspendLayout();
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Location = System::Drawing::Point(12, 15);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(58, 13);
			this->label1->TabIndex = 0;
			this->label1->Text = L"Entry Point";
			// 
			// text_Entry
			// 
			this->text_Entry->Location = System::Drawing::Point(86, 12);
			this->text_Entry->Name = L"text_Entry";
			this->text_Entry->Size = System::Drawing::Size(123, 20);
			this->text_Entry->TabIndex = 1;
			// 
			// text_ImageBase
			// 
			this->text_ImageBase->Location = System::Drawing::Point(86, 38);
			this->text_ImageBase->Name = L"text_ImageBase";
			this->text_ImageBase->Size = System::Drawing::Size(123, 20);
			this->text_ImageBase->TabIndex = 3;
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Location = System::Drawing::Point(12, 41);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(60, 13);
			this->label2->TabIndex = 2;
			this->label2->Text = L"ImageBase";
			// 
			// text_ImageSize
			// 
			this->text_ImageSize->Location = System::Drawing::Point(86, 64);
			this->text_ImageSize->Name = L"text_ImageSize";
			this->text_ImageSize->Size = System::Drawing::Size(123, 20);
			this->text_ImageSize->TabIndex = 5;
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Location = System::Drawing::Point(12, 67);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(56, 13);
			this->label3->TabIndex = 4;
			this->label3->Text = L"ImageSize";
			// 
			// text_CodeBase
			// 
			this->text_CodeBase->Location = System::Drawing::Point(86, 90);
			this->text_CodeBase->Name = L"text_CodeBase";
			this->text_CodeBase->Size = System::Drawing::Size(123, 20);
			this->text_CodeBase->TabIndex = 7;
			// 
			// label4
			// 
			this->label4->AutoSize = true;
			this->label4->Location = System::Drawing::Point(12, 93);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(59, 13);
			this->label4->TabIndex = 6;
			this->label4->Text = L"Code Base";
			// 
			// text_DataBase
			// 
			this->text_DataBase->Location = System::Drawing::Point(86, 116);
			this->text_DataBase->Name = L"text_DataBase";
			this->text_DataBase->Size = System::Drawing::Size(123, 20);
			this->text_DataBase->TabIndex = 9;
			// 
			// label5
			// 
			this->label5->AutoSize = true;
			this->label5->Location = System::Drawing::Point(12, 119);
			this->label5->Name = L"label5";
			this->label5->Size = System::Drawing::Size(57, 13);
			this->label5->TabIndex = 8;
			this->label5->Text = L"Data Base";
			// 
			// text_SectionAlign
			// 
			this->text_SectionAlign->Location = System::Drawing::Point(86, 142);
			this->text_SectionAlign->Name = L"text_SectionAlign";
			this->text_SectionAlign->Size = System::Drawing::Size(123, 20);
			this->text_SectionAlign->TabIndex = 11;
			// 
			// label6
			// 
			this->label6->AutoSize = true;
			this->label6->Location = System::Drawing::Point(7, 145);
			this->label6->Name = L"label6";
			this->label6->Size = System::Drawing::Size(69, 13);
			this->label6->TabIndex = 10;
			this->label6->Text = L"Section Align";
			// 
			// text_FileAlign
			// 
			this->text_FileAlign->Location = System::Drawing::Point(86, 168);
			this->text_FileAlign->Name = L"text_FileAlign";
			this->text_FileAlign->Size = System::Drawing::Size(123, 20);
			this->text_FileAlign->TabIndex = 13;
			// 
			// label7
			// 
			this->label7->AutoSize = true;
			this->label7->Location = System::Drawing::Point(14, 171);
			this->label7->Name = L"label7";
			this->label7->Size = System::Drawing::Size(49, 13);
			this->label7->TabIndex = 12;
			this->label7->Text = L"File Align";
			// 
			// text_Magic
			// 
			this->text_Magic->Location = System::Drawing::Point(86, 194);
			this->text_Magic->Name = L"text_Magic";
			this->text_Magic->Size = System::Drawing::Size(123, 20);
			this->text_Magic->TabIndex = 15;
			// 
			// label8
			// 
			this->label8->AutoSize = true;
			this->label8->Location = System::Drawing::Point(22, 197);
			this->label8->Name = L"label8";
			this->label8->Size = System::Drawing::Size(36, 13);
			this->label8->TabIndex = 14;
			this->label8->Text = L"Magic";
			// 
			// text_RvaAndSizes
			// 
			this->text_RvaAndSizes->Location = System::Drawing::Point(372, 197);
			this->text_RvaAndSizes->Name = L"text_RvaAndSizes";
			this->text_RvaAndSizes->Size = System::Drawing::Size(123, 20);
			this->text_RvaAndSizes->TabIndex = 31;
			// 
			// label9
			// 
			this->label9->AutoSize = true;
			this->label9->Location = System::Drawing::Point(283, 200);
			this->label9->Name = L"label9";
			this->label9->Size = System::Drawing::Size(71, 13);
			this->label9->TabIndex = 30;
			this->label9->Text = L"RvaAndSizes";
			// 
			// text_SizeOfOptionalHeader
			// 
			this->text_SizeOfOptionalHeader->Location = System::Drawing::Point(372, 171);
			this->text_SizeOfOptionalHeader->Name = L"text_SizeOfOptionalHeader";
			this->text_SizeOfOptionalHeader->Size = System::Drawing::Size(123, 20);
			this->text_SizeOfOptionalHeader->TabIndex = 29;
			// 
			// label10
			// 
			this->label10->AutoSize = true;
			this->label10->Location = System::Drawing::Point(263, 174);
			this->label10->Name = L"label10";
			this->label10->Size = System::Drawing::Size(104, 13);
			this->label10->TabIndex = 28;
			this->label10->Text = L"OptionalHeader Size";
			// 
			// text_CheckSum
			// 
			this->text_CheckSum->Location = System::Drawing::Point(372, 145);
			this->text_CheckSum->Name = L"text_CheckSum";
			this->text_CheckSum->Size = System::Drawing::Size(123, 20);
			this->text_CheckSum->TabIndex = 27;
			// 
			// label11
			// 
			this->label11->AutoSize = true;
			this->label11->Location = System::Drawing::Point(286, 148);
			this->label11->Name = L"label11";
			this->label11->Size = System::Drawing::Size(59, 13);
			this->label11->TabIndex = 26;
			this->label11->Text = L"CheckSum";
			// 
			// text_Characteristics
			// 
			this->text_Characteristics->Location = System::Drawing::Point(372, 119);
			this->text_Characteristics->Name = L"text_Characteristics";
			this->text_Characteristics->Size = System::Drawing::Size(123, 20);
			this->text_Characteristics->TabIndex = 25;
			// 
			// label12
			// 
			this->label12->AutoSize = true;
			this->label12->Location = System::Drawing::Point(281, 122);
			this->label12->Name = L"label12";
			this->label12->Size = System::Drawing::Size(76, 13);
			this->label12->TabIndex = 24;
			this->label12->Text = L"Characteristics";
			// 
			// text_HeadersSize
			// 
			this->text_HeadersSize->Location = System::Drawing::Point(372, 93);
			this->text_HeadersSize->Name = L"text_HeadersSize";
			this->text_HeadersSize->Size = System::Drawing::Size(123, 20);
			this->text_HeadersSize->TabIndex = 23;
			// 
			// label13
			// 
			this->label13->AutoSize = true;
			this->label13->Location = System::Drawing::Point(284, 96);
			this->label13->Name = L"label13";
			this->label13->Size = System::Drawing::Size(70, 13);
			this->label13->TabIndex = 22;
			this->label13->Text = L"Headers Size";
			// 
			// text_TimeStamp
			// 
			this->text_TimeStamp->Location = System::Drawing::Point(372, 67);
			this->text_TimeStamp->Name = L"text_TimeStamp";
			this->text_TimeStamp->Size = System::Drawing::Size(123, 20);
			this->text_TimeStamp->TabIndex = 21;
			// 
			// label14
			// 
			this->label14->AutoSize = true;
			this->label14->Location = System::Drawing::Point(291, 70);
			this->label14->Name = L"label14";
			this->label14->Size = System::Drawing::Size(60, 13);
			this->label14->TabIndex = 20;
			this->label14->Text = L"TimeStamp";
			// 
			// text_SectionNumber
			// 
			this->text_SectionNumber->Location = System::Drawing::Point(372, 41);
			this->text_SectionNumber->Name = L"text_SectionNumber";
			this->text_SectionNumber->Size = System::Drawing::Size(123, 20);
			this->text_SectionNumber->TabIndex = 19;
			// 
			// label15
			// 
			this->label15->AutoSize = true;
			this->label15->Location = System::Drawing::Point(278, 45);
			this->label15->Name = L"label15";
			this->label15->Size = System::Drawing::Size(83, 13);
			this->label15->TabIndex = 18;
			this->label15->Text = L"Section Number";
			// 
			// text_Subsystem
			// 
			this->text_Subsystem->Location = System::Drawing::Point(372, 15);
			this->text_Subsystem->Name = L"text_Subsystem";
			this->text_Subsystem->Size = System::Drawing::Size(123, 20);
			this->text_Subsystem->TabIndex = 17;
			// 
			// label16
			// 
			this->label16->AutoSize = true;
			this->label16->Location = System::Drawing::Point(291, 18);
			this->label16->Name = L"label16";
			this->label16->Size = System::Drawing::Size(58, 13);
			this->label16->TabIndex = 16;
			this->label16->Text = L"Subsystem";
			// 
			// frm_PEInfo
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(507, 233);
			this->Controls->Add(this->text_RvaAndSizes);
			this->Controls->Add(this->label9);
			this->Controls->Add(this->text_SizeOfOptionalHeader);
			this->Controls->Add(this->label10);
			this->Controls->Add(this->text_CheckSum);
			this->Controls->Add(this->label11);
			this->Controls->Add(this->text_Characteristics);
			this->Controls->Add(this->label12);
			this->Controls->Add(this->text_HeadersSize);
			this->Controls->Add(this->label13);
			this->Controls->Add(this->text_TimeStamp);
			this->Controls->Add(this->label14);
			this->Controls->Add(this->text_SectionNumber);
			this->Controls->Add(this->label15);
			this->Controls->Add(this->text_Subsystem);
			this->Controls->Add(this->label16);
			this->Controls->Add(this->text_Magic);
			this->Controls->Add(this->label8);
			this->Controls->Add(this->text_FileAlign);
			this->Controls->Add(this->label7);
			this->Controls->Add(this->text_SectionAlign);
			this->Controls->Add(this->label6);
			this->Controls->Add(this->text_DataBase);
			this->Controls->Add(this->label5);
			this->Controls->Add(this->text_CodeBase);
			this->Controls->Add(this->label4);
			this->Controls->Add(this->text_ImageSize);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->text_ImageBase);
			this->Controls->Add(this->label2);
			this->Controls->Add(this->text_Entry);
			this->Controls->Add(this->label1);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedToolWindow;
			this->Icon = (cli::safe_cast<System::Drawing::Icon^>(resources->GetObject(L"$this.Icon")));
			this->Name = L"frm_PEInfo";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"PE Info";
			this->Load += gcnew System::EventHandler(this, &frm_PEInfo::frm_PEInfo_Load);
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void frm_PEInfo_Load(System::Object^ sender, System::EventArgs^ e) 
	{
		if (PElist.size() == 0) return;
		text_Entry->Text= gcnew String(PElist[0].c_str());
		text_Subsystem->Text = gcnew String(PElist[1].c_str());
		text_ImageBase->Text = gcnew String(PElist[2].c_str());
		text_SectionNumber->Text = gcnew String(PElist[3].c_str());
		text_ImageSize->Text = gcnew String(PElist[4].c_str());
		text_TimeStamp->Text = gcnew String(PElist[5].c_str());
		text_CodeBase->Text = gcnew String(PElist[6].c_str());
		text_HeadersSize->Text = gcnew String(PElist[7].c_str());
		text_DataBase->Text = gcnew String(PElist[8].c_str());
		text_Characteristics->Text = gcnew String(PElist[9].c_str());
		text_SectionAlign->Text = gcnew String(PElist[10].c_str());
		text_CheckSum->Text = gcnew String(PElist[11].c_str());
		text_FileAlign->Text = gcnew String(PElist[12].c_str());
		text_SizeOfOptionalHeader->Text = gcnew String(PElist[13].c_str());
		text_Magic->Text = gcnew String(PElist[14].c_str());
		text_RvaAndSizes->Text = gcnew String(PElist[15].c_str());
	}
};
}
