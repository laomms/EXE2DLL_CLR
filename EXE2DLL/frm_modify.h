#pragma once

namespace EXE2DLL {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	/// <summary>
	/// frm_modify 摘要
	/// </summary>
	public ref class frm_modify : public System::Windows::Forms::Form
	{
	public:	static frm_modify^ MyInstance;
	public:
		frm_modify(void)
		{
			InitializeComponent();
			MyInstance = this;
		}

	protected:
		/// <summary>
		/// 清理所有正在使用的资源。
		/// </summary>
		~frm_modify()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Label^ label1;
	public: System::Windows::Forms::TextBox^ textBox1;
	private:
	protected:

	private: System::Windows::Forms::Label^ label2;
	public: System::Windows::Forms::TextBox^ textBox2;
	private:
	public: System::Windows::Forms::TextBox^ textBox3;


	private: System::Windows::Forms::Label^ label3;
	private: System::Windows::Forms::Button^ button1;
	private: System::Windows::Forms::ToolTip^ toolTip1;
	private: System::Windows::Forms::Label^ label4;
	private: System::ComponentModel::IContainer^ components;

	private:
		/// <summary>
		/// 必需的设计器变量。
		/// </summary>


#pragma region Windows Form Designer generated code
		/// <summary>
		/// 设计器支持所需的方法 - 不要修改
		/// 使用代码编辑器修改此方法的内容。
		/// </summary>
		void InitializeComponent(void)
		{
			this->components = (gcnew System::ComponentModel::Container());
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(frm_modify::typeid));
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->textBox2 = (gcnew System::Windows::Forms::TextBox());
			this->textBox3 = (gcnew System::Windows::Forms::TextBox());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->toolTip1 = (gcnew System::Windows::Forms::ToolTip(this->components));
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->SuspendLayout();
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Location = System::Drawing::Point(4, 18);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(62, 13);
			this->label1->TabIndex = 0;
			this->label1->Text = L"FuncName:";
			// 
			// textBox1
			// 
			this->textBox1->Location = System::Drawing::Point(66, 15);
			this->textBox1->Name = L"textBox1";
			this->textBox1->Size = System::Drawing::Size(217, 20);
			this->textBox1->TabIndex = 1;
			this->textBox1->Text = L"e.g. func1  e.g. @func1@12 ";
			this->toolTip1->SetToolTip(this->textBox1, L"Input the function name.");
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Location = System::Drawing::Point(4, 44);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(56, 13);
			this->label2->TabIndex = 2;
			this->label2->Text = L"FuncAddr:";
			// 
			// textBox2
			// 
			this->textBox2->Location = System::Drawing::Point(66, 41);
			this->textBox2->Name = L"textBox2";
			this->textBox2->Size = System::Drawing::Size(217, 20);
			this->textBox2->TabIndex = 3;
			this->textBox2->Text = L"e.g.  0x00012345 (rva-base)";
			// 
			// textBox3
			// 
			this->textBox3->Location = System::Drawing::Point(66, 67);
			this->textBox3->Name = L"textBox3";
			this->textBox3->Size = System::Drawing::Size(217, 20);
			this->textBox3->TabIndex = 5;
			this->textBox3->Text = L"e.g.  .idata";
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Location = System::Drawing::Point(7, 70);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(46, 13);
			this->label3->TabIndex = 4;
			this->label3->Text = L"Section:";
			// 
			// button1
			// 
			this->button1->Location = System::Drawing::Point(109, 101);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(91, 27);
			this->button1->TabIndex = 6;
			this->button1->Text = L"OK";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &frm_modify::button1_Click);
			// 
			// label4
			// 
			this->label4->AutoSize = true;
			this->label4->Location = System::Drawing::Point(17, 143);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(271, 13);
			this->label4->TabIndex = 7;
			this->label4->Text = L"Note: For x86 fastcall name should be @name@agrnum";
			// 
			// frm_modify
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(295, 168);
			this->Controls->Add(this->label4);
			this->Controls->Add(this->button1);
			this->Controls->Add(this->textBox3);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->textBox2);
			this->Controls->Add(this->label2);
			this->Controls->Add(this->textBox1);
			this->Controls->Add(this->label1);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedToolWindow;
			this->Icon = (cli::safe_cast<System::Drawing::Icon^>(resources->GetObject(L"$this.Icon")));
			this->Name = L"frm_modify";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"Modify";
			this->Load += gcnew System::EventHandler(this, &frm_modify::frm_modify_Load);
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void frm_modify_Load(System::Object^ sender, System::EventArgs^ e) 
	{
		this->toolTip1->SetToolTip(this->textBox1, "Input the function name.");
		this->toolTip1->SetToolTip(this->textBox2, "Input the function Address." + Environment::NewLine + "You can check from IDA." );
		this->toolTip1->SetToolTip(this->textBox3, "Enter a comment for this function.");
	}
    private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e)
    {
		if (EXE2DLL::EXETODLL::FilePath == nullptr) return;
		if (textBox1->Text == "" || textBox2->Text == "") return;
		if (modifyflag == true)
		{
			int funcrva;
			sscanf((marshal_as<std::string>(textBox2->Text)).c_str(), "%x", &funcrva);
			EXETODLL::ModifyExtportFuncton(EXE2DLL::EXETODLL::FilePath, gcnew String(EXE2DLL::fun_name.c_str()), textBox1->Text, funcrva);
		}
		else
		{
			int hexNumber;
			sscanf((marshal_as<std::string>(textBox2->Text)).c_str(), "%x", &hexNumber);
			EXETODLL::AddExtportFuncton(EXE2DLL::EXETODLL::FilePath, textBox3->Text, textBox1->Text, hexNumber);
		}
		
		updatecontrol();
		this->Close();
    }
};
}
