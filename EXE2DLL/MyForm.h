#pragma once
//#pragma comment(lib, "shell32.lib")
//#pragma comment(lib, "user32.lib")
//#using <mscorlib.dll>
#include <windows.h>
#include <shellapi.h>
#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>
#include "frm_Section.h"
#include "frm_modify.h"
#include "add_export_function.h"
#include "EXE2DLL.h"
#include "PE_INFO.h"
#include "frm_PEInfo.h"
#include "frm_Directory.h"
#include "ExeToDll.h"



namespace EXE2DLL 
{

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace msclr::interop;
	using namespace System::Net;
	using namespace System::Threading;
	using namespace System::IO;
	using namespace msclr::interop;
	using namespace System::Runtime::InteropServices;

	/// <summary>
	/// Summary for MyForm
	/// </summary>


    public ref class MyForm : public System::Windows::Forms::Form
	{
	
	
	public:
		static MyForm^ TheInstance;
		MyForm(void)
		{
			InitializeComponent();
			TheInstance = this;
		}

	protected:
		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		~MyForm()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Button^ button1;
	public: System::Windows::Forms::TextBox^ textBox1;
	private:
	protected:


	private: System::Windows::Forms::GroupBox^ groupBox1;
	private: System::Windows::Forms::Button^ button2;
	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::OpenFileDialog^ openFileDialog1;
	private: System::Windows::Forms::ContextMenuStrip^ contextMenuStrip1;



	private: System::Windows::Forms::ToolTip^ toolTip1;

	private: System::Windows::Forms::TabControl^ tabControl1;
	private: System::Windows::Forms::TabPage^ tabPage1;
	private: System::Windows::Forms::TabPage^ tabPage2;
	private: System::Windows::Forms::ListView^ listView1;

	private: System::Windows::Forms::ListView^ listView2;
	private: System::Windows::Forms::ContextMenuStrip^ contextMenuStrip2;
	private: System::Windows::Forms::ToolStripMenuItem^ AddSectionMenu;
	private: System::Windows::Forms::ToolStripMenuItem^ AddExporFuncMenuI;
	private: System::Windows::Forms::ToolStripMenuItem^ ModifyExportFuncMenu;
	private: System::Windows::Forms::ToolStripMenuItem^ DeletExoprtFuncMenu;
	private: System::Windows::Forms::ToolStripMenuItem^ pEInfoMenu;
	private: System::Windows::Forms::ToolStripMenuItem^ dataDirectoryMenu;
	private: System::Windows::Forms::SaveFileDialog^ saveFileDialog1;










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
			this->components = (gcnew System::ComponentModel::Container());
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(MyForm::typeid));
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->contextMenuStrip1 = (gcnew System::Windows::Forms::ContextMenuStrip(this->components));
			this->pEInfoMenu = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->dataDirectoryMenu = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->groupBox1 = (gcnew System::Windows::Forms::GroupBox());
			this->button2 = (gcnew System::Windows::Forms::Button());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->openFileDialog1 = (gcnew System::Windows::Forms::OpenFileDialog());
			this->toolTip1 = (gcnew System::Windows::Forms::ToolTip(this->components));
			this->tabControl1 = (gcnew System::Windows::Forms::TabControl());
			this->tabPage1 = (gcnew System::Windows::Forms::TabPage());
			this->listView1 = (gcnew System::Windows::Forms::ListView());
			this->tabPage2 = (gcnew System::Windows::Forms::TabPage());
			this->listView2 = (gcnew System::Windows::Forms::ListView());
			this->contextMenuStrip2 = (gcnew System::Windows::Forms::ContextMenuStrip(this->components));
			this->AddSectionMenu = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->AddExporFuncMenuI = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->ModifyExportFuncMenu = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->DeletExoprtFuncMenu = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->saveFileDialog1 = (gcnew System::Windows::Forms::SaveFileDialog());
			this->contextMenuStrip1->SuspendLayout();
			this->groupBox1->SuspendLayout();
			this->tabControl1->SuspendLayout();
			this->tabPage1->SuspendLayout();
			this->tabPage2->SuspendLayout();
			this->contextMenuStrip2->SuspendLayout();
			this->SuspendLayout();
			// 
			// button1
			// 
			this->button1->Location = System::Drawing::Point(460, 13);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(58, 29);
			this->button1->TabIndex = 0;
			this->button1->Text = L"Open";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &MyForm::button1_Click);
			// 
			// textBox1
			// 
			this->textBox1->Location = System::Drawing::Point(10, 18);
			this->textBox1->Name = L"textBox1";
			this->textBox1->Size = System::Drawing::Size(441, 20);
			this->textBox1->TabIndex = 1;
			this->textBox1->Text = L"Drag or Open Exe File";
			this->textBox1->DragEnter += gcnew System::Windows::Forms::DragEventHandler(this, &MyForm::textBox1_DragEnter);
			// 
			// contextMenuStrip1
			// 
			this->contextMenuStrip1->Items->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(2) {
				this->pEInfoMenu,
					this->dataDirectoryMenu
			});
			this->contextMenuStrip1->Name = L"contextMenuStrip1";
			this->contextMenuStrip1->Size = System::Drawing::Size(168, 48);
			// 
			// pEInfoMenu
			// 
			this->pEInfoMenu->Name = L"pEInfoMenu";
			this->pEInfoMenu->Size = System::Drawing::Size(167, 22);
			this->pEInfoMenu->Text = L"PE Info";
			this->pEInfoMenu->Click += gcnew System::EventHandler(this, &MyForm::pEInfoMenu_Click);
			// 
			// dataDirectoryMenu
			// 
			this->dataDirectoryMenu->Name = L"dataDirectoryMenu";
			this->dataDirectoryMenu->Size = System::Drawing::Size(167, 22);
			this->dataDirectoryMenu->Text = L"DataDirectory List";
			this->dataDirectoryMenu->Click += gcnew System::EventHandler(this, &MyForm::dataDirectoryMenu_Click);
			// 
			// groupBox1
			// 
			this->groupBox1->Controls->Add(this->button2);
			this->groupBox1->Controls->Add(this->textBox1);
			this->groupBox1->Controls->Add(this->button1);
			this->groupBox1->Location = System::Drawing::Point(6, 1);
			this->groupBox1->Name = L"groupBox1";
			this->groupBox1->Size = System::Drawing::Size(594, 48);
			this->groupBox1->TabIndex = 3;
			this->groupBox1->TabStop = false;
			// 
			// button2
			// 
			this->button2->Location = System::Drawing::Point(527, 13);
			this->button2->Name = L"button2";
			this->button2->Size = System::Drawing::Size(58, 29);
			this->button2->TabIndex = 2;
			this->button2->Text = L"Save";
			this->button2->UseVisualStyleBackColor = true;
			this->button2->Click += gcnew System::EventHandler(this, &MyForm::button2_Click);
			// 
			// label1
			// 
			this->label1->Location = System::Drawing::Point(7, 256);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(592, 32);
			this->label1->TabIndex = 4;
			this->label1->Text = L"Right click operation export table";
			this->label1->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;
			// 
			// openFileDialog1
			// 
			this->openFileDialog1->FileName = L"openFileDialog1";
			// 
			// tabControl1
			// 
			this->tabControl1->Controls->Add(this->tabPage1);
			this->tabControl1->Controls->Add(this->tabPage2);
			this->tabControl1->Location = System::Drawing::Point(6, 55);
			this->tabControl1->Name = L"tabControl1";
			this->tabControl1->SelectedIndex = 0;
			this->tabControl1->Size = System::Drawing::Size(593, 206);
			this->tabControl1->TabIndex = 3;
			// 
			// tabPage1
			// 
			this->tabPage1->Controls->Add(this->listView1);
			this->tabPage1->Location = System::Drawing::Point(4, 22);
			this->tabPage1->Name = L"tabPage1";
			this->tabPage1->Padding = System::Windows::Forms::Padding(3);
			this->tabPage1->Size = System::Drawing::Size(585, 180);
			this->tabPage1->TabIndex = 0;
			this->tabPage1->Text = L"Section List";
			this->tabPage1->UseVisualStyleBackColor = true;
			// 
			// listView1
			// 
			this->listView1->ContextMenuStrip = this->contextMenuStrip1;
			this->listView1->FullRowSelect = true;
			this->listView1->GridLines = true;
			this->listView1->HideSelection = false;
			this->listView1->Location = System::Drawing::Point(1, 2);
			this->listView1->Name = L"listView1";
			this->listView1->Size = System::Drawing::Size(589, 178);
			this->listView1->TabIndex = 4;
			this->listView1->UseCompatibleStateImageBehavior = false;
			// 
			// tabPage2
			// 
			this->tabPage2->Controls->Add(this->listView2);
			this->tabPage2->Location = System::Drawing::Point(4, 22);
			this->tabPage2->Name = L"tabPage2";
			this->tabPage2->Padding = System::Windows::Forms::Padding(3);
			this->tabPage2->Size = System::Drawing::Size(585, 180);
			this->tabPage2->TabIndex = 1;
			this->tabPage2->Text = L"Export List";
			this->tabPage2->UseVisualStyleBackColor = true;
			// 
			// listView2
			// 
			this->listView2->ContextMenuStrip = this->contextMenuStrip2;
			this->listView2->FullRowSelect = true;
			this->listView2->GridLines = true;
			this->listView2->HideSelection = false;
			this->listView2->Location = System::Drawing::Point(1, 2);
			this->listView2->Name = L"listView2";
			this->listView2->Size = System::Drawing::Size(589, 177);
			this->listView2->TabIndex = 3;
			this->listView2->UseCompatibleStateImageBehavior = false;
			// 
			// contextMenuStrip2
			// 
			this->contextMenuStrip2->Items->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(4) {
				this->AddSectionMenu,
					this->AddExporFuncMenuI, this->ModifyExportFuncMenu, this->DeletExoprtFuncMenu
			});
			this->contextMenuStrip2->Name = L"contextMenuStrip1";
			this->contextMenuStrip2->Size = System::Drawing::Size(173, 92);
			// 
			// AddSectionMenu
			// 
			this->AddSectionMenu->Name = L"AddSectionMenu";
			this->AddSectionMenu->Size = System::Drawing::Size(172, 22);
			this->AddSectionMenu->Text = L"AddSection";
			this->AddSectionMenu->Click += gcnew System::EventHandler(this, &MyForm::toolStripMenuItem1_Click);
			// 
			// AddExporFuncMenuI
			// 
			this->AddExporFuncMenuI->Name = L"AddExporFuncMenuI";
			this->AddExporFuncMenuI->Size = System::Drawing::Size(172, 22);
			this->AddExporFuncMenuI->Text = L"AddExporFunc";
			this->AddExporFuncMenuI->Click += gcnew System::EventHandler(this, &MyForm::AddExporFuncMenuI_Click);
			// 
			// ModifyExportFuncMenu
			// 
			this->ModifyExportFuncMenu->Name = L"ModifyExportFuncMenu";
			this->ModifyExportFuncMenu->Size = System::Drawing::Size(172, 22);
			this->ModifyExportFuncMenu->Text = L"ModifyExportFunc";
			// 
			// DeletExoprtFuncMenu
			// 
			this->DeletExoprtFuncMenu->Name = L"DeletExoprtFuncMenu";
			this->DeletExoprtFuncMenu->Size = System::Drawing::Size(172, 22);
			this->DeletExoprtFuncMenu->Text = L"DeletExoprtFunc";
			// 
			// MyForm
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(612, 290);
			this->Controls->Add(this->tabControl1);
			this->Controls->Add(this->label1);
			this->Controls->Add(this->groupBox1);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedToolWindow;
			this->Icon = (cli::safe_cast<System::Drawing::Icon^>(resources->GetObject(L"$this.Icon")));
			this->Name = L"MyForm";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"EXE2DLL ";
			this->Load += gcnew System::EventHandler(this, &MyForm::MyForm_Load);
			this->contextMenuStrip1->ResumeLayout(false);
			this->groupBox1->ResumeLayout(false);
			this->groupBox1->PerformLayout();
			this->tabControl1->ResumeLayout(false);
			this->tabPage1->ResumeLayout(false);
			this->tabPage2->ResumeLayout(false);
			this->contextMenuStrip2->ResumeLayout(false);
			this->ResumeLayout(false);

		}
#pragma endregion
		
	private: System::Void MyForm_Load(System::Object^ sender, System::EventArgs^ e)
	{
		this->AllowDrop = true;
		this->textBox1->AllowDrop = true;
		this->listView1->View = View::Details;
		this->listView1->Columns->Add("NO.", 40, HorizontalAlignment::Center);
		this->listView1->Columns->Add("Name", 60, HorizontalAlignment::Center);
		this->listView1->Columns->Add("RawAddr", 100, HorizontalAlignment::Center);
		this->listView1->Columns->Add("RawSize",100, HorizontalAlignment::Center);
		this->listView1->Columns->Add("VirtualAddr", 100, HorizontalAlignment::Center);
		this->listView1->Columns->Add("VirtualSize", 100, HorizontalAlignment::Center);
		this->listView1->Columns->Add("Characteristics", 90, HorizontalAlignment::Center);


		this->listView2->View = View::Details;
		this->listView2->Columns->Add("NO.", 40, HorizontalAlignment::Center);
		this->listView2->Columns->Add("FuncRVA.", 150, HorizontalAlignment::Center);
		this->listView2->Columns->Add("FuncName", 200, HorizontalAlignment::Center);
		this->listView2->Columns->Add("Comment", this->listView1->Width - 200 - 150 - 40 - 5, HorizontalAlignment::Center);
	}

	private: System::Void textBox1_DragEnter(System::Object^ sender, System::Windows::Forms::DragEventArgs^ e)
	{
		cli::array<System::String^>^ items = (cli::array<System::String^>^)e->Data->GetData(DataFormats::FileDrop);
		
		if (items->Length > 0)
		{
			textBox1->Text = Convert::ToString(((cli::array<System::String^>^)e->Data->GetData(DataFormats::FileDrop))[0]);
			EXE2DLL::EXETODLL::FilePath = textBox1->Text;

			PElist.clear();
			DataDirectory.clear();
			Sectionlist.clear();
			funlist.clear();


			int hRes = GetPeInfo((const char*)(void*)Marshal::StringToHGlobalAnsi(textBox1->Text), PElist, DataDirectory, Sectionlist);
			if (hRes == 0)
			{
				this->listView1->Items->Clear();
				this->listView1->BeginUpdate();
				for (int i = 0; i < Sectionlist.size(); ++i)
				{
					String^ str = gcnew String(Sectionlist[i].c_str());
					ListViewItem^ lvi = gcnew ListViewItem();
					lvi->Text = (i + 1).ToString();
					lvi->SubItems->Add(str->Split('@')[0]->ToString());
					lvi->SubItems->Add(str->Split('@')[1]->ToString());
					lvi->SubItems->Add(str->Split('@')[2]->ToString());
					lvi->SubItems->Add(str->Split('@')[3]->ToString());
					lvi->SubItems->Add(str->Split('@')[4]->ToString());
					lvi->SubItems->Add(str->Split('@')[5]->ToString());
					listView1->Items->Add(lvi);
				}
				this->listView1->EndUpdate();
			}

			int res = GetExpTableList((const char*)(void*)Marshal::StringToHGlobalAnsi(textBox1->Text), funlist);
			if (res == 0)			{
				this->listView2->Items->Clear();
				this->listView2->BeginUpdate();
				for (int i = 0; i < funlist.size(); ++i)
				{
					String^ str = gcnew String(funlist[i].c_str());
					ListViewItem^ lvi = gcnew ListViewItem();
					lvi->Text = (i+1).ToString();
					lvi->SubItems->Add(str->Split('@')[0]->ToString());
					lvi->SubItems->Add(str->Split('@')[1]->ToString());
					listView2->Items->Add(lvi);
				}
				this->listView2->EndUpdate();
			}
		}
	}


	private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e)
	{
		Stream^ myStream;
		OpenFileDialog^ openFileDialog1 = gcnew OpenFileDialog;

		openFileDialog1->InitialDirectory = Application::StartupPath;
		openFileDialog1->Filter = "exe files (*.exe)|*.exe|All files (*.*)|*.*";
		openFileDialog1->FilterIndex = 2;
		openFileDialog1->RestoreDirectory = true;

		if (openFileDialog1->ShowDialog() == System::Windows::Forms::DialogResult::OK)
		{
			textBox1->Text = openFileDialog1->FileName;
			EXE2DLL::EXETODLL::FilePath= openFileDialog1->FileName;			
			std::string filepath = marshal_as<std::string>(textBox1->Text);

			PElist.clear();
			DataDirectory.clear();
			Sectionlist.clear();
			funlist.clear();
			
			int hRes=GetPeInfo((const char*)(void*)Marshal::StringToHGlobalAnsi(textBox1->Text), PElist, DataDirectory,  Sectionlist);
			if (hRes == 0)
			{

				this->listView1->Items->Clear();
				this->listView1->BeginUpdate();
				for (int i = 0; i < Sectionlist.size(); ++i)
				{
					String^ str = gcnew String(Sectionlist[i].c_str());
					ListViewItem^ lvi = gcnew ListViewItem();
					lvi->Text = (i + 1).ToString();
					lvi->SubItems->Add(str->Split('@')[0]->ToString());
					lvi->SubItems->Add(str->Split('@')[1]->ToString());
					lvi->SubItems->Add(str->Split('@')[2]->ToString());
					lvi->SubItems->Add(str->Split('@')[3]->ToString());
					lvi->SubItems->Add(str->Split('@')[4]->ToString());
					lvi->SubItems->Add(str->Split('@')[5]->ToString());
					listView1->Items->Add(lvi);
				}
				this->listView1->EndUpdate();
			}
			
			int res= GetExpTableList((const char*)(void*)Marshal::StringToHGlobalAnsi(textBox1->Text), funlist);
			if (res == 0)
			{
				this->listView2->Items->Clear();
				this->listView2->BeginUpdate();
				for (int i = 0; i < funlist.size(); ++i)
				{
					String^ str = gcnew String(funlist[i].c_str());
					ListViewItem^ lvi = gcnew ListViewItem();
					lvi->Text = (i + 1).ToString();
					lvi->SubItems->Add(str->Split('@')[0]->ToString());
					lvi->SubItems->Add(str->Split('@')[1]->ToString());
					listView2->Items->Add(lvi);
				}
				this->listView2->EndUpdate();
			}
		}
	}
	private: System::Void toolStripMenuItem1_Click(System::Object^ sender, System::EventArgs^ e)
	{
		frm_section^ stForm = gcnew frm_section;
		stForm->Show();
	}

	private: System::Void AddExporFuncMenuI_Click(System::Object^ sender, System::EventArgs^ e)
	{
		frm_modify^ mfForm = gcnew frm_modify();
		mfForm->Show();
	}




    private: System::Void pEInfoMenu_Click(System::Object^ sender, System::EventArgs^ e) 
    {
	    frm_PEInfo^ frm = gcnew frm_PEInfo;
	    frm->Show();

    }
    private: System::Void dataDirectoryMenu_Click(System::Object^ sender, System::EventArgs^ e) 
    {
	    frm_Directory^ frm = gcnew frm_Directory;
	    frm->Show();
    }
    private: System::Void button2_Click(System::Object^ sender, System::EventArgs^ e) 
    {
		Stream^ myStream;
		SaveFileDialog^ saveFileDialog1 = gcnew SaveFileDialog;
		saveFileDialog1->Filter = "dll files (*.dll)|*.dll|All files (*.*)|*.*";
		saveFileDialog1->FilterIndex = 1;
		saveFileDialog1->RestoreDirectory = true;
		saveFileDialog1->FileName= System::IO::Path::GetFileName(EXE2DLL::EXETODLL::FilePath)->Replace("exe","dll");
		if (saveFileDialog1->ShowDialog() == System::Windows::Forms::DialogResult::OK)
		{
			//if ((myStream = saveFileDialog1->OpenFile()) != nullptr)
			//{
				exe2dll((const char*)(void*)Marshal::StringToHGlobalAnsi(EXE2DLL::EXETODLL::FilePath), (const char*)(void*)Marshal::StringToHGlobalAnsi(saveFileDialog1->FileName));
			//}
			
		}
    }
};
}
