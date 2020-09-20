#include "pch.h"
#include "EXE2DLL.h"
#include "MyForm.h"



#include "dbghelp.h"
#pragma comment(lib, "dbghelp.lib")

//extern char* __unDName(char*, const char*, int, void*, void*, int);

using namespace EXE2DLL;

	using namespace System;
	using namespace System::Windows::Forms;

	//[System::STAThread]
	[STAThreadAttribute]
	int main(cli::array<System::String^>^ args)
	{
		Application::EnableVisualStyles();
		Application::SetCompatibleTextRenderingDefault(false);
	    MyForm MainForm;
		Application::Run(% MainForm);
	}



void updatecontrol()
{
	PElist.clear();
	DataDirectory.clear();
	Sectionlist.clear();
	funlist.clear();
	EXE2DLL::section_name = "";

	try
	{
		EXE2DLL::MyForm::TheInstance->listView1->Items->Clear();
		EXE2DLL::MyForm::TheInstance->listView2->Items->Clear();
	}
	catch(exception e)
	{

	}
	

	if (EXE2DLL::section_name.empty() == true && EXE2DLL::EXETODLL::FilePath != nullptr)
	{
		HANDLE hFile = CreateFileA((const char*)(void*)Marshal::StringToHGlobalAnsi(EXE2DLL::EXETODLL::FilePath), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		//获取文件大小
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		CHAR* pFileBuf = new CHAR[dwFileSize];
		//将文件读取到内存
		DWORD ReadSize = 0;
		ReadFile(hFile, pFileBuf, dwFileSize, &ReadSize, NULL);
		PIMAGE_SECTION_HEADER last_section = get_last_section((PBYTE)pFileBuf, dwFileSize, true);
		for (DWORD i = 0; i < IMAGE_SIZEOF_SHORT_NAME; i++)
		{
			char name[62];
			sprintf_s(name, "%c", last_section->Name[i]);
			EXE2DLL::section_name += name;
		}
		CloseHandle(hFile);
	}

	int hRes = GetPeInfo((const char*)(void*)Marshal::StringToHGlobalAnsi(EXE2DLL::EXETODLL::FilePath), PElist, DataDirectory, Sectionlist);
	if (hRes == 0)
	{
		EXE2DLL::MyForm::TheInstance->listView1->BeginUpdate();
		for (int i = 0; i < Sectionlist.size(); ++i)
		{
			String^ str = gcnew String(Sectionlist[i].c_str());
			ListViewItem^ lvi = gcnew ListViewItem();
			lvi->Text = (i + 1).ToString();
			lvi->SubItems->Add(str->Split('#')[0]->ToString());
			lvi->SubItems->Add(str->Split('#')[1]->ToString());
			lvi->SubItems->Add(str->Split('#')[2]->ToString());
			lvi->SubItems->Add(str->Split('#')[3]->ToString());
			lvi->SubItems->Add(str->Split('#')[4]->ToString());
			lvi->SubItems->Add(str->Split('#')[5]->ToString());
			EXE2DLL::MyForm::TheInstance->listView1->Items->Add(lvi);
		}
		EXE2DLL::MyForm::TheInstance->listView1->EndUpdate();
	}

	int res = GetExpTableList((const char*)(void*)Marshal::StringToHGlobalAnsi(EXE2DLL::EXETODLL::FilePath), funlist);
	if (res == 0)
	{
		EXE2DLL::MyForm::TheInstance->listView2->BeginUpdate();
		for (int i = 0; i < funlist.size(); ++i)
		{
			String^ str = gcnew String(funlist[i].c_str());
			ListViewItem^ lvi = gcnew ListViewItem();
			lvi->Text = (i + 1).ToString();
			lvi->SubItems->Add(str->Split('#')[0]->ToString());
			lvi->SubItems->Add(str->Split('#')[1]->ToString());
			lvi->SubItems->Add(str->Split('#')[2]->ToString());
			lvi->SubItems->Add(str->Split('#')[3]->ToString());
			lvi->SubItems->Add(gcnew String(EXE2DLL::section_name.c_str()));
			EXE2DLL::MyForm::TheInstance->listView2->Items->Add(lvi);
		}
		EXE2DLL::MyForm::TheInstance->listView2->EndUpdate();
	}
}
