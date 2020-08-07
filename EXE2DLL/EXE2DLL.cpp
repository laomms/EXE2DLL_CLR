#include "pch.h"
#include "MyForm.h"
#include "EXE2DLL.h"

using namespace System;
using namespace System::ComponentModel;
using namespace System::Collections;
using namespace System::Windows::Forms;
using namespace System::Data;
using namespace System::Drawing;
using namespace System::Net;
using namespace System::Threading;
using namespace System::IO;
using namespace System::Runtime::InteropServices;


//[System::STAThread]
[STAThreadAttribute]
int main(cli::array<System::String ^> ^args)
{
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);
	EXE2DLL::MyForm MainForm;
	Application::Run(% MainForm);
}


