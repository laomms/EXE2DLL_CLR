#pragma once

#include "add_export_function.h"
//#include "MyForm.h"

#ifdef _WIN64
typedef unsigned __int64 size_t;
#else
typedef unsigned int size_t;
#endif 


void updatecontrol();

namespace EXE2DLL
{
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


	static std::vector<std::string>  PElist;
	static std::vector<std::string>  DataDirectory;
	static std::vector<std::string>  Sectionlist;
	static std::vector<std::string>  funlist;
	static bool modifyflag;
	static std::string section_name;
	static std::string fun_name;

	public  ref class EXETODLL
	{
	public: static String^FilePath;
		 
    public:
         static size_t AddSection(String^ path, String^ wc_section_name, DWORD VirtualSize, String^ str_Characteristics, size_t^% RvaRawData)
        {
            return add_section((const char*)(void*)Marshal::StringToHGlobalAnsi(path), (const char*)(void*)Marshal::StringToHGlobalAnsi(wc_section_name), VirtualSize, (const char*)(void*)Marshal::StringToHGlobalAnsi(str_Characteristics), (size_t)RvaRawData);
        }
        static  BOOL AddExtportFuncton(String^ file_name, String^ section_name, String^ FuncName, size_t FuncRva)
        {
            return add_export_table((const char*)(void*)Marshal::StringToHGlobalAnsi(file_name), (const char*)(void*)Marshal::StringToHGlobalAnsi(section_name), (const char*)(void*)Marshal::StringToHGlobalAnsi(FuncName), FuncRva);
        }
        static  BOOL ModifyExtportFuncton(String^ file_name, String^ old_func_name, String^ FuncName, size_t FuncRva)
        {
            return modify_export_table((const char*)(void*)Marshal::StringToHGlobalAnsi(file_name), (const char*)(void*)Marshal::StringToHGlobalAnsi(old_func_name), (const char*)(void*)Marshal::StringToHGlobalAnsi(FuncName), FuncRva);
        }
		static  BOOL DeleteExtportFuncton(String^ file_name,  String^ FuncName, size_t FuncRva)
		{
			return delete_export_table((const char*)(void*)Marshal::StringToHGlobalAnsi(file_name), (const char*)(void*)Marshal::StringToHGlobalAnsi(FuncName), FuncRva);
		}
	};

};