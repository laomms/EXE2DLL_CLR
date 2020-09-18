#include "pch.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <cstring>
#include <memory.h>
#include "imagehlp.h"
#include <vector>
#include <sstream>
#include "EXE2DLL.h"
#include "ExeToDll.h"
#include <msclr\marshal.h>
#include <msclr\marshal_cppstd.h>
#pragma comment(lib,"Imagehlp.lib")

#ifdef _WIN64
typedef unsigned __int64 size_t;
#else
typedef unsigned int size_t;
#endif 

#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

using namespace std;


DWORD SizeOfFile;

// align x down to the nearest multiple of align. align must be a power of 2.
#define P2ALIGNDOWN(x, align) ((x) & -(align))
// align x up to the nearest multiple of align. align must be a power of 2.
#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

vector<string> split(string s, string delimiter) {
	size_t pos_start = 0, pos_end, delim_len = delimiter.length();
	string token;
	vector<string> res;

	while ((pos_end = s.find(delimiter, pos_start)) != string::npos) {
		token = s.substr(pos_start, pos_end - pos_start);
		pos_start = pos_end + delim_len;
		res.push_back(token);
	}

	res.push_back(s.substr(pos_start));
	return res;
}

BYTE* get_nt_hdrs(IN const BYTE* pe_buffer)
{
	if (!pe_buffer) return nullptr;
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;	
	if (IsBadReadPtr(idh, sizeof(IMAGE_DOS_HEADER))) {
		return nullptr;
	}
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return nullptr;
	}
	const LONG kMaxOffset = 1024;
	LONG pe_offset = idh->e_lfanew;

	if (pe_offset > kMaxOffset) return nullptr;

	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)(pe_buffer + pe_offset);
	if (IsBadReadPtr(inh, sizeof(IMAGE_NT_HEADERS32))) {
		return nullptr;
	}
	if (inh->Signature != IMAGE_NT_SIGNATURE) {
		return nullptr;
	}
	return (BYTE*)inh;
}

size_t add_section(const char* path, const char* section_name, DWORD VirtualSize, const char* str_Characteristics, size_t RvaRawData)//target_file.exe .mySection 0x231 rdata 
{
	DWORD SectionRVA = 0;
	std::string file_path = path;
	size_t found_indx = file_path.find_last_of(".");
	std::string ext = file_path.substr(found_indx + 1);
	std::string name = file_path.substr(0, found_indx);
	std::string newspath = file_path + ".bake." + ext;
	DWORD Characteristics = 0;
	if (strcmp(str_Characteristics, "text") == 0) {
		Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
	}
	else if (strcmp(str_Characteristics, "data") == 0) {
		Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	}
	else if (strcmp(str_Characteristics, "rdata") == 0) {
		Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
	}
	else {
		Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
	}

	HANDLE hFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		wcout << L"Cannot open file (0x" << hex << GetLastError() << L")" << endl;
		return 0;
	}

	HANDLE hNewFile = CreateFileA(newspath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNewFile == INVALID_HANDLE_VALUE)
	{
		printf("backup file has already exsit.\n");
		CloseHandle(hNewFile);
	}
	else
	{
		char buff[4096];
		DWORD dwBytesWritten = 0;
		DWORD dwBytesRead = 0;
		while (ReadFile(hFile, buff, sizeof(buff), &dwBytesRead, NULL))
		{
			if (dwBytesRead == 0)
				break;
			if (!WriteFile(hNewFile, buff, sizeof(buff), &dwBytesWritten, NULL)) {
				printf("Target file not written to. Error %u", GetLastError());
				break;
			}
		}
		CloseHandle(hNewFile);
	}

	LPDWORD dwFileSizeHigh = 0;
	DWORD dwFileSizeLow = 0;
	dwFileSizeLow = GetFileSize(hFile, dwFileSizeHigh);
	if (dwFileSizeHigh != NULL) {
		CloseHandle(hFile);
		wcout << L"Big files not supported." << endl;
		return 0;
	}
	wcout << L"File size in bytes: " << dwFileSizeLow << endl;

	// Mapping the file read-only
	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == INVALID_HANDLE_VALUE) return 0;
	PBYTE pView = (PBYTE)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (pView == NULL) {
		wcout << L"Error in MapFileReadOnly (" << GetLastError() << L")" << endl;
		return 0;
	}
	// Checking the file.
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pView;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		wcout << L"Invalid PE file" << endl;
		UnmapViewOfFile((PVOID)pView);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return 0;
	}
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pView + dosHeader->e_lfanew);

	// Extracting data for some global variables that will be used later.
	WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
	DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
	DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;


	CHAR str_section_name[9] = { 0 };
	std::memcpy(str_section_name, section_name, sizeof(str_section_name) - 1);

	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < numberOfSections; i++, section++)
	{
		if (strncmp((char*)section->Name, (char*)str_section_name, 8) == 0)
		{
			wcout << L"Section name has already  Exist." << endl;
			wcout << L"The raw section offset is 0x" << hex << section->PointerToRawData
				<< L" The section size is 0x" << hex << section->Misc.VirtualSize << endl
				<< L"The section at RVA 0x" << hex << section->VirtualAddress << endl;
			RvaRawData = section->PointerToRawData;
			SectionRVA = section->VirtualAddress;
			UnmapViewOfFile((PVOID)pView);
			CloseHandle(hFileMapping);
			CloseHandle(hFile);
			return SectionRVA;
		}
	}
	PIMAGE_FILE_HEADER fileHeader = &(ntHeaders->FileHeader);
	WORD sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
	PIMAGE_SECTION_HEADER firstSectionHeader = (PIMAGE_SECTION_HEADER)(((UINT_PTR)fileHeader) + sizeof(IMAGE_FILE_HEADER) + sizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER newSectionHeader = &firstSectionHeader[numberOfSections]; // Right after last section header.
	PBYTE firstByteOfSectionData = (PBYTE)(((DWORD)firstSectionHeader->PointerToRawData) + (UINT_PTR)pView);
	DWORD available_space = ((UINT_PTR)firstByteOfSectionData) - ((UINT_PTR)newSectionHeader);
	if (available_space < sizeof(IMAGE_SECTION_HEADER)) {
		wcout << L"There is no room for the new section header. Functionality to make room is not yet implemented so "
			<< L"the program will abort. No change has been made to the file." << endl;
		UnmapViewOfFile((PVOID)pView);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return 0;
	}


	// Unmaping the file.
	// Since file mappings are fixed size, we need to close this read-only one and create a bigger RW one to 
	// be able to add the section header and expand the size of the file.
	UnmapViewOfFile((PVOID)pView);
	CloseHandle(hFileMapping);

	DWORD newSize = P2ALIGNUP(dwFileSizeLow + VirtualSize, fileAlignment);
	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, newSize, NULL);
	if (hFileMapping == INVALID_HANDLE_VALUE) return 0;
	pView = (PBYTE)MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	if (pView == NULL) {
		wcout << L"Error in MapFileRWNewSize (" << GetLastError() << L")" << endl;
		return 0;
	}


	dosHeader = (PIMAGE_DOS_HEADER)pView;
	ntHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pView + dosHeader->e_lfanew);
	sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
	fileHeader = &(ntHeaders->FileHeader);
	firstSectionHeader = (PIMAGE_SECTION_HEADER)(((UINT_PTR)fileHeader) + sizeof(IMAGE_FILE_HEADER) + sizeOfOptionalHeader);
	numberOfSections = ntHeaders->FileHeader.NumberOfSections;
	// We asssume there is room for a new section header.
	newSectionHeader = &firstSectionHeader[numberOfSections]; // Right after last section header.
	PIMAGE_SECTION_HEADER lastSectionHeader = &firstSectionHeader[numberOfSections - 1];
	memset(newSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(&newSectionHeader->Name, section_name, min(strlen(section_name), 8));
	newSectionHeader->Misc.VirtualSize = VirtualSize;
	newSectionHeader->VirtualAddress = P2ALIGNUP(lastSectionHeader->VirtualAddress + lastSectionHeader->Misc.VirtualSize, sectionAlignment);
	newSectionHeader->SizeOfRawData = P2ALIGNUP(VirtualSize, fileAlignment);
	newSectionHeader->PointerToRawData = dwFileSizeLow; // at the end of the file before expanding its size.
	// this also works:
	//newSectionHeader->PointerToRawData = (DWORD)(lastSectionHeader->PointerToRawData + lastSectionHeader->SizeOfRawData);
	newSectionHeader->Characteristics = Characteristics;

	numberOfSections++;
	ntHeaders->FileHeader.NumberOfSections = numberOfSections;
	ntHeaders->OptionalHeader.SizeOfImage = P2ALIGNUP(newSectionHeader->VirtualAddress + newSectionHeader->Misc.VirtualSize, sectionAlignment);
	// this also works:
	//ntHeaders->OptionalHeader.SizeOfImage = P2ALIGNUP(ntHeaders->OptionalHeader.SizeOfImage + VirtualSize, sectionAlignment);

	memset((PVOID)((UINT_PTR)pView + newSectionHeader->PointerToRawData), 0, newSectionHeader->SizeOfRawData);

	wcout << L"You can proceed to copy your raw section data to file offset 0x" << hex << newSectionHeader->PointerToRawData
		<< L" up to a length of 0x" << hex << VirtualSize << endl
		<< L"The section will be mapped at RVA 0x" << hex << newSectionHeader->VirtualAddress << endl;
	RvaRawData = newSectionHeader->PointerToRawData;
	SectionRVA = newSectionHeader->VirtualAddress;
	wcout << L"New file size in bytes: " << newSize << endl << L"Operation completed successfully." << endl;
	CloseHandle(hFile);
	UnmapViewOfFile((PVOID)pView);
	CloseHandle(hFileMapping);
	return SectionRVA;
}

DWORD get_hdrs_size(IN const BYTE* pe_buffer)
{
	bool is64b = is64bit(pe_buffer);
	BYTE* payload_nt_hdr = get_nt_hdrs(pe_buffer);
	if (!payload_nt_hdr) {
		return 0;
	}
	DWORD hdrs_size = 0;
	if (is64b) {
		IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
		hdrs_size = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
	}
	else {
		IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
		hdrs_size = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
	}
	return hdrs_size;
}

PIMAGE_SECTION_HEADER get_last_section(IN const PBYTE pe_buffer, IN size_t pe_size, IN bool is_raw)
{
	SIZE_T module_end = get_hdrs_size(pe_buffer);
	const size_t sections_count = get_sections_count(pe_buffer, pe_size);
	if (sections_count == 0) {
		return nullptr;
	}
	PIMAGE_SECTION_HEADER last_sec = nullptr;
	//walk through sections
	for (size_t i = 0; i < sections_count; i++) {
		PIMAGE_SECTION_HEADER sec = get_section_hdr(pe_buffer, pe_size, i);
		if (!sec) break;

		size_t new_end = is_raw ? (sec->PointerToRawData + sec->SizeOfRawData) : (sec->VirtualAddress + sec->Misc.VirtualSize);
		if (new_end > module_end) {
			module_end = new_end;
			last_sec = sec;
		}
	}
	return last_sec;
}

DWORD RvaToFoa(DWORD FileBuff, DWORD Rva)
{
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeaders;
	PIMAGE_FILE_HEADER pImageFileHeader;
	PIMAGE_OPTIONAL_HEADER pImageOptionalHeader;
	PIMAGE_SECTION_HEADER pImageSectionHeader;

	pImageDosHeader = (PIMAGE_DOS_HEADER)FileBuff;
	pImageNtHeaders = (PIMAGE_NT_HEADERS)(FileBuff + pImageDosHeader->e_lfanew);
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageNtHeaders + sizeof(pImageNtHeaders->Signature));
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	DWORD SectionAlignment = pImageOptionalHeader->SectionAlignment;

	for (DWORD i = 0; i < pImageFileHeader->NumberOfSections; i++)
	{
		DWORD SizeOfSection = pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].Misc.VirtualSize;

		if (SizeOfSection % SectionAlignment)
		{
			SizeOfSection = (SizeOfSection + SectionAlignment) & (0 - SectionAlignment);
		}
		if (Rva < SizeOfSection)
		{
			Rva = Rva - pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].PointerToRawData;
			return Rva;
		}

	}

	return Rva;
}
DWORD FoaToRva(DWORD FileBuff, DWORD Foa)
{
	PIMAGE_DOS_HEADER pImageDosHeader;
	PIMAGE_NT_HEADERS pImageNtHeaders;
	PIMAGE_FILE_HEADER pImageFileHeader;
	PIMAGE_OPTIONAL_HEADER pImageOptionalHeader;
	PIMAGE_SECTION_HEADER pImageSectionHeader;

	pImageDosHeader = (PIMAGE_DOS_HEADER)FileBuff;
	pImageNtHeaders = (PIMAGE_NT_HEADERS)(FileBuff + pImageDosHeader->e_lfanew);
	pImageFileHeader = (PIMAGE_FILE_HEADER)((DWORD)pImageNtHeaders + sizeof(pImageNtHeaders->Signature));
	pImageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)pImageFileHeader + sizeof(IMAGE_FILE_HEADER));
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pImageOptionalHeader + pImageFileHeader->SizeOfOptionalHeader);
	DWORD SectionAlignment = pImageOptionalHeader->SectionAlignment;

	for (DWORD i = 0; i < pImageFileHeader->NumberOfSections; i++)
	{
		DWORD SizeOfSection = pImageSectionHeader[i].PointerToRawData + pImageSectionHeader[i].SizeOfRawData;

		if (Foa < SizeOfSection)
		{
			Foa = Foa - pImageSectionHeader[i].PointerToRawData + pImageSectionHeader[i].VirtualAddress;
			return Foa;
		}

	}

	return Foa;
}

BOOL add_export_table(const char* file_name, const char* section_name, const char* FuncName, size_t FuncRva)
{
	DWORD VirtualSize = 0;
	DWORD NewAddSize = 0;
	HANDLE hFile = CreateFileA(file_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wcout << L"Cannot open file (0x" << hex << GetLastError() << L")" << endl;
		return false;
	}
	LPDWORD dwFileSizeHigh = 0;
	DWORD dwFileSizeLow = 0;
	dwFileSizeLow = GetFileSize(hFile, dwFileSizeHigh);
	if (dwFileSizeHigh != NULL) {
		CloseHandle(hFile);
		wcout << L"Big files not supported." << endl;
	}
	wcout << L"File size in bytes: " << dwFileSizeLow << endl;

	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hFileMapping == INVALID_HANDLE_VALUE) return 0;
	PBYTE pView = (PBYTE)MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pView == NULL) {
		wcout << L"Error in MapFileReadOnly (" << GetLastError() << L")" << endl;
		return 0;
	}

	// Checking the file.
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pView;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		wcout << L"Invalid PE file" << endl;
		CloseHandle(hFile);
		return 0;
	}
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pView + dosHeader->e_lfanew);
#ifdef _WIN64
#define MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define MACHINE IMAGE_FILE_MACHINE_I386
#endif

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->FileHeader.Machine != MACHINE) {
		wcout << L"Invalid PE file" << endl;
		CloseHandle(hFile);
		return 0;
	}
	// Extracting data for some global variables that will be used later.
	WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
	DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;

	CHAR str_section_name[9] = { 0 };
	std::memcpy(str_section_name, section_name, sizeof(str_section_name) - 1);
	size_t	RvaRawData;
	size_t  RvaSection;
	bool isfind = false;
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < numberOfSections; i++, section++)
	{
		if (strncmp((char*)section->Name, (char*)str_section_name, 8) == 0)
		{
			isfind = true;
			RvaRawData = section->PointerToRawData;
			RvaSection = section->VirtualAddress;
			VirtualSize = section->Misc.VirtualSize;
			section->Characteristics = 0x60000020;//修改属性(可执行)
		}
	}
	if (!isfind)
	{
		wcout << L"Cannot find the specified section name." << endl;
		return 0;
	}
	char* FuncNameList = new char[VirtualSize]();
	DWORD LenFuncName = 0;
	char* FuncAddrList = new char[VirtualSize]();
	DWORD LenFuncAddr = 0;
	PIMAGE_FILE_HEADER fileHeader = &(ntHeaders->FileHeader);
	WORD sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)ntHeaders + 4 + IMAGE_SIZEOF_FILE_HEADER);

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pView + RvaRawData);
	//DWORD ExportFoa = RvaRawData;//获取导出表的地址FOA=RvaToFoa((DWORD)pView,RvaSection);
	DWORD AddressOfFunctionsFOA;
	DWORD AddressOfNamesFOA;
	DWORD AddressOfNameOrdinalsFOA;
	DWORD NameFOA;

	if (pOptionalHeader->DataDirectory[0].VirtualAddress == 0) //如果没有导出表
	{
		pExportDirectory->Characteristics = 0;
		pExportDirectory->TimeDateStamp = 0;
		pExportDirectory->MajorVersion = 0;
		pExportDirectory->MinorVersion = 0;
		pExportDirectory->Base = 1;
		pExportDirectory->NumberOfFunctions = 1;
		pExportDirectory->NumberOfNames = 1;
		pOptionalHeader->DataDirectory[0].VirtualAddress = RvaSection;//修改导出表的起始地址为新区段地址
		strcpy(&FuncNameList[LenFuncName + 1], FuncName);
		strcpy(&FuncAddrList[LenFuncAddr], (char*)(DWORD)&FuncRva);
		LenFuncAddr = 4;
	}
	else
	{
		//是否已经有该函数名或者地址	
		DWORD* AddressOfName = (DWORD*)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfNames));
		DWORD* AddressOfFunctions = (DWORD*)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfFunctions));
		for (int i = 0; i < (int)pExportDirectory->NumberOfNames; i++)
		{
			char* func_names = (char*)(pView + RvaToFoa((DWORD)pView, AddressOfName[i]));
			DWORD* func_addr = (DWORD*)AddressOfFunctions[i];
			if (strcmp(FuncName, func_names) == 0 || func_addr == (DWORD*)FuncRva)
			{
				wcout << L"Funtion name or RVA has already  Exist." << endl;
				return false;
			}			
			strcpy(&FuncNameList[LenFuncName + 1], (char*)(pView + RvaToFoa((DWORD)pView, AddressOfName[i])));//存储函数名备用
			strcpy(&FuncAddrList[LenFuncAddr], (char*)(DWORD)&AddressOfFunctions[i]);//存储名字偏移地址备用
			LenFuncName = LenFuncName + strlen(func_names) + 1;
			LenFuncAddr = LenFuncAddr + 4;
		}

		pExportDirectory->NumberOfFunctions = pExportDirectory->NumberOfFunctions + 1;
		pExportDirectory->NumberOfNames = pExportDirectory->NumberOfNames + 1;		
	}

	AddressOfFunctionsFOA = RvaSection + sizeof(IMAGE_EXPORT_DIRECTORY);
	AddressOfNamesFOA = AddressOfFunctionsFOA + pExportDirectory->NumberOfFunctions * 4;
	AddressOfNameOrdinalsFOA = AddressOfNamesFOA + pExportDirectory->NumberOfFunctions * 4;
	NameFOA = AddressOfNameOrdinalsFOA + pExportDirectory->NumberOfNames * 2;

	pExportDirectory->AddressOfFunctions = AddressOfFunctionsFOA;
	pExportDirectory->AddressOfNames = AddressOfNamesFOA;
	pExportDirectory->AddressOfNameOrdinals = AddressOfNameOrdinalsFOA;
	pExportDirectory->Name = NameFOA;

	//赋值AddressOfFunctions
	LPVOID pAddressOfFunctions = (LPVOID)(pView + RvaToFoa((DWORD)pView, AddressOfFunctionsFOA));
	char* Func_Addr = new char[LenFuncAddr + 4]();
	memcpy(Func_Addr, FuncAddrList, LenFuncAddr);
	strcpy(Func_Addr + LenFuncAddr, (char*)(DWORD)&FuncRva);
	memcpy(pAddressOfFunctions, Func_Addr, LenFuncAddr + 4);

	//连接新旧函数名字符串
	int FuncNamelen = LenFuncName + strlen(FuncName) + 1;
	char* Func_Name = new char[FuncNamelen]();
	//strncpy(Func_Name, FuncNameList, LenFuncName);
	memcpy(Func_Name, FuncNameList, LenFuncName);
	strcpy(Func_Name + LenFuncName + 1, FuncName);
	PCHAR FName = (PCHAR)Func_Name;
	NewAddSize = pExportDirectory->Name - RvaSection + FuncNamelen+1 ;

	//赋值Names
	LPVOID pNames = (LPVOID)(pView + RvaToFoa((DWORD)pView, NameFOA));
	memcpy(pNames, FName, FuncNamelen);

	PWORD pAddressOfNameOrdinals = (PWORD)(pView + RvaToFoa((DWORD)pView, AddressOfNameOrdinalsFOA));
	PDWORD pAddressOfNames = (PDWORD)(pView + RvaToFoa((DWORD)pView, AddressOfNamesFOA));
	size_t n = 0;
	for (size_t i = 0; i < pExportDirectory->NumberOfNames; i++, pAddressOfNames++, pAddressOfNameOrdinals++)
	{
		while (FName[n] != '\0')
		{
			NameFOA += 1;
			n += 1;
		}
		//赋值AddressOfNames
		NameFOA += 1;
		memcpy(pAddressOfNames, &NameFOA, 4);
		//赋值AddressOfNameOrdinals
		memcpy(pAddressOfNameOrdinals, (char*)(DWORD)&i, 2);
		n += 1;
	}
	pOptionalHeader->DataDirectory[0].Size = NewAddSize;
	CloseHandle(hFile);
	UnmapViewOfFile((PVOID)pView);
	CloseHandle(hFileMapping);
	return TRUE;
}

BOOL modify_export_table(const char* file_name, const char* old_name, const char* new_name, size_t FuncRva)
{
	int len = strlen(old_name);
	char* FuncName = new char[len]();
	if (strlen(new_name) > len)
	{
		len = strlen(new_name);
		::memcpy(FuncName, new_name, len+1);
		//add_export_table(file_name,  old_name, new_name,  FuncRva);
	}
	else
	{		
		::memcpy(FuncName, new_name, len);
	}	
	DWORD VirtualSize = 0;
	HANDLE hFile = CreateFileA(file_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wcout << L"Cannot open file (0x" << hex << GetLastError() << L")" << endl;
		return false;
	}
	LPDWORD dwFileSizeHigh = 0;
	DWORD dwFileSizeLow = 0;
	dwFileSizeLow = GetFileSize(hFile, dwFileSizeHigh);
	if (dwFileSizeHigh != NULL) {
		CloseHandle(hFile);
		wcout << L"Big files not supported." << endl;
	}
	wcout << L"File size in bytes: " << dwFileSizeLow << endl;

	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hFileMapping == INVALID_HANDLE_VALUE) return 0;
	PBYTE pView = (PBYTE)MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pView == NULL) {
		wcout << L"Error in MapFileReadOnly (" << GetLastError() << L")" << endl;
		return 0;
	}

	// Checking the file.
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pView;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		wcout << L"Invalid PE file" << endl;
		CloseHandle(hFile);
		return 0;
	}
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pView + dosHeader->e_lfanew);
#ifdef _WIN64
#define MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define MACHINE IMAGE_FILE_MACHINE_I386
#endif

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->FileHeader.Machine != MACHINE) {
		wcout << L"Invalid PE file" << endl;
		CloseHandle(hFile);
		return 0;
	}

	char* FuncAddrList = new char[4]();
	WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
	DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;
	PIMAGE_FILE_HEADER fileHeader = &(ntHeaders->FileHeader);
	WORD sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)ntHeaders + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntHeaders + sizeof(IMAGE_NT_HEADERS));
	if (pOptionalHeader->DataDirectory[0].VirtualAddress == 0) //如果没有导出表
	{
		wcout << L"No Export Table find." << endl;
		CloseHandle(hFile);
		UnmapViewOfFile((PVOID)pView);
		CloseHandle(hFileMapping);
		return 0;
	}
	else
	{
		//寻找导出表所在区段
		DWORD dwRva = pOptionalHeader->DataDirectory[0].VirtualAddress;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory;
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
			if (pSecHeader[i].Misc.VirtualSize == 0)break;
			//pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pView + pSecHeader[i].SizeOfRawData);
			//if (pExportDirectory->Base = 1)
			//{
			//	//break;
			//}
			DWORD dwSectionBeginRva = pSecHeader[i].VirtualAddress;
			DWORD dwSectionEndRva = pSecHeader[i].VirtualAddress + pSecHeader[i].SizeOfRawData;
			if (dwRva >= dwSectionBeginRva && dwRva <= dwSectionEndRva) {
				pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pView + pSecHeader[i].PointerToRawData);
				pSecHeader[i].Characteristics = 0x60000020;
			}			
		}
		BOOL found = false;
		DWORD* AddressOfName = (DWORD*)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfNames));
		//是否有该函数名
		for (int i = 0; i < (int)pExportDirectory->NumberOfNames; i++)
		{
			char* func_names = (char*)(pView + RvaToFoa((DWORD)pView, AddressOfName[i]));
			if (strcmp(old_name, func_names) == 0)
			{
				LPVOID pAddressOfFunctions = (LPVOID)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfFunctions)+ i * 4);
				memcpy(pAddressOfFunctions, (char*)(DWORD)&FuncRva,  4);
				LPVOID pNames = (LPVOID)(pView + RvaToFoa((DWORD)pView, AddressOfName[i]));
				memcpy(pNames, FuncName, len);
				found=true;
				break;
			}
		}
		if (found==false) 
		{
			wcout << L"Can not finding this functin name." << endl;
		}
	}	
	CloseHandle(hFile);
	UnmapViewOfFile((PVOID)pView);
	CloseHandle(hFileMapping);
	return TRUE;
};

BOOL delete_export_table(const char* file_name, const char* func_name, size_t FuncRva)
{
	size_t  RvaSection;
	DWORD NewAddSize = 0;
	static std::vector<std::string>  func_list = EXE2DLL::funlist;
	GetExpTableList(file_name, func_list);

	DWORD VirtualSize = 0;
	HANDLE hFile = CreateFileA(file_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wcout << L"Cannot open file (0x" << hex << GetLastError() << L")" << endl;
		return false;
	}
	LPDWORD dwFileSizeHigh = 0;
	DWORD dwFileSizeLow = 0;
	dwFileSizeLow = GetFileSize(hFile, dwFileSizeHigh);
	if (dwFileSizeHigh != NULL) {
		CloseHandle(hFile);
		wcout << L"Big files not supported." << endl;
	}
	wcout << L"File size in bytes: " << dwFileSizeLow << endl;

	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (hFileMapping == INVALID_HANDLE_VALUE) return 0;
	PBYTE pView = (PBYTE)MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (pView == NULL) {
		wcout << L"Error in MapFileReadOnly (" << GetLastError() << L")" << endl;
		return 0;
	}

	// Checking the file.
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pView;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		wcout << L"Invalid PE file" << endl;
		CloseHandle(hFile);
		return 0;
	}
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)pView + dosHeader->e_lfanew);
#ifdef _WIN64
#define MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define MACHINE IMAGE_FILE_MACHINE_I386
#endif

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->FileHeader.Machine != MACHINE) {
		wcout << L"Invalid PE file" << endl;
		CloseHandle(hFile);
		return 0;
	}

	char* FuncAddrList = new char[4]();
	WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
	DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;
	PIMAGE_FILE_HEADER fileHeader = &(ntHeaders->FileHeader);
	WORD sizeOfOptionalHeader = ntHeaders->FileHeader.SizeOfOptionalHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)ntHeaders + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)ntHeaders + sizeof(IMAGE_NT_HEADERS));
	if (pOptionalHeader->DataDirectory[0].VirtualAddress == 0) //如果没有导出表
	{
		wcout << L"No Export Table find." << endl;
		CloseHandle(hFile);
		UnmapViewOfFile((PVOID)pView);
		CloseHandle(hFileMapping);
		return 0;
	}
	else
	{
		//寻找导出表所在区段
		DWORD dwRva = pOptionalHeader->DataDirectory[0].VirtualAddress;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory;
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
			if (pSecHeader[i].Misc.VirtualSize == 0)break;
			DWORD dwSectionBeginRva = pSecHeader[i].VirtualAddress;
			RvaSection = pSecHeader[i].VirtualAddress;
			DWORD dwSectionEndRva = pSecHeader[i].VirtualAddress + pSecHeader[i].SizeOfRawData;
			if (dwRva >= dwSectionBeginRva && dwRva <= dwSectionEndRva) {
				pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pView + pSecHeader[i].PointerToRawData);
				pSecHeader[i].Characteristics = 0x60000020;
			}
		}
		BOOL found = false;
		DWORD* AddressOfName = (DWORD*)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfNames));
		//是否有该函数名
		int func_positon = (int)pExportDirectory->NumberOfNames;
		for (int i = 0; i < (int)pExportDirectory->NumberOfNames; i++)
		{
			if (i < func_positon)
			{
				char* func_names = (char*)(pView + RvaToFoa((DWORD)pView, AddressOfName[i]));
				if (strcmp(func_name, func_names) == 0)
				{
					found = true;
					func_positon = i;

					//移动pAddressOfFunctions
					LPVOID pAddressOfFunctions = (LPVOID)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfFunctions) + i * 4);
					string strFuncAddr = split(func_list[i+1], "@")[1];
					unsigned long funcrva = strtoul(strFuncAddr.c_str(), 0, 16);
					memcpy(pAddressOfFunctions, &funcrva, 4);

					//移动funcname
					LPVOID pNames = (LPVOID)(pView + RvaToFoa((DWORD)pView, AddressOfName[i]));
					string strFuncName = split(func_list[i + 1], "@")[3];
					int len = strFuncName.size() + 1;					
					char* cstr=new char[len];
					std::fill_n(cstr, len, 0);
					strFuncName.copy(cstr, len);				    		
					strcpy(cstr, strFuncName.c_str());
					memcpy(pNames, cstr, len);

					//赋值下一个AddressOfNames
					DWORD* pOldAddressOfNames = (DWORD*)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfNames) + i * 4);
					LPVOID pAddressOfNames = (LPVOID)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfNames) + ( i + 1) * 4);	
					DWORD newPtr = (DWORD)*pOldAddressOfNames + strFuncName.length() + 1;
					memcpy(pAddressOfNames, (char*)&newPtr, 4);					
				}
			}
			else
			{
				if (i != pExportDirectory->NumberOfNames-1 )
				{
					LPVOID pAddressOfFunctions = (LPVOID)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfFunctions) + i * 4);
					string strFuncAddr = split(func_list[i + 1], "@")[1];
					unsigned long funcrva = strtoul(strFuncAddr.c_str(), 0, 16);
					memcpy(pAddressOfFunctions, &funcrva, 4);
					LPVOID pNames = (LPVOID)(pView + RvaToFoa((DWORD)pView, AddressOfName[i]));
					string strFuncName = split(func_list[i + 1], "@")[3];
					int len = strFuncName.size() + 1;
					char* cstr = new char[len];
					std::fill_n(cstr, len, 0);
					strFuncName.copy(cstr, len);
					strcpy(cstr, strFuncName.c_str());
					memcpy(pNames, cstr, len);
					DWORD* pOldAddressOfNames = (DWORD*)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfNames) + i * 4);
					LPVOID pAddressOfNames = (LPVOID)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfNames) + (i + 1) * 4);
					DWORD newPtr = (DWORD)*pOldAddressOfNames + strFuncName.length() + 1;
					memcpy(pAddressOfNames, (char*)&newPtr, 4);	
				}
				else
				{
					LPVOID pAddressOfFunctions = (LPVOID)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfFunctions) + i * 4);
					memset(pAddressOfFunctions, 0, 4);
					LPVOID pNames = (LPVOID)(pView + RvaToFoa((DWORD)pView, AddressOfName[i]));
					char* charData = (char*)pNames;
					memset(pNames,0, strlen(charData)+1);		
					//赋值下一个AddressOfNameOrdinals
					/*LPVOID pAddressOfNameOrdinals = (LPVOID)(pView + RvaToFoa((DWORD)pView, pExportDirectory->AddressOfNameOrdinals) + (i + 1) * 4);
					memset(pAddressOfNameOrdinals, 0, 2);*/
					break;
				}
			}
			
		}
		NewAddSize = pExportDirectory->Name - RvaSection - strlen(func_name) - 1;
		pExportDirectory->NumberOfFunctions = pExportDirectory->NumberOfFunctions - 1;
		pExportDirectory->NumberOfNames = pExportDirectory->NumberOfNames - 1;
		if (found == false)
		{
			wcout << L"Can not finding this functin name." << endl;
		}
	}
	
	pOptionalHeader->DataDirectory[0].Size = NewAddSize;
	CloseHandle(hFile);
	UnmapViewOfFile((PVOID)pView);
	CloseHandle(hFileMapping);
	return TRUE;
};

int GetExpTableList(const char* file_name, std::vector<string>& funlist)
{

	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID lpFileBase;
	PIMAGE_DOS_HEADER pImg_DOS_Header;
	PIMAGE_NT_HEADERS pImg_NT_Header;
	PIMAGE_EXPORT_DIRECTORY pImg_Export_Dir;

	hFile = CreateFileA(file_name, GENERIC_READ, FILE_SHARE_READ,		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		return 3;

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == 0)
	{
		CloseHandle(hFile);
		return 3;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpFileBase == 0)
	{
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return 3;
	}

	BYTE* payload_nt_hdr = get_nt_hdrs((BYTE*)lpFileBase);
	if (payload_nt_hdr == NULL) {		
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return 3;
	}

	pImg_DOS_Header = (PIMAGE_DOS_HEADER)lpFileBase;
	pImg_NT_Header = (PIMAGE_NT_HEADERS)((LONG)pImg_DOS_Header + (LONG)pImg_DOS_Header->e_lfanew);

	if (IsBadReadPtr(pImg_NT_Header, sizeof(IMAGE_NT_HEADERS))|| pImg_NT_Header->Signature != IMAGE_NT_SIGNATURE)
	{
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return 3;
	}

	pImg_Export_Dir = (PIMAGE_EXPORT_DIRECTORY)pImg_NT_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!pImg_Export_Dir)
	{
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return 2;
	}
	pImg_Export_Dir = (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa(pImg_NT_Header,pImg_DOS_Header, (DWORD)pImg_Export_Dir, 0);



	DWORD** ppdwNames = (DWORD**)pImg_Export_Dir->AddressOfNames;

	ppdwNames = (PDWORD*)ImageRvaToVa(pImg_NT_Header,pImg_DOS_Header, (DWORD)ppdwNames, 0);
	if (!ppdwNames)
	{
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return 2;
	}


	//寻找导出表所在区段
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT_PTR)lpFileBase + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)pImg_NT_Header + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)ntHeaders + 4 + IMAGE_SIZEOF_FILE_HEADER);
	DWORD dwRva = pOptionalHeader->DataDirectory[0].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
		if (pSecHeader[i].Misc.VirtualSize == 0)break;
		DWORD dwSectionBeginRva = pSecHeader[i].VirtualAddress;
		DWORD dwSectionEndRva = pSecHeader[i].VirtualAddress + pSecHeader[i].SizeOfRawData;
		if (dwRva >= dwSectionBeginRva && dwRva <= dwSectionEndRva) {
			DWORD aa= pSecHeader[i].Characteristics ;
			EXE2DLL::section_name = "";
			for (DWORD j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++)
			{
				char name[62];
				sprintf_s(name, "%c", pSectionHeader->Name[j]);
				EXE2DLL::section_name += name;
			}
		}
	}

	UINT nNoOfExports = pImg_Export_Dir->NumberOfNames;
	//char* &pszFunctions = new char [nNoOfExports];

	for (UINT i = 0; i < pImg_Export_Dir->NumberOfNames; i++)
	{
		LPVOID pAddressOfFunction = (LPVOID)((PBYTE)lpFileBase + RvaToFoa((DWORD)lpFileBase, pImg_Export_Dir->AddressOfFunctions) + i * 4);
		DWORD func_addr;
		memcpy(&func_addr, pAddressOfFunction, sizeof func_addr);
		char nFuncFoa[32];
		sprintf_s(nFuncFoa, "0x%08X", func_addr); 
		std::string FuncFoa(nFuncFoa);

		LPVOID pAddressOfName = (LPVOID)((PBYTE)lpFileBase + RvaToFoa((DWORD)lpFileBase, pImg_Export_Dir->AddressOfNames)+ i * 4);
		DWORD name_addr;
		memcpy(&name_addr, pAddressOfName, sizeof func_addr);
		char nNameFoa[32];
		sprintf_s(nNameFoa, "0x%08X", name_addr);
		std::string NameFoa(nNameFoa);

		char* FuncName = (PSTR)ImageRvaToVa(pImg_NT_Header, pImg_DOS_Header, (DWORD)*ppdwNames, 0);
		
		char nFuncRVA[32];
		sprintf_s(nFuncRVA, "0x%08X", pImg_Export_Dir->AddressOfFunctions + i * 4); //"0x%s"
		std::string FuncRVA(nFuncRVA);

		std::string items = FuncRVA + "@" + FuncFoa + "@" + NameFoa + "@" + FuncName + "@" + EXE2DLL::section_name;
		funlist.push_back(items);
		ppdwNames++;
	}
	UnmapViewOfFile(lpFileBase);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);
	return 0;
}