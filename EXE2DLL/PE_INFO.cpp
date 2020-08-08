#include "pch.h"
#include <windows.h>
#include <fileapi.h>
#include <stdio.h>
#include <vector>
#include <string>
using namespace std;


int GetPeInfo(const char* file_name, std::vector<std::string>& PElist, std::vector<std::string>& DataDirectory, std::vector<std::string>& Sectionlist)
{
	//获取文件句柄
	HANDLE hFile = CreateFileA(file_name,GENERIC_READ,0,NULL,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//获取文件大小
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	CHAR* pFileBuf = new CHAR[dwFileSize];
	//将文件读取到内存
	DWORD ReadSize = 0;
	ReadFile(hFile, pFileBuf, dwFileSize, &ReadSize, NULL);

	//判断是否为PE文件
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//不是PE
		printf("不是PE文件\n");
		system("pause");
		CloseHandle(hFile);
		return 2;
	}

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuf + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		//不是PE文件
		printf("不是PE文件\n");
		system("pause");
		CloseHandle(hFile);
		return 2;
	}

	//获取基本PE头信息
	//获取信息所用到的两个结构体指针	（这两个结构体都属于NT头）
	PIMAGE_FILE_HEADER		pFileHeader = &(pNtHeader->FileHeader);
	PIMAGE_OPTIONAL_HEADER	pOptionalHeader = &(pNtHeader->OptionalHeader);
	//输出PE头信息
	char data[32];
	sprintf_s(data, "%08X", pOptionalHeader->AddressOfEntryPoint); 
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%04X", pOptionalHeader->Subsystem);	
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%08X",  pOptionalHeader->ImageBase);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%04X", pFileHeader->NumberOfSections);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%08X", pOptionalHeader->SizeOfImage);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%08X", pFileHeader->TimeDateStamp);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%08X", pOptionalHeader->BaseOfCode);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%08X", pOptionalHeader->SizeOfHeaders);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%08X", pOptionalHeader->BaseOfData);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%04X", pFileHeader->Characteristics);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%08X", pOptionalHeader->SectionAlignment);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%08X", pOptionalHeader->CheckSum);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%08X", pOptionalHeader->FileAlignment);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%04X", pFileHeader->SizeOfOptionalHeader);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%04X", pOptionalHeader->Magic);
	PElist.push_back(data);
	memset(data, 0, 32);
	sprintf_s(data, "%08X", pOptionalHeader->NumberOfRvaAndSizes);
	PElist.push_back(data);
	memset(data, 0, 32);


	//获取目录表头指针
	PIMAGE_DATA_DIRECTORY pDataDirectory = pOptionalHeader->DataDirectory;
	for (DWORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		char size[32];
		sprintf_s(data, "%08X", pDataDirectory[i].VirtualAddress);
		std::string sdata(data);
		sprintf_s(size, "%08X", pDataDirectory[i].Size);
		std::string ssize(size);
		std::string items = sdata + "@" + ssize;
		DataDirectory.push_back(items);
		memset(data, 0, 32);
	}

	printf("======================= 区 段 表 =======================\n");
	//获取区段表头指针
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	//获取区段个数
	DWORD dwSectionNum = pFileHeader->NumberOfSections;
	//根据区段个数遍历区段信息
	for (DWORD i = 0; i < dwSectionNum; i++, pSectionHeader++)
	{

		
		char address[32];
		char size[32];
		char rawdata[32];
		char rawsize[32];
		char feature[32];
		string sname;
		for (DWORD j = 0; j < IMAGE_SIZEOF_SHORT_NAME; j++)
		{			
			char name[62];
			sprintf_s(name, "%c", pSectionHeader->Name[j]);
			sname += name;
		}
		sprintf_s(address, "%08X", pSectionHeader->VirtualAddress);
		std::string saddress(address);
		sprintf_s(size, "%08X", pSectionHeader->Misc.VirtualSize);
		std::string ssize(size);
		sprintf_s(rawdata, "%08X", pSectionHeader->PointerToRawData);
		std::string srawdata(rawdata);
		sprintf_s(rawsize, "%08X", pSectionHeader->SizeOfRawData);
		std::string srawsize(rawsize);
		sprintf_s(feature, "%08X", pSectionHeader->Characteristics);	
		std::string sfeature(feature);
		std::string items = sname + "@" + saddress + "@" + ssize + "@" + srawdata + "@" + srawsize + "@" + sfeature;
		Sectionlist.push_back(items);
	}
	CloseHandle(hFile);
	return 0;
}