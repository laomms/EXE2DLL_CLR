#include "pch.h"
#include <windows.h>
#include <fstream>
#include <string>
#include <iostream>
#include <vector>
using namespace std;




int rva_to_raw(PIMAGE_SECTION_HEADER pSection, int nSectionNum, int nRva)
{
	int nRet = 0;

	// 遍历节区
	for (int i = 0; i < nSectionNum; i++) {
		// 导出表地址在这个节区内
		if (pSection[i].VirtualAddress <= nRva && nRva < pSection[i + 1].VirtualAddress) {
			// 文件偏移 = 该段的 PointerToRawData + （内存偏移 - 该段起始的RVA(VirtualAddress)）
			nRet = nRva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
			break;
		}
	}

	return nRet;
}

int printExpTable(const char* strFilePath, std::vector<string>& funlist)
{


	// 二进制方式读文件
	fstream cFile(strFilePath, ios::binary | ios::in);
	if (!cFile) { 
		std::cout << "error: " << strerror(errno) << std::endl;
		cout << "打开文件失败" << endl; 
		return 1;
	}

	// 读 dos 头
	IMAGE_DOS_HEADER dosHeader;
	cFile.read((char*)&dosHeader, sizeof(IMAGE_DOS_HEADER));

	// 读 nt 头（64位）
	IMAGE_NT_HEADERS64 ntHeader;
	cFile.seekg(dosHeader.e_lfanew, ios::beg);
	cFile.read((char*)&ntHeader, sizeof(IMAGE_NT_HEADERS64));
	if (!ntHeader.OptionalHeader.DataDirectory[0].VirtualAddress) {
		cout << "文件没有导出函数" << endl;
		cFile.close(); return 2;
	}

	// 读节区头
	int nSectionNum = ntHeader.FileHeader.NumberOfSections;
	shared_ptr<IMAGE_SECTION_HEADER> pShareSection(new IMAGE_SECTION_HEADER[nSectionNum]);
	PIMAGE_SECTION_HEADER pSection = pShareSection.get();
	cFile.read((char*)pSection, sizeof(IMAGE_SECTION_HEADER) * nSectionNum);

	// 计算导出表 RAW
	IMAGE_EXPORT_DIRECTORY expDir;
	int nExportOffset = rva_to_raw(pSection, nSectionNum, ntHeader.OptionalHeader.DataDirectory[0].VirtualAddress);
	if (!nExportOffset) {
		cout << "RAW 获取失败" << endl;
		cFile.close();
		return 1;
	}

	// 读导出表
	cFile.seekg(nExportOffset, ios::beg);
	cFile.read((char*)&expDir, sizeof(IMAGE_EXPORT_DIRECTORY));

	// 读导出表头
	cFile.seekg(rva_to_raw(pSection, nSectionNum, expDir.Name), ios::beg);
	char szExportName[50];
	cFile.get(szExportName, 50);
	cout << "IMAGE_EXPORT_DIRECTORY.Name = " << szExportName << endl;

	// 获取到处函数个数
	int nAddressNum = expDir.NumberOfFunctions;

	// 获取导出表函数名
	shared_ptr<int> pShareName(new int[nAddressNum]);
	int* pName = pShareName.get();
	cFile.seekg(rva_to_raw(pSection, nSectionNum, expDir.AddressOfNames), ios::beg);
	cFile.read((char*)pName, sizeof(int) * nAddressNum);

	// 获取导出表函数序号
	shared_ptr<short> pShareOrder(new short[nAddressNum]);
	short* pOrder = pShareOrder.get();
	cFile.seekg(rva_to_raw(pSection, nSectionNum, expDir.AddressOfNameOrdinals), ios::beg);
	cFile.read((char*)pOrder, sizeof(short) * nAddressNum);

	// 获取导出表函数地址
	shared_ptr<int> pShareFunc(new int[nAddressNum]);
	int* pFunc = pShareFunc.get();
	cFile.seekg(rva_to_raw(pSection, nSectionNum, expDir.AddressOfFunctions), ios::beg);
	cFile.read((char*)pFunc, sizeof(int) * nAddressNum);

	// 遍历导出表
	char szFuncName[50];
	for (int i = 0; i < nAddressNum; i++) {
		cFile.seekg(rva_to_raw(pSection, nSectionNum, pName[i]), ios::beg);
		cFile.get(szFuncName, 50);
		char nFunc[32];
		sprintf_s(nFunc, "0x%s", pFunc[i]);
		//std::string FuncRVA(nFunc);
		std::string items = std::to_string(i) + "@" + nFunc + "@" + szFuncName;
		funlist.push_back(items);
		/*cout << "[Index:" << dec << i << "]\t"
			<< "[ID:" << hex << pOrder[i] << "]\t"
			<< "[RVA:" << pFunc[i] << "]\t"
			<< "[Name:" << szFuncName << "]\t"
			<< endl;*/
	}

	cFile.close();
}