#include "pch.h"
#include <iostream>
#include <windows.h>
#include "add_section.h"
#include <memory.h>
#include <strsafe.h>

using namespace std;

// Macros


// align x down to the nearest multiple of align. align must be a power of 2.
#define P2ALIGNDOWN(x, align) ((x) & -(align))
// align x up to the nearest multiple of align. align must be a power of 2.
#define P2ALIGNUP(x, align) (-(-(x) & -(align)))



/*USAGE: addscn.exe <path to PE file> <section name> <VirtualSize> <Characteristics>

VirtualSize can be in decimal(ex : 5021) or in hex(ex. 0x12c)
Characteristics can either be a hex DWORD like this : 0xC0000040
or the strings "text", "data" or "rdata" which mean :

text:  0x60000020 : IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
data : 0xC0000040 : IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
rdata : 0x40000040 : IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ*/
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


#ifdef _WIN64
#define MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define MACHINE IMAGE_FILE_MACHINE_I386
#endif

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE || ntHeaders->FileHeader.Machine != MACHINE) {
		wcout << L"Invalid PE file" << endl;
		UnmapViewOfFile((PVOID)pView);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return 0;
	}

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

