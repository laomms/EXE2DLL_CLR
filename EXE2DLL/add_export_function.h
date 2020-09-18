#pragma once
#include <wtypes.h>
#include <iostream> 
#include <string> 
#include <vector>
using namespace std;

BOOL add_export_table(const char* file_name, const char* section_name, const char* FuncName, size_t FuncRva);
BOOL modify_export_table(const char* file_name, const char* old_name, const char* FuncName, size_t FuncRva);
BOOL delete_export_table(const char* file_name, const char* func_name,  size_t FuncRva);

int GetExpTableList(const char* file_name, std::vector<std::string>& funlist);
size_t add_section(const char* path, const char* wc_section_name, DWORD VirtualSize, const char* str_Characteristics, size_t  RvaRawData);
PIMAGE_SECTION_HEADER get_last_section(IN const PBYTE pe_buffer, IN size_t pe_size, IN bool is_raw);