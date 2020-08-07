#pragma once
#include <winnt.h>

size_t add_section(const char* path, const char* wc_section_name, DWORD VirtualSize, const char* str_Characteristics, size_t  RvaRawData);
