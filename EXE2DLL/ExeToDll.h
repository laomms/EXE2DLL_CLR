#pragma once
#include <Windows.h>

int exe2dll(const char* filename, const  char* outfile);
bool validate_ptr(IN const void* buffer_bgn, IN SIZE_T buffer_size, IN const void* field_bgn, IN SIZE_T field_size);
PIMAGE_SECTION_HEADER get_section_hdr(IN const BYTE* payload, IN const size_t buffer_size, IN size_t section_num);
bool is64bit(IN const BYTE* pe_buffer);
const IMAGE_FILE_HEADER* get_file_hdr(IN const BYTE* payload, IN const size_t buffer_size);
PIMAGE_SECTION_HEADER get_section_hdr(IN const BYTE* payload, IN const size_t buffer_size, IN size_t section_num);
size_t get_sections_count(IN const BYTE* payload, IN const size_t buffer_size);

namespace EXE2DLL{

    class RelocBlockCallback
    {
    public:
        RelocBlockCallback(bool _is64bit)
            : is64bit(_is64bit)
        {
        }

        virtual bool processRelocField(ULONG_PTR relocField) = 0;

    protected:
        bool is64bit;
    };


}

