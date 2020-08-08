#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include "ExeToDll.h"

#pragma comment(lib,"user32.lib")

using namespace EXE2DLL;

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#ifdef _WIN64
typedef unsigned __int64 size_t;
#else
typedef unsigned int size_t;
#endif 
#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 0xA

BYTE* pe_ptr;
size_t v_size;
size_t out_size;
size_t last_sec;
bool is64b;

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;
typedef PBYTE ALIGNED_BUF;


class ApplyRelocCallback : public RelocBlockCallback
{
public:
    ApplyRelocCallback(bool _is64bit, ULONGLONG _oldBase, ULONGLONG _newBase)
        : RelocBlockCallback(_is64bit), oldBase(_oldBase), newBase(_newBase)
    {
    }

    virtual bool processRelocField(ULONG_PTR relocField)
    {
        if (is64bit) {
            ULONGLONG* relocateAddr = (ULONGLONG*)((ULONG_PTR)relocField);
            ULONGLONG rva = (*relocateAddr) - oldBase;
            (*relocateAddr) = rva + newBase;
        }
        else {
            DWORD* relocateAddr = (DWORD*)((ULONG_PTR)relocField);
            ULONGLONG rva = ULONGLONG(*relocateAddr) - oldBase;
            (*relocateAddr) = static_cast<DWORD>(rva + newBase);
        }
        return true;
    }

protected:
    ULONGLONG oldBase;
    ULONGLONG newBase;
};


bool validate_ptr(IN const void* buffer_bgn, IN SIZE_T buffer_size, IN const void* field_bgn, IN SIZE_T field_size)
{
    if (buffer_bgn == nullptr || field_bgn == nullptr) {
        return false;
    }
    BYTE* _start = (BYTE*)buffer_bgn;
    BYTE* _end = _start + buffer_size;

    BYTE* _field_start = (BYTE*)field_bgn;
    BYTE* _field_end = (BYTE*)field_bgn + field_size;

    if (_field_start < _start) {
        return false;
    }
    if (_field_end > _end) {
        return false;
    }
    return true;
}

BYTE* get_nt_hdrs(IN const BYTE* pe_buffer, IN OPTIONAL size_t buffer_size)
{
    if (!pe_buffer) return nullptr;

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (buffer_size != 0) {
        if (!validate_ptr((LPVOID)pe_buffer, buffer_size, (LPVOID)idh, sizeof(IMAGE_DOS_HEADER))) {
            return nullptr;
        }
    }
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
    if (buffer_size != 0) {
        if (!validate_ptr((LPVOID)pe_buffer, buffer_size, (LPVOID)inh, sizeof(IMAGE_NT_HEADERS32))) {
            return nullptr;
        }
    }
    if (IsBadReadPtr(inh, sizeof(IMAGE_NT_HEADERS32))) {
        return nullptr;
    }
    if (inh->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }
    return (BYTE*)inh;
}

WORD get_nt_hdr_architecture(IN const BYTE* pe_buffer)
{
    void* ptr = get_nt_hdrs(pe_buffer,0);
    if (!ptr) return 0;

    IMAGE_NT_HEADERS32* inh = static_cast<IMAGE_NT_HEADERS32*>(ptr);
    if (IsBadReadPtr(inh, sizeof(IMAGE_NT_HEADERS32))) {
        return 0;
    }
    return inh->OptionalHeader.Magic;
}

bool is64bit(IN const BYTE* pe_buffer)
{
    WORD arch = get_nt_hdr_architecture(pe_buffer);
    if (arch == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return true;
    }
    return false;
}

template <typename IMAGE_NT_HEADERS_T>
inline const IMAGE_FILE_HEADER* fetch_file_hdr(IN const BYTE* payload, IN const size_t buffer_size, IN const IMAGE_NT_HEADERS_T* payload_nt_hdr)
{
    if (!payload || !payload_nt_hdr) return nullptr;

    const IMAGE_FILE_HEADER* fileHdr = &(payload_nt_hdr->FileHeader);

    if (!validate_ptr((const LPVOID)payload, buffer_size, (const LPVOID)fileHdr, sizeof(IMAGE_FILE_HEADER))) {
        return nullptr;
    }
    return fileHdr;
}

const IMAGE_FILE_HEADER* get_file_hdr(IN const BYTE* payload, IN const size_t buffer_size)
{
    if (!payload) return nullptr;

    BYTE* payload_nt_hdr = get_nt_hdrs(payload,0);
    if (!payload_nt_hdr) {
        return nullptr;
    }
    if (is64bit(payload)) {
        return fetch_file_hdr(payload, buffer_size, (IMAGE_NT_HEADERS64*)payload_nt_hdr);
    }
    return fetch_file_hdr(payload, buffer_size, (IMAGE_NT_HEADERS32*)payload_nt_hdr);
}

bool isDll()
{
    const IMAGE_FILE_HEADER* hdr = get_file_hdr(pe_ptr, v_size);
    if (!hdr) return false;
    if (hdr->Characteristics & IMAGE_FILE_DLL) {
        return true;
    }
    return false;
}

IMAGE_DATA_DIRECTORY* get_directory_entry(IN const BYTE* pe_buffer, IN DWORD dir_id, IN bool allow_empty)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return nullptr;

    BYTE* nt_headers = get_nt_hdrs((BYTE*)pe_buffer,0);
    if (!nt_headers) return nullptr;

    IMAGE_DATA_DIRECTORY* peDir = nullptr;
    if (is64bit(pe_buffer)) {
        IMAGE_NT_HEADERS64* nt_headers64 = (IMAGE_NT_HEADERS64*)nt_headers;
        peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
    }
    else {
        IMAGE_NT_HEADERS32* nt_headers64 = (IMAGE_NT_HEADERS32*)nt_headers;
        peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
    }
    if (!allow_empty && peDir->VirtualAddress == NULL) {
        return nullptr;
    }
    return peDir;
}

bool process_reloc_block(BASE_RELOCATION_ENTRY* block, SIZE_T entriesNum, DWORD page, PVOID modulePtr, SIZE_T moduleSize, bool is64bit, RelocBlockCallback* callback)
{
    BASE_RELOCATION_ENTRY* entry = block;
    SIZE_T i = 0;
    for (i = 0; i < entriesNum; i++) {
        if (!validate_ptr(modulePtr, moduleSize, entry, sizeof(BASE_RELOCATION_ENTRY))) {
            break;
        }
        DWORD offset = entry->Offset;
        DWORD type = entry->Type;
        if (type == 0) {
            break;
        }
        if (type != RELOC_32BIT_FIELD && type != RELOC_64BIT_FIELD) {
            if (callback) { //print debug messages only if the callback function was set
                printf("[-] Not supported relocations format at %d: %d\n", (int)i, (int)type);
            }
            return false;
        }
        DWORD reloc_field = page + offset;
        if (reloc_field >= moduleSize) {
            if (callback) { //print debug messages only if the callback function was set
                printf("[-] Malformed field: %lx\n", reloc_field);
            }
            return false;
        }
        if (callback) {
            bool isOk = callback->processRelocField(((ULONG_PTR)modulePtr + reloc_field));
            if (!isOk) {
                std::cout << "[-] Failed processing reloc field at: " << std::hex << reloc_field << "\n";
                return false;
            }
        }
        entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)entry + sizeof(WORD));
    }
    return (i != 0);
}

bool process_relocation_table(IN PVOID modulePtr, IN SIZE_T moduleSize, IN RelocBlockCallback* callback)
{
    IMAGE_BASE_RELOCATION* reloc = NULL;
    IMAGE_DATA_DIRECTORY* relocDir = get_directory_entry((const BYTE*)modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC,true);
    if (relocDir == NULL) {
#ifdef _DEBUG
        std::cout << "[!] WARNING: no relocation table found!\n";
#endif
        return false;
    }
    if (!validate_ptr(modulePtr, moduleSize, relocDir, sizeof(IMAGE_DATA_DIRECTORY))) {
        std::cerr << "[!] Invalid relocDir pointer\n";
        return false;
    }
    DWORD maxSize = relocDir->Size;
    DWORD relocAddr = relocDir->VirtualAddress;
    bool is64b = is64bit((BYTE*)modulePtr);

    //IMAGE_BASE_RELOCATION* reloc = NULL;

    DWORD parsedSize = 0;
    while (parsedSize < maxSize) {
        reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + (ULONG_PTR)modulePtr);
        if (!validate_ptr(modulePtr, moduleSize, reloc, sizeof(IMAGE_BASE_RELOCATION))) {
#ifdef _DEBUG
            std::cerr << "[-] Invalid address of relocations\n";
#endif
            return false;
        }
        if (reloc->SizeOfBlock == 0) {
            break;
        }
        size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(DWORD)) / sizeof(WORD);
        DWORD page = reloc->VirtualAddress;

        BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)reloc + sizeof(DWORD) + sizeof(DWORD));
        if (!validate_ptr(modulePtr, moduleSize, block, sizeof(BASE_RELOCATION_ENTRY))) {
            std::cerr << "[-] Invalid address of relocations block\n";
            return false;
        }
        if (!process_reloc_block(block, entriesNum, page, modulePtr, moduleSize, is64b, callback)) {
            return false;
        }
        parsedSize += reloc->SizeOfBlock;
    }
    return (parsedSize != 0);
}

bool has_valid_relocation_table(IN const PBYTE modulePtr, IN const size_t moduleSize)
{
    return process_relocation_table(modulePtr, moduleSize, nullptr);
}

bool isConvertable()
{
    if (has_valid_relocation_table(pe_ptr, v_size)) {
        return true;
    }
    return false;
}

bool setExe()
{
    IMAGE_FILE_HEADER* hdr = const_cast<IMAGE_FILE_HEADER*> (get_file_hdr(pe_ptr, v_size));
    if (!hdr) return false;

    hdr->Characteristics ^= IMAGE_FILE_DLL;
    return true;
}

bool is_padding(const BYTE* cave_ptr, size_t cave_size, const BYTE padding)
{
    for (size_t i = 0; i < cave_size; i++) {
        if (cave_ptr[i] != padding) {
            return false;
        }
    }
    return true;
}

size_t get_sections_count(IN const BYTE* payload, IN const size_t buffer_size)
{
    const IMAGE_FILE_HEADER* fileHdr = get_file_hdr(payload, buffer_size);
    if (!fileHdr) {
        return 0;
    }
    return fileHdr->NumberOfSections;
}


template <typename IMAGE_NT_HEADERS_T>
inline const LPVOID fetch_opt_hdr(IN const BYTE* payload, IN const size_t buffer_size, IN const IMAGE_NT_HEADERS_T* payload_nt_hdr)
{
    if (!payload) return nullptr;

    const IMAGE_FILE_HEADER* fileHdr = fetch_file_hdr<IMAGE_NT_HEADERS_T>(payload, buffer_size, payload_nt_hdr);
    if (!fileHdr) {
        return nullptr;
    }
    const LPVOID opt_hdr = (const LPVOID)&(payload_nt_hdr->OptionalHeader);
    const size_t opt_size = fileHdr->SizeOfOptionalHeader;
    if (!validate_ptr((const LPVOID)payload, buffer_size, opt_hdr, opt_size)) {
        return nullptr;
    }
    return opt_hdr;
}

template <typename IMAGE_NT_HEADERS_T>
inline LPVOID fetch_section_hdrs_ptr(IN const BYTE* payload, IN const size_t buffer_size, IN const IMAGE_NT_HEADERS_T* payload_nt_hdr)
{
    const IMAGE_FILE_HEADER* fileHdr = fetch_file_hdr<IMAGE_NT_HEADERS_T>(payload, buffer_size, payload_nt_hdr);
    if (!fileHdr) {
        return nullptr;
    }
    const size_t opt_size = fileHdr->SizeOfOptionalHeader;
    BYTE* opt_hdr = (BYTE*)fetch_opt_hdr(payload, buffer_size, payload_nt_hdr);
    if (!validate_ptr((const LPVOID)payload, buffer_size, opt_hdr, opt_size)) {
        return nullptr;
    }
    //sections headers starts right after the end of the optional header
    return (LPVOID)(opt_hdr + opt_size);
}

PIMAGE_SECTION_HEADER get_section_hdr(IN const BYTE* payload, IN const size_t buffer_size, IN size_t section_num)
{
    if (!payload) return nullptr;

    const size_t sections_count = get_sections_count(payload, buffer_size);
    if (section_num >= sections_count) {
        return nullptr;
    }

    LPVOID nt_hdrs = get_nt_hdrs(payload,0);
    if (!nt_hdrs) return nullptr; //this should never happened, because the get_sections_count did not fail

    LPVOID secptr = nullptr;
    //get the beginning of sections headers:
    if (is64bit(payload)) {
        secptr = fetch_section_hdrs_ptr<IMAGE_NT_HEADERS64>(payload, buffer_size, (IMAGE_NT_HEADERS64*)nt_hdrs);
    }
    else {
        secptr = fetch_section_hdrs_ptr<IMAGE_NT_HEADERS32>(payload, buffer_size, (IMAGE_NT_HEADERS32*)nt_hdrs);
    }
    //get the section header of given number:
    PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)(
        (ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * section_num)
        );
    //validate pointer:
    if (!validate_ptr((const LPVOID)payload, buffer_size, (const LPVOID)next_sec, sizeof(IMAGE_SECTION_HEADER))) {
        return nullptr;
    }
    return next_sec;
}

PBYTE find_padding_cave(BYTE* modulePtr, size_t moduleSize, const size_t minimal_size, const DWORD req_charact)
{

    PIMAGE_SECTION_HEADER section_hdr = get_section_hdr(modulePtr, moduleSize, last_sec);
    size_t sec_count = get_sections_count(modulePtr, moduleSize);
    for (size_t i = 0; i < sec_count; i++) {
        PIMAGE_SECTION_HEADER section_hdr = get_section_hdr(modulePtr, moduleSize, i);
        if (section_hdr == nullptr) continue;
        if (!(section_hdr->Characteristics & req_charact)) continue;

        if (section_hdr->SizeOfRawData < minimal_size) continue;

        // we will be searching in the loaded, virtual image:
        DWORD sec_start = section_hdr->VirtualAddress;
        if (sec_start == 0) continue;

        DWORD sec_end = sec_start + section_hdr->SizeOfRawData;
#ifdef _DEBUG
        std::cout << "section: " << std::hex << sec_start << " : " << sec_end << std::endl;
#endif
        //offset from the end of the section:
        size_t cave_offset = section_hdr->SizeOfRawData - minimal_size;
        PBYTE cave_ptr = modulePtr + sec_start + cave_offset;
        if (!validate_ptr(modulePtr, moduleSize, cave_ptr, minimal_size)) {
#ifdef _DEBUG
            std::cout << "Invalid cave pointer" << std::endl;
#endif
            continue;
        }
        bool found = false;
        if (is_padding(cave_ptr, minimal_size, 0)) {
            found = true;
        }
        //if the section is code, check also code padding:
        if (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (is_padding(cave_ptr, minimal_size, 0xCC)) {
                found = true;
            }
        }
        if (found) {
            return cave_ptr;
        }
    }
#ifdef _DEBUG
    std::cout << "Cave not found" << std::endl;
#endif
    return nullptr;
}

BYTE* getCavePtr(size_t neededSize)
{
    BYTE* cave = find_padding_cave(pe_ptr, v_size, neededSize, IMAGE_SCN_MEM_EXECUTE);
    if (!cave) {
        std::cout << "Cave Not found!" << std::endl;
    }
    return cave;
}

inline long long int get_jmp_delta(ULONGLONG currVA, int instrLen, ULONGLONG destVA)
{
    long long int diff = destVA - (currVA + instrLen);
    return diff;
}

bool update_entry_point_rva(IN OUT BYTE* pe_buffer, IN DWORD value)
{
    bool is64b = is64bit(pe_buffer);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hdrs(pe_buffer,0);
    if (!payload_nt_hdr) {
        return false;
    }
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        payload_nt_hdr64->OptionalHeader.AddressOfEntryPoint = value;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        payload_nt_hdr32->OptionalHeader.AddressOfEntryPoint = value;
    }
    return true;
}

bool exeToDllPatch()
{
    BYTE back_stub32[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, //MOV EAX, 1
        0xC2, 0x0C, 0x00 //retn 0x0C
    };

    BYTE back_stub64[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, //MOV EAX, 1
        0xC3
    };

    BYTE* back_stub = back_stub32;
    size_t stub_size = sizeof(back_stub32);

    if (is64b) {
        back_stub = back_stub64;
        stub_size = sizeof(back_stub64);
    }
    size_t call_offset = stub_size - 6;

    BYTE* ptr = getCavePtr(stub_size);
    if (!ptr) {
        return false;
    }
    memmove(ptr, back_stub, stub_size);
    DWORD new_ep = DWORD(ptr - pe_ptr);
    return update_entry_point_rva(pe_ptr, new_ep);
}

bool dump_to_file(IN const char* out_path, IN PBYTE dump_data, IN size_t dump_size)
{
    if (!out_path || !dump_data || !dump_size) return false;

   
    HANDLE file = CreateFileA(out_path, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD errStatus = GetLastError();
        printf("\nError in Opening Device....Error Status = %d", errStatus);
#ifdef _DEBUG
        std::cerr << "Cannot open the file for writing!" << std::endl;
#endif
        CloseHandle(file);
        return false;
    }
    DWORD written_size = 0;
    bool is_dumped = false;
    if (WriteFile(file, dump_data, (DWORD)dump_size, &written_size, nullptr)) {
        is_dumped = true;
    }
#ifdef _DEBUG
    else {
        std::cerr << "Failed to write to the file : " << out_path << std::endl;
    }
#endif
    CloseHandle(file);
    return is_dumped;
}

ULONGLONG get_image_base(IN const BYTE* pe_buffer)
{
    bool is64b = is64bit(pe_buffer);

    BYTE* payload_nt_hdr = get_nt_hdrs(pe_buffer,0 );
    if (!payload_nt_hdr) {
        return 0;
    }
    ULONGLONG img_base = 0;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        img_base = payload_nt_hdr64->OptionalHeader.ImageBase;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        img_base = static_cast<ULONGLONG>(payload_nt_hdr32->OptionalHeader.ImageBase);
    }
    return img_base;
}

bool free_aligned(ALIGNED_BUF buffer, size_t buffer_size)
{
    if (buffer == nullptr) return true;
    if (!VirtualFree(buffer, 0, MEM_RELEASE)) {
#ifdef _DEBUG
        std::cerr << "Releasing failed" << std::endl;
#endif
        return false;
    }
    return true;
}

bool free_pe_buffer(ALIGNED_BUF buffer, size_t buffer_size)
{
    return free_aligned(buffer, buffer_size);
}

ALIGNED_BUF alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    if (!buffer_size) return NULL;

    ALIGNED_BUF buf = (ALIGNED_BUF)VirtualAlloc((LPVOID)desired_base, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
    return buf;
}

ALIGNED_BUF alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    return alloc_aligned(buffer_size, protect, desired_base);
}

bool update_image_base(IN OUT BYTE* payload, IN ULONGLONG destImageBase)
{
    bool is64b = is64bit(payload);
    BYTE* payload_nt_hdr = get_nt_hdrs(payload,0);
    if (!payload_nt_hdr) {
        return false;
    }
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        payload_nt_hdr64->OptionalHeader.ImageBase = (ULONGLONG)destImageBase;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        payload_nt_hdr32->OptionalHeader.ImageBase = (DWORD)destImageBase;
    }
    return true;
}

bool apply_relocations(PVOID modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase)
{
    const bool is64b = is64bit((BYTE*)modulePtr);
    ApplyRelocCallback callback(is64b, oldBase, newBase);
    return process_relocation_table(modulePtr, moduleSize, &callback);
}

bool relocate_module(IN BYTE* modulePtr, IN SIZE_T moduleSize, IN ULONGLONG newBase, IN ULONGLONG oldBase)
{
    if (modulePtr == NULL) {
        return false;
    }
    if (oldBase == 0) {
        oldBase = get_image_base(modulePtr);
    }
#ifdef _DEBUG
    printf("New Base: %llx\n", newBase);
    printf("Old Base: %llx\n", oldBase);
#endif
    if (newBase == oldBase) {
#ifdef _DEBUG
        printf("Nothing to relocate! oldBase is the same as the newBase!\n");
#endif
        return true; //nothing to relocate
    }
    if (apply_relocations(modulePtr, moduleSize, newBase, oldBase)) {
        return true;
    }
#ifdef _DEBUG
    printf("Could not relocate the module!\n");
#endif
    return false;
}

bool sections_virtual_to_raw(BYTE* payload, SIZE_T payload_size, OUT BYTE* destAddress, OUT SIZE_T* raw_size_ptr)
{
    if (!payload || !destAddress) return false;

    bool is64b = is64bit(payload);

    BYTE* payload_nt_hdr = get_nt_hdrs(payload,0);
    if (payload_nt_hdr == NULL) {
        std::cerr << "Invalid payload: " << std::hex << (ULONGLONG)payload << std::endl;
        return false;
    }

    IMAGE_FILE_HEADER* fileHdr = NULL;
    DWORD hdrsSize = 0;
    LPVOID secptr = NULL;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
        hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG) & (payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
        hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG) & (payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }

    //copy all the sections, one by one:
#ifdef _DEBUG
    std::cout << "Coping sections:" << std::endl;
#endif
    DWORD first_raw = 0;
    SIZE_T raw_end = hdrsSize;
    for (WORD i = 0; i < fileHdr->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!validate_ptr(payload, payload_size, next_sec, IMAGE_SIZEOF_SECTION_HEADER)) {
            return false;
        }

        LPVOID section_mapped = (BYTE*)payload + next_sec->VirtualAddress;
        LPVOID section_raw_ptr = destAddress + next_sec->PointerToRawData;
        SIZE_T sec_size = next_sec->SizeOfRawData;

        size_t new_end = sec_size + next_sec->PointerToRawData;
        if (new_end > raw_end) raw_end = new_end;

        if ((next_sec->VirtualAddress + sec_size) > payload_size) {
            std::cerr << "[!] Virtual section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            sec_size = (payload_size > next_sec->VirtualAddress) ? SIZE_T(payload_size - next_sec->VirtualAddress) : 0;
            std::cerr << "[!] Truncated to maximal size: " << std::hex << sec_size << ", buffer size: " << payload_size << std::endl;
        }
        if (next_sec->VirtualAddress > payload_size && sec_size != 0) {
            std::cerr << "[-] VirtualAddress of section is out ouf bounds: " << std::hex << next_sec->VirtualAddress << std::endl;
            return false;
        }
        if (next_sec->PointerToRawData + sec_size > payload_size) {
            std::cerr << "[-] Raw section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            return false;
        }
#ifdef _DEBUG
        std::cout << "[+] " << next_sec->Name << " to: " << std::hex << section_raw_ptr << std::endl;
#endif
        //validate source:
        if (!validate_ptr(payload, payload_size, section_mapped, sec_size)) {
            std::cerr << "[-] Section " << i << ":  out ouf bounds, skipping... " << std::endl;
            continue;
        }
        //validate destination:
        if (!validate_ptr(destAddress, payload_size, section_raw_ptr, sec_size)) {
            std::cerr << "[-] Section " << i << ":  out ouf bounds, skipping... " << std::endl;
            continue;
        }
        memcpy(section_raw_ptr, section_mapped, sec_size);
        if (first_raw == 0 || (next_sec->PointerToRawData < first_raw)) {
            first_raw = next_sec->PointerToRawData;
        }
    }
    if (raw_end > payload_size) raw_end = payload_size;
    if (raw_size_ptr != NULL) {
        (*raw_size_ptr) = raw_end;
    }

    //copy payload's headers:
    if (hdrsSize == 0) {
        hdrsSize = first_raw;
#ifdef _DEBUG
        std::cout << "hdrsSize not filled, using calculated size: " << std::hex << hdrsSize << "\n";
#endif
    }
    if (!validate_ptr(payload, payload_size, payload, hdrsSize)) {
        return false;
    }
    memcpy(destAddress, payload, hdrsSize);
    return true;
}

BYTE* pe_virtual_to_raw(    IN BYTE* payload,    IN size_t in_size,    IN ULONGLONG loadBase,    OUT size_t& out_size,    IN OPTIONAL bool rebuffer)
{
    BYTE* out_buf = (BYTE*)alloc_pe_buffer(in_size, PAGE_READWRITE,0);
    if (out_buf == NULL) return NULL; //could not allocate output buffer

    BYTE* in_buf = payload;
    if (rebuffer) {
        in_buf = (BYTE*)alloc_pe_buffer(in_size, PAGE_READWRITE,0);
        if (in_buf == NULL) {
            free_pe_buffer(out_buf, in_size);
            return NULL;
        }
        memcpy(in_buf, payload, in_size);
    }

    ULONGLONG oldBase = get_image_base(in_buf);
    bool isOk = true;
    // from the loadBase go back to the original base
    if (!relocate_module(in_buf, in_size, oldBase, loadBase)) {
        //Failed relocating the module! Changing image base instead...
        if (!update_image_base(in_buf, (ULONGLONG)loadBase)) {
            std::cerr << "[-] Failed relocating the module!" << std::endl;
            isOk = false;
        }
        else {
#ifdef _DEBUG
            std::cerr << "[!] WARNING: The module could not be relocated, so the ImageBase has been changed instead!" << std::endl;
#endif
        }
    }
    SIZE_T raw_size = 0;
    if (isOk) {
        if (!sections_virtual_to_raw(in_buf, in_size, out_buf, &raw_size)) {
            isOk = false;
        }
    }
    if (rebuffer && in_buf != NULL) {
        free_pe_buffer(in_buf, in_size);
        in_buf = NULL;
    }
    if (!isOk) {
        free_pe_buffer(out_buf, in_size);
        out_buf = NULL;
        raw_size = 0;
    }
    out_size = raw_size;
    return out_buf;
}

bool savePe(const char* out_path)
{
    size_t out_size = 0;
    /*in this case we need to use the original module base, because
    * the loaded PE was not relocated */
    ULONGLONG module_base = get_image_base(pe_ptr);

    BYTE* unmapped_module = pe_virtual_to_raw(pe_ptr, v_size,module_base,out_size,true);
    bool is_ok = false;
    if (unmapped_module) {
        if (dump_to_file(out_path, unmapped_module, out_size)) {
            is_ok = true;
        }
        free_pe_buffer(unmapped_module, v_size);
    }
    return is_ok;
}

ALIGNED_BUF load_file(IN const char* filename, OUT size_t& read_size)
{
    HANDLE file = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "Could not open file!" << std::endl;
#endif
        return nullptr;
    }
    HANDLE mapping = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!mapping) {
#ifdef _DEBUG
        std::cerr << "Could not create mapping!" << std::endl;
#endif
        CloseHandle(file);
        return nullptr;
    }
    BYTE* dllRawData = (BYTE*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!dllRawData) {
#ifdef _DEBUG
        std::cerr << "Could not map view of file" << std::endl;
#endif
        CloseHandle(mapping);
        CloseHandle(file);
        return nullptr;
    }
    size_t r_size = GetFileSize(file, 0);
    if (read_size != 0 && read_size <= r_size) {
        r_size = read_size;
    }
    if (IsBadReadPtr(dllRawData, r_size)) {
        std::cerr << "[-] Mapping of " << filename << " is invalid!" << std::endl;
        UnmapViewOfFile(dllRawData);
        CloseHandle(mapping);
        CloseHandle(file);
        return nullptr;
    }
    ALIGNED_BUF localCopyAddress = alloc_aligned(r_size, PAGE_READWRITE,0);
    if (localCopyAddress != nullptr) {
        memcpy(localCopyAddress, dllRawData, r_size);
        read_size = r_size;
    }
    else {
        read_size = 0;
#ifdef _DEBUG
        std::cerr << "Could not allocate memory in the current process" << std::endl;
#endif
    }
    UnmapViewOfFile(dllRawData);
    CloseHandle(mapping);
    CloseHandle(file);
    return localCopyAddress;
}

IMAGE_NT_HEADERS32* get_nt_hdrs32(IN const BYTE* payload)
{
    if (!payload) return nullptr;

    BYTE* ptr = get_nt_hdrs(payload,0);
    if (!ptr) return nullptr;

    if (!is64bit(payload)) {
        return (IMAGE_NT_HEADERS32*)ptr;
    }
    return nullptr;
}

IMAGE_NT_HEADERS64* get_nt_hdrs64(IN const BYTE* payload)
{
    if (payload == nullptr) return nullptr;

    BYTE* ptr = get_nt_hdrs(payload,0);
    if (!ptr) return nullptr;

    if (is64bit(payload)) {
        return (IMAGE_NT_HEADERS64*)ptr;
    }
    return nullptr;
}

DWORD get_image_size(IN const BYTE* payload)
{
    if (!get_nt_hdrs(payload,0)) {
        return 0;
    }
    DWORD image_size = 0;
    if (is64bit(payload)) {
        IMAGE_NT_HEADERS64* nt64 = get_nt_hdrs64(payload);
        image_size = nt64->OptionalHeader.SizeOfImage;
    }
    else {
        IMAGE_NT_HEADERS32* nt32 = get_nt_hdrs32(payload);
        image_size = nt32->OptionalHeader.SizeOfImage;
    }
    return image_size;
}

BYTE* load_no_sec_pe(BYTE* dllRawData, size_t r_size, OUT size_t& v_size, bool executable)
{
    ULONGLONG desired_base = 0;
    size_t out_size = (r_size < PAGE_SIZE) ? PAGE_SIZE : r_size;
    if (executable) {
        desired_base = get_image_base(dllRawData);
        out_size = get_image_size(dllRawData);
    }
    DWORD protect = (executable) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    BYTE* mappedPE = alloc_pe_buffer(out_size, protect, desired_base);
    if (!mappedPE) {
        return NULL;
    }
    memcpy(mappedPE, dllRawData, r_size);
    v_size = out_size;
    return mappedPE;
}

bool has_relocations(IN const BYTE* pe_buffer)
{
    IMAGE_DATA_DIRECTORY* relocDir = get_directory_entry(pe_buffer, IMAGE_DIRECTORY_ENTRY_BASERELOC,0);
    if (!relocDir) {
        return false;
    }
    return true;
}

bool sections_raw_to_virtual(IN const BYTE* payload, IN SIZE_T payloadSize, OUT BYTE* destBuffer, IN SIZE_T destBufferSize)
{
    if (!payload || !destBuffer) return false;

    bool is64b = is64bit(payload);

    BYTE* payload_nt_hdr = get_nt_hdrs(payload,0);
    if (payload_nt_hdr == NULL) {
        std::cerr << "Invalid payload: " << std::hex << (ULONGLONG)payload << std::endl;
        return false;
    }

    IMAGE_FILE_HEADER* fileHdr = NULL;
    DWORD hdrsSize = 0;
    LPVOID secptr = NULL;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
        hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG) & (payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
        hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG) & (payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }

    DWORD first_raw = 0;
    //copy all the sections, one by one:
    SIZE_T raw_end = 0;
    for (WORD i = 0; i < fileHdr->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!validate_ptr((const LPVOID)payload, destBufferSize, next_sec, IMAGE_SIZEOF_SECTION_HEADER)) {
            return false;
        }
        if (next_sec->PointerToRawData == 0 || next_sec->SizeOfRawData == 0) {
            continue; //skipping empty
        }
        LPVOID section_mapped = destBuffer + next_sec->VirtualAddress;
        LPVOID section_raw_ptr = (BYTE*)payload + next_sec->PointerToRawData;
        SIZE_T sec_size = next_sec->SizeOfRawData;
        raw_end = next_sec->SizeOfRawData + next_sec->PointerToRawData;

        if ((next_sec->VirtualAddress + sec_size) > destBufferSize) {
            std::cerr << "[!] Virtual section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            sec_size = (destBufferSize > next_sec->VirtualAddress) ? SIZE_T(destBufferSize - next_sec->VirtualAddress) : 0;
            std::cerr << "[!] Truncated to maximal size: " << std::hex << sec_size << ", buffer size:" << destBufferSize << std::endl;
        }
        if (next_sec->VirtualAddress >= destBufferSize && sec_size != 0) {
            std::cerr << "[-] VirtualAddress of section is out ouf bounds: " << std::hex << next_sec->VirtualAddress << std::endl;
            return false;
        }
        if (next_sec->PointerToRawData + sec_size > destBufferSize) {
            std::cerr << "[-] Raw section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            return false;
        }
        // validate source:
        if (!validate_ptr((const LPVOID)payload, payloadSize, section_raw_ptr, sec_size)) {
            std::cerr << "[-] Section " << i << ":  out ouf bounds, skipping... " << std::endl;
            continue;
        }
        // validate destination:
        if (!validate_ptr(destBuffer, destBufferSize, section_mapped, sec_size)) {
            std::cerr << "[-] Section " << i << ":  out ouf bounds, skipping... " << std::endl;
            continue;
        }
        memcpy(section_mapped, section_raw_ptr, sec_size);
        if (first_raw == 0 || (next_sec->PointerToRawData < first_raw)) {
            first_raw = next_sec->PointerToRawData;
        }
    }

    //copy payload's headers:
    if (hdrsSize == 0) {
        hdrsSize = first_raw;
#ifdef _DEBUG
        std::cout << "hdrsSize not filled, using calculated size: " << std::hex << hdrsSize << "\n";
#endif
    }
    if (!validate_ptr((const LPVOID)payload, destBufferSize, (const LPVOID)payload, hdrsSize)) {
        return false;
    }
    memcpy(destBuffer, payload, hdrsSize);
    return true;
}

BYTE* pe_raw_to_virtual(    IN const BYTE* payload,    IN size_t in_size,    OUT size_t& out_size,    IN OPTIONAL bool executable,    IN OPTIONAL ULONGLONG desired_base)
{
    //check payload:
    BYTE* nt_hdr = get_nt_hdrs(payload,0);
    if (nt_hdr == NULL) {
        std::cerr << "Invalid payload: " << std::hex << (ULONGLONG)payload << std::endl;
        return nullptr;
    }
    DWORD payloadImageSize = 0;

    bool is64 = is64bit(payload);
    if (is64) {
        IMAGE_NT_HEADERS64* payload_nt_hdr = (IMAGE_NT_HEADERS64*)nt_hdr;
        payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr = (IMAGE_NT_HEADERS32*)nt_hdr;
        payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;
    }

    DWORD protect = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

    //first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
    //when it will be ready, we will copy it into the space reserved in the target process
    BYTE* localCopyAddress = alloc_pe_buffer(payloadImageSize, protect, desired_base);
    if (localCopyAddress == NULL) {
        std::cerr << "Could not allocate memory in the current process" << std::endl;
        return NULL;
    }
    //printf("Allocated local memory: %p size: %x\n", localCopyAddress, payloadImageSize);
    if (!sections_raw_to_virtual(payload, in_size, (BYTE*)localCopyAddress, payloadImageSize)) {
        std::cerr << "Could not copy PE file" << std::endl;
        return NULL;
    }
    out_size = payloadImageSize;
    return localCopyAddress;
}

BYTE* load_pe_module(BYTE* dllRawData, size_t r_size, OUT size_t& v_size, bool executable, bool relocate)
{
    if (!get_nt_hdrs(dllRawData,0)) {
        return NULL;
    }
    if (get_sections_count(dllRawData, r_size) == 0) {
        return load_no_sec_pe(dllRawData, r_size, v_size, executable);
    }
    // by default, allow to load the PE at any base:
    ULONGLONG desired_base = NULL;
    // if relocating is required, but the PE has no relocation table...
    if (relocate && !has_relocations(dllRawData)) {
        // ...enforce loading the PE image at its default base (so that it will need no relocations)
        desired_base = get_image_base(dllRawData);
    }
    // load a virtual image of the PE file at the desired_base address (random if desired_base is NULL):
    BYTE* mappedDLL = pe_raw_to_virtual(dllRawData, r_size, v_size, executable, desired_base);
    if (mappedDLL) {
        //if the image was loaded at its default base, relocate_module will return always true (because relocating is already done)
        if (relocate && !relocate_module(mappedDLL, v_size, (ULONGLONG)mappedDLL,0)) {
            // relocating was required, but it failed - thus, the full PE image is useless
            printf("Could not relocate the module!");
            free_pe_buffer(mappedDLL, v_size);
            mappedDLL = NULL;
        }
    }
    else {
        printf("Could not allocate memory at the desired base!\n");
    }
    return mappedDLL;
}

BYTE* load_pe_module(const char* filename, OUT size_t& v_size, bool executable, bool relocate)
{
    size_t r_size = 0;
    BYTE* dllRawData = load_file(filename, r_size);
    if (!dllRawData) {
#ifdef _DEBUG
        std::cerr << "Cannot load the file: " << filename << std::endl;
#endif
        return NULL;
    }
    BYTE* mappedPE = load_pe_module(dllRawData, r_size, v_size, executable, relocate);
    free_pe_buffer(dllRawData,0);
    return mappedPE;
}

DWORD get_entry_point_rva(IN const BYTE* pe_buffer)
{
    bool is64b = is64bit(pe_buffer);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hdrs(pe_buffer,0);
    if (!payload_nt_hdr) {
        return 0;
    }
    DWORD value = 0;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        value = payload_nt_hdr64->OptionalHeader.AddressOfEntryPoint;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        value = payload_nt_hdr32->OptionalHeader.AddressOfEntryPoint;
    }
    return value;
}

int exe2dll(const char* filename, const  char* outfile)
{  
    pe_ptr = load_pe_module(filename, v_size, false, false);
    if (!pe_ptr)
    {
        MessageBoxA(nullptr, "Load moudle failed!", "EXE2DLL", MB_OK | MB_ICONERROR);
        return 2;
    }
    DWORD ep = get_entry_point_rva(pe_ptr);
    bool is64b = is64bit(pe_ptr);
    if (isDll()) {
        MessageBoxA(nullptr, "It is already a DLL!", "EXE2DLL", MB_OK | MB_ICONERROR);
        return -1;
    }
    if (!isConvertable()) {
        MessageBoxA(nullptr, "Converting not possible: relocation table missing or invalid!", "EXE2DLL", MB_OK | MB_ICONERROR);       
        return -1;
    }
    setExe();
    if (!exeToDllPatch()) 
    {    
        MessageBoxA(nullptr, "Could not convert!", "EXE2DLL", MB_OK | MB_ICONERROR);
        return -1;
    }
    if (savePe(outfile)) {
        MessageBoxA(nullptr, "File saved!", "EXE2DLL", MB_OK | MB_ICONINFORMATION);
    }
    return 0;
}