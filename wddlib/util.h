#pragma once

#pragma once

void
ArgvQuote(
	const std::wstring& Argument,
	std::wstring& CommandLine,
	bool Force
);

std::wstring BuildCommandLine(const std::vector<std::wstring>& args);

#pragma warning(disable: 4996) // wcsnicmp deprecated
#include <winternl.h>

// This makro assures that INVALID_HANDLE_VALUE (0xFFFFFFFF) returns FALSE
#define IsConsoleHandle(h) (((((ULONG_PTR)h) & 0x10000003) == 0x3) ? TRUE : FALSE)

enum OBJECT_INFORMATION_CLASS_extended
{
	//ObjectBasicInformation,
	ObjectNameInformation = 1,
	//ObjectTypeInformation,
	ObjectAllInformation = 3,
	ObjectDataInformation = 4,
};

struct OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name; // defined in winternl.h
	WCHAR NameBuffer;
};

typedef NTSTATUS(NTAPI* t_NtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS_extended Info, PVOID Buffer, ULONG BufferSize, PULONG ReturnLength);

DWORD GetNtPathFromHandle(HANDLE h_File, std::wstring& ps_NTPath);
DWORD GetDosPathFromNtPath(const WCHAR* u16_NTPath, std::wstring& ps_DosPath);

DWORD GetPathFromHandle(HANDLE hFile, std::wstring& path);

using ArgPack = std::unordered_map<uint64_t, uint64_t>;

std::string ws2s(const std::wstring& wstr);
std::wstring s2ws(const std::string& str);
