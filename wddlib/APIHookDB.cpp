#include "stdafx.h"
#include "APIHookDB.h"
#include "Symbols.h"
#include "util.h"

std::unordered_map<std::wstring, std::vector<std::wstring>> APIHookDB::hook_points = {
	{ L"system32\\kernel32.dll", std::vector<std::wstring>{L"GetTickCount" } },
	{ L"system32\\ntdll.dll", std::vector<std::wstring>{L"RtlGetTickCount" } },
	{ L"system32\\cryptbase.dll", std::vector<std::wstring>{L"SystemFunction036" }},
};

uint64_t APIHookDB::GetVA(const std::wstring & path, const std::wstring & function_name)
{
	// TODO save to trace folder

	return SymbolTable(path).GetVA(function_name);
}

uint64_t APIHookDB::GetVASimple(const std::wstring& path, const std::wstring& function_name)
{
	HMODULE mod = LoadLibraryW(path.c_str());
	if (!mod)
		return 0;
	auto addr = GetProcAddress(mod, ws2s(function_name).c_str());
	if (!addr)
		return 0;
	FreeLibrary(mod);
	return (uint64_t)addr - (uint64_t)mod;
}
