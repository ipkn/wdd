#pragma once

class APIHookDB
{
public:
	static uint64_t GetVASimple(const std::wstring& path, const std::wstring& function_name);
	static uint64_t GetVA(const std::wstring& path, const std::wstring& function_name);
	static std::unordered_map<std::wstring, std::vector<std::wstring>> hook_points;
};