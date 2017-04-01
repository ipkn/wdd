#pragma once

#include "util.h"
#include "ThreadContext.h"
#include "SyscallCodes.h"

struct SyscallInfo
{
	std::string name;
	SyscallCode code;
	int internal_op;

	// for record
	std::function<void(HANDLE, HANDLE, ArgPack&, ThreadContext& ctx)> before_handler;
	std::function<void(HANDLE, HANDLE, ArgPack&, ThreadContext& before)> after_handler;
};

class RecordTrace;
class ReplayTrace;

class SyscallDB
{
public:
	SyscallDB() {}
	SyscallDB(const std::string& type, uint64_t version);

	bool has(SyscallCode code) { return syscalls_.count(code) > 0; }
	bool has(int internal_op) { return syscallsByInternalOp_.count(internal_op) > 0; }

	SyscallInfo& find(SyscallCode code);
	SyscallInfo& find(int internal_op);
	SyscallInfo& find(const std::string& name);
private:
	std::unordered_map<SyscallCode, SyscallInfo> syscalls_;
	std::unordered_map<int, SyscallInfo*> syscallsByInternalOp_;
	std::unordered_map<std::string, SyscallInfo*> syscallsByName_;
};