#include "stdafx.h"
#include "syscalls.h"
#include "Trace.h"
namespace
{
	//using namespace SyscallCode;
	// for fast test
	std::unordered_map<uint64_t, std::vector<SyscallInfo>> syscallInfos = {

		{0x000a0000295a02a0ull,	{
#define XX(a,b,c,d) {#a, SyscallCode:: ## a, c},
#include "syscall_defines.h"
#undef XX
		}},
	};
}

SyscallDB::SyscallDB(const std::string & type, uint64_t version)
{
	assert(type == "ntdll");
	assert(version = 0x000a0000295a02a0ull);
	assert(syscallInfos.count(version) > 0);
	for (auto& info : syscallInfos[version])
	{
		if (info.internal_op == -1)
			continue;
		syscalls_[info.code] = info;
		syscallsByInternalOp_.emplace(info.internal_op, &syscalls_[info.code]);
		syscallsByName_.emplace(info.name, &syscalls_[info.code]);
	}
}

SyscallInfo & SyscallDB::find(SyscallCode code)
{
	return syscalls_[code];
}

SyscallInfo& SyscallDB::find(int op)
{
	return *syscallsByInternalOp_[op];
}

SyscallInfo & SyscallDB::
find(const std::string & name)
{
	return *syscallsByName_[name];
}

