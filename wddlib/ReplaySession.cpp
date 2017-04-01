#include "stdafx.h"
#include "ReplaySession.h"
#include "APIHookDB.h"

ReplaySession::ReplaySession()
{
}

void ReplaySession::Start(const std::vector<std::wstring>& args)
{
	trace_.Prepare(args[0]);
	fragment_ = trace_.GetFirstFragment();

	auto config = fragment_.get<ConfigTrace>();
	Session::StartProcess(config->exe_path.c_str(), config->cmdline.c_str(), config->env.c_str());
	time_slice_ = config->time_slice;

	fragment_ = fragment_.Next();

	OutputDebugStringW(config->exe_path.c_str());
	DebugLoop();
}

void ReplaySession::OnDebugString(ProcessID processId, ThreadID threadId, OUTPUT_DEBUG_STRING_INFO & info)
{
	Session::OnDebugString(processId, threadId, info);
}

void ReplaySession::OnRIP(ProcessID processId, ThreadID threadId, RIP_INFO & info)
{
	Session::OnRIP(processId, threadId, info);
}


void ReplaySession::OnLoadDLL(ProcessID processId, ThreadID threadId, LOAD_DLL_DEBUG_INFO & info)
{
	std::wstring path;
	if (info.hFile)
	{
		GetPathFromHandle(info.hFile, path);
	}

	Session::OnLoadDLL(processId, threadId, info);

	int bits = bits_[processId];
	if (bits == 33)
	{
		if (StrStrI(path.c_str(), L"syswow64\\ntdll.dll"))
		{
			DWORD sz = GetFileVersionInfoSizeW(path.c_str(), nullptr);
			if (sz)
			{
				std::vector<char> version_buffer(sz);
				GetFileVersionInfoW(path.c_str(), 0, sz, &version_buffer[0]);
				VS_FIXEDFILEINFO* vi;
				UINT vi_sz = sizeof(vi);
				VerQueryValueW(&version_buffer[0], L"\\", (LPVOID*)&vi, &vi_sz);
				uint64_t version = (((uint64_t)vi->dwProductVersionMS) << 32) + vi->dwProductVersionLS;

				syscallDB_ = SyscallDB("ntdll", version);
				PrepareSyscallDBForReplay();
			}
			TransformSyscallsToBreakpoints(processId, info.lpBaseOfDll);
			// NtGetTickCount
			LPVOID baseAddress = info.lpBaseOfDll;
			SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVA(path, L"RtlGetTickCount"),
				[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& ctx) {
				ctx.ax(fragment_.as<GetTickCountTrace>()->tick);
				fragment_ = fragment_.Next();
				SetSkipReturnHook();
			},
				nullptr);
			SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVA(path.c_str(), L"RtlGetSystemTimePrecise"),
				[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& ctx) {
				auto t = fragment_.as<RtlGetSystemTimePreciseTrace>();
				//WriteProcessMemory(process, (LPVOID)before.Rcx, &t->ft, sizeof(t->ft), nullptr);
				if (ctx.bits == 33)
				{
					ctx.ax(t->ft&0xFFFFFFFFFFFFFFFF);
					ctx.dx(t->ft>>32);
				}
				else
					ctx.ax(t->ft);
				fragment_ = fragment_.Next();
				SetSkipReturnHook();
			}, nullptr);
			//RemoveSyscallBreakpoint(processId, SyscallCode::NtQueryInformationProcess);
			//RemoveSyscallBreakpoint(processId, SyscallCode::NtRaiseException);
			//RemoveSyscallBreakpoint(processId, SyscallCode::NtContinue);
		}
		else if (StrStrI(path.c_str(), L"syswow64\\kernel32.dll"))
		{
			LPVOID baseAddress = info.lpBaseOfDll;
			SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVA(path, L"GetTickCount"),
				[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& ctx) {
				ctx.ax(fragment_.as<GetTickCountTrace>()->tick);
				fragment_ = fragment_.Next();
				SetSkipReturnHook();
			},
				nullptr);
		}
		else if (StrStrI(path.c_str(), L"syswow64\\cryptbase.dll"))
		{
			LPVOID baseAddress = info.lpBaseOfDll;
			SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVA(path, L"SystemFunction036"),
				[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& ctx) {
				auto trace = fragment_.as<RtlGenRandomTrace>();
				trace->generated;
				Match(ctx.arg1(), trace->generated.size());
				WriteProcessMemory(process, (LPVOID)ctx.arg0(), &trace->generated[0], trace->generated.size(), nullptr);
				fragment_ = fragment_.Next();
				SetSkipReturnHook();
			},
				nullptr);
		}
		RemoveSyscallBreakpoint(processId, SyscallCode::NtQueryInformationProcess);
		RemoveSyscallBreakpoint(processId, SyscallCode::NtRaiseException);
		RemoveSyscallBreakpoint(processId, SyscallCode::NtContinue);
	}
	else if (bits == 64)
	{
		// hack for win10 x64 1511 version
		if (StrStrI(path.c_str(), L"system32\\ntdll.dll"))
		{
			DWORD sz = GetFileVersionInfoSizeW(path.c_str(), nullptr);
			if (sz)
			{
				std::vector<char> version_buffer(sz);
				GetFileVersionInfoW(path.c_str(), 0, sz, &version_buffer[0]);
				VS_FIXEDFILEINFO* vi;
				UINT vi_sz = sizeof(vi);
				VerQueryValueW(&version_buffer[0], L"\\", (LPVOID*)&vi, &vi_sz);
				uint64_t version = (((uint64_t)vi->dwProductVersionMS) << 32) + vi->dwProductVersionLS;

				syscallDB_ = SyscallDB("ntdll", version);
				PrepareSyscallDBForReplay();
			}
			TransformSyscallsToBreakpoints(processId, info.lpBaseOfDll);
			// NtGetTickCount
			LPVOID baseAddress = info.lpBaseOfDll;
			SetAPIHook(processId, (uint64_t)baseAddress + 0xd66e0,
				[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& ctx) {
				ctx.ax(fragment_.as<GetTickCountTrace>()->tick);
				fragment_ = fragment_.Next();
				SetSkipReturnHook();
			},
				nullptr);
			SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVA(path.c_str(), L"RtlGetSystemTimePrecise"),
				[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& ctx) {
				auto t = fragment_.as<RtlGetSystemTimePreciseTrace>();
				//WriteProcessMemory(process, (LPVOID)before.Rcx, &t->ft, sizeof(t->ft), nullptr);
				ctx.ax(t->ft);
				fragment_ = fragment_.Next();
				SetSkipReturnHook();
			}, nullptr);
			//RemoveSyscallBreakpoint(processId, SyscallCode::NtQueryInformationProcess);
			//RemoveSyscallBreakpoint(processId, SyscallCode::NtRaiseException);
			//RemoveSyscallBreakpoint(processId, SyscallCode::NtContinue);
		}
		else if (StrStrI(path.c_str(), L"system32\\kernel32.dll"))
		{
			LPVOID baseAddress = info.lpBaseOfDll;
			SetAPIHook(processId, (uint64_t)baseAddress + 0x1b4c0,
				[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& ctx) {
				ctx.ax(fragment_.as<GetTickCountTrace>()->tick);
				fragment_ = fragment_.Next();
				SetSkipReturnHook();
			},
				nullptr);
		}
		else if (StrStrI(path.c_str(), L"system32\\cryptbase.dll"))
		{
			LPVOID baseAddress = info.lpBaseOfDll;
			SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVASimple(path, L"SystemFunction036"),
				[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& ctx) {
				auto trace = fragment_.as<RtlGenRandomTrace>();
				trace->generated;
				Match(ctx.arg1(), trace->generated.size());
				WriteProcessMemory(process, (LPVOID)ctx.arg0(), &trace->generated[0], trace->generated.size(), nullptr);
				fragment_ = fragment_.Next();
				SetSkipReturnHook();
			},
				nullptr);
		}
	}
}

void ReplaySession::OnUnloadDLL(ProcessID processId, ThreadID threadId, UNLOAD_DLL_DEBUG_INFO & info)
{
	Session::OnUnloadDLL(processId, threadId, info);
}

void ReplaySession::OnExitThread(ProcessID processId, ThreadID threadId, EXIT_THREAD_DEBUG_INFO & info)
{
	Session::OnExitThread(processId, threadId, info);
}

void ReplaySession::OnExitProcess(ProcessID processId, ThreadID threadId, EXIT_PROCESS_DEBUG_INFO & info)
{
	Session::OnExitProcess(processId, threadId, info);
}

DWORD ReplaySession::OnException(ProcessID processId, ThreadID threadId, EXCEPTION_DEBUG_INFO & info)
{
	return Session::OnException(processId, threadId, info);
}

void ReplaySession::OnCreateThread(ProcessID processId, ThreadID threadId, CREATE_THREAD_DEBUG_INFO & info)
{
	Session::OnCreateThread(processId, threadId, info);
}

void ReplaySession::OnCreateProcess(ProcessID processId, ThreadID threadId, CREATE_PROCESS_DEBUG_INFO & info)
{
	Session::OnCreateProcess(processId, threadId, info);
}

//void ReplaySession::MatchContext(ThreadContext* expected, ThreadContext* actual)
//{
//	if (expected == nullptr || actual == nullptr)
//		return;
//	if (memcmp(expected, actual, sizeof(ThreadContext)) != 0)
//	{
//		std::cerr << "ThreadContext diverges\n";
//		throw std::runtime_error("ThreadContext diverges");
//	}
//}

#define BEFORE(x) syscallDB_.find(SyscallCode:: ## x).before_handler = [&](HANDLE process, HANDLE thread, ArgPack& args, ThreadContext& ctx) 
#define AFTER(x) syscallDB_.find(SyscallCode:: ## x).after_handler = [&](HANDLE process, HANDLE thread, ArgPack& args, ThreadContext& before) 

void ReplaySession::PrepareSyscallDBForReplay()
{
	BEFORE(NtQueryPerformanceCounter)
	{
		//MatchContext(fragment_.ctx, &ctx);
		auto trace = fragment_.as<SyscallNtQueryPerformanceCounterTrace>();

		WriteProcessMemory(process, (LPVOID)ctx.arg0(), &trace->c, sizeof(trace->c), nullptr);
		if (ctx.arg1())
		{
			WriteProcessMemory(process, (LPVOID)ctx.arg1(), &trace->f, sizeof(trace->f), nullptr);
		}

		// skip syscall instruction
		ctx.ip(ctx.ip() + 2 - 1);
		ctx.set();

		fragment_ = fragment_.Next();

		SetSkipSyscall();
	};
}

#undef AFTER
#undef BEFORE