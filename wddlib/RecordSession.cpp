#include "stdafx.h"
#include "RecordSession.h"
#include "util.h"
#include "APIHookDB.h"

RecordSession::RecordSession(const std::vector<std::wstring>& args)
{
	// TODO change timeSlice_ from option
	time_slice_ = 5;

	auto env_raw = GetEnvironmentStringsW();
	size_t env_sz = 0;
	while (1)
	{
		if (env_raw[env_sz] == 0 && env_raw[env_sz + 1] == 0)
			break;
		env_sz++;
	}
	std::wstring env(env_raw, env_sz+2);
	FreeEnvironmentStringsW(env_raw);
	auto cmdline = BuildCommandLine(args);
	trace_.Prepare(args[0]);

	WCHAR absPath[2048];
	GetFullPathNameW(args[0].c_str(), 2048, absPath, nullptr);
	trace_.Record(nullptr, ConfigTrace{ absPath, cmdline, env, time_slice_ });
	Session::StartProcess(args[0], cmdline, env);
}

void RecordSession::Start()
{
	DebugLoop();
}

void RecordSession::OnLoadDLL(ProcessID processId, ThreadID threadId, LOAD_DLL_DEBUG_INFO & info)
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
		if (StrStrI(path.c_str(), L"SysWOW64\\ntdll.dll"))
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
				PrepareSyscallDBForRecord();
			}
			TransformSyscallsToBreakpoints(processId, info.lpBaseOfDll);
			// RtlGetTickCount
			{
				LPVOID baseAddress = info.lpBaseOfDll;
				//0xd66e0
				SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVA(path, L"RtlGetTickCount"),
					nullptr,
					[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& before) {
					ThreadContext ctx(process, thread, before.bits);

					trace_.Record(&before, GetTickCountTrace{ (DWORD)ctx.ax() });

				});
				SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVA(path.c_str(), L"RtlGetSystemTimePrecise"),
					nullptr,
					[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& before) {
					RtlGetSystemTimePreciseTrace t;
					//ReadProcessMemory(process, (LPVOID)before.Rcx, &t.ft, sizeof(t.ft), nullptr);
					ThreadContext ctx(process, thread, before.bits);
					t.ft = ctx.ax()+((ctx.dx())<<32);
					trace_.Record(&before, t);
				});
			}
			RemoveSyscallBreakpoint(processId, SyscallCode::NtQueryInformationProcess);
			RemoveSyscallBreakpoint(processId, SyscallCode::NtRaiseException);
			RemoveSyscallBreakpoint(processId, SyscallCode::NtContinue);
		}
		else if (StrStrI(path.c_str(), L"SysWOW64\\kernel32.dll"))
		{
			LPVOID baseAddress = info.lpBaseOfDll;
			// GetTickCount
			{
				//0x1b4c0
				SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVA(path, L"GetTickCount"),
					nullptr,
					[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& before) {
					ThreadContext ctx(process, thread, before.bits);

					trace_.Record(&before, GetTickCountTrace{ (DWORD)ctx.ax() });

				});
			}
		}
		else if (StrStrI(path.c_str(), L"SysWOW64\\cryptbase.dll"))
		{
			LPVOID baseAddress = info.lpBaseOfDll;
			SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVA(path, L"SystemFunction036"),
				nullptr,
				[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& ctx) {
				RtlGenRandomTrace t;
				t.generated.resize(ctx.arg1());
				ReadProcessMemory(process, (LPVOID)ctx.arg0(), &t.generated[0], t.generated.size(), nullptr);
				trace_.Record(&ctx, std::move(t));
			});
		}
	}
	else if (bits_[processId] == 64)
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
				PrepareSyscallDBForRecord();
			}
			TransformSyscallsToBreakpoints(processId, info.lpBaseOfDll);
			// NtGetTickCount
			{
				LPVOID baseAddress = info.lpBaseOfDll;
				SetAPIHook(processId, (uint64_t)baseAddress + 0xd66e0,
					nullptr,
					[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& before) {
					ThreadContext ctx(process, thread, before.bits);
					trace_.Record(&before, GetTickCountTrace{ (DWORD)ctx.ax() });

				});
				SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVA(path.c_str(), L"RtlGetSystemTimePrecise"),
					nullptr,
					[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& before) {
					RtlGetSystemTimePreciseTrace t;
					ThreadContext ctx(process, thread, before.bits);
					t.ft = ctx.ax();
					trace_.Record(&before, t);
				});
			}
			//RemoveSyscallBreakpoint(processId, SyscallCode::NtQueryInformationProcess);
			//RemoveSyscallBreakpoint(processId, SyscallCode::NtRaiseException);
			//RemoveSyscallBreakpoint(processId, SyscallCode::NtContinue);
		}
		else if (StrStrI(path.c_str(), L"system32\\kernel32.dll"))
		{
			LPVOID baseAddress = info.lpBaseOfDll;
			// GetTickCount
			{
				SetAPIHook(processId, (uint64_t)baseAddress + 0x1b4c0,
					nullptr,
					[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& before) {
					ThreadContext ctx(process, thread, before.bits);
					trace_.Record(&before, GetTickCountTrace{ (DWORD)ctx.ax() });

				});
			}
		}
		else if (StrStrI(path.c_str(), L"system32\\cryptbase.dll"))
		{
			LPVOID baseAddress = info.lpBaseOfDll;
			SetAPIHook(processId, (uint64_t)baseAddress + APIHookDB::GetVASimple(path, L"SystemFunction036"),
				nullptr,
				[&](HANDLE process, HANDLE thread, ArgPack& pack, ThreadContext& ctx) {
				RtlGenRandomTrace t;
				t.generated.resize(ctx.arg1());
				ReadProcessMemory(process, (LPVOID)ctx.arg0(), &t.generated[0], t.generated.size(), nullptr);
				trace_.Record(&ctx, std::move(t));
			});
		}
	}
}

void RecordSession::OnUnloadDLL(ProcessID processId, ThreadID threadId, UNLOAD_DLL_DEBUG_INFO & info)
{
	Session::OnUnloadDLL(processId, threadId, info);
}

void RecordSession::OnExitThread(ProcessID processId, ThreadID threadId, EXIT_THREAD_DEBUG_INFO & info)
{
	Session::OnExitThread(processId, threadId, info);
}

void RecordSession::OnExitProcess(ProcessID processId, ThreadID threadId, EXIT_PROCESS_DEBUG_INFO & info)
{
	Session::OnExitProcess(processId, threadId, info);
}

DWORD RecordSession::OnException(ProcessID processId, ThreadID threadId, EXCEPTION_DEBUG_INFO & info)
{
	return Session::OnException(processId, threadId, info);
}

void RecordSession::OnCreateThread(ProcessID processId, ThreadID threadId, CREATE_THREAD_DEBUG_INFO & info)
{
	Session::OnCreateThread(processId, threadId, info);
}

void RecordSession::OnCreateProcess(ProcessID processId, ThreadID threadId, CREATE_PROCESS_DEBUG_INFO & info)
{
	Session::OnCreateProcess(processId, threadId, info);
}

void RecordSession::OnDebugString(ProcessID processId, ThreadID threadId, OUTPUT_DEBUG_STRING_INFO & info)
{
	Session::OnDebugString(processId, threadId, info);
}

void RecordSession::OnRIP(ProcessID processId, ThreadID threadId, RIP_INFO & info)
{
	Session::OnRIP(processId, threadId, info);
}

#define BEFORE(x) syscallDB_.find(SyscallCode:: ## x).before_handler = [&](HANDLE process, HANDLE thread, ArgPack& args, ThreadContext& ctx) 
#define AFTER(x) syscallDB_.find(SyscallCode:: ## x).after_handler = [&](HANDLE process, HANDLE thread, ArgPack& args, ThreadContext& before) 

void RecordSession::PrepareSyscallDBForRecord()
{
	BEFORE(NtClose)
	{
		{
			std::ostringstream os;
			os << "before NtClose: close " << std::hex << (uint64_t)ctx.arg0() << '\n';
			OutputDebugStringA(os.str().c_str());
		}
	};
	BEFORE(NtRaiseException)
	{
		DebugActiveProcessStop(GetProcessId(process));
	};
	AFTER(NtCreateFile)
	{
		uint64_t p = 0;
		ReadProcessMemory(process, (LPVOID)before.arg0(), &p, sizeof(intptr_t), nullptr);

		std::ostringstream os;
		os << "NtCreateFile returns " << std::hex << p << '\n';
		OutputDebugStringA(os.str().c_str());
	};
	BEFORE(NtCreateFile)
	{
		uint64_t p = 0;
		if (ctx.bits == 33)
		{
			ReadProcessMemory(process, (LPVOID)(ctx.arg2() + 8), &p, 4, nullptr);
			ReadProcessMemory(process, (LPVOID)(p + 4), &p, 4, nullptr);
		}
		else if (ctx.bits == 64)
		{
			ReadProcessMemory(process, (LPVOID)(ctx.arg2() + 12), &p, 8, nullptr);
			ReadProcessMemory(process, (LPVOID)(p + 4), &p, 8, nullptr);
		}
		std::wstring wstr;
		if (p)
			wstr = ReadProcessMemoryUnicodeString(process, (LPVOID)p);
		else
			wstr = L"(nullptr)";
		{
			std::wostringstream os;
			os << L"before NtCreateFile: " << wstr << L'\n';
			OutputDebugStringW(os.str().c_str());
		}

	};
	AFTER(NtDeviceIoControlFile)
	{
		OutputDebugStringW(L"after NtDeviceIoControlFile\n");
		if (before.arg(9))
		{
			auto ret = ReadProcessMemoryVector(process, (LPVOID)before.arg(8), before.arg(9));
			for (size_t i = 0; i < ret.size(); i ++)
			{
				if (!isprint((uint8_t)ret[i]))
					ret[i] = '.';
			}
			ret.push_back('\n');
			ret.push_back(0);
			OutputDebugStringA(&ret[0]);
		}
	};
	BEFORE(NtDeviceIoControlFile)
	{
		std::wostringstream os;
		os << std::hex << "before NtDeviceIoControlFile"
			<< "\n\tFileHandle " << ctx.arg0()
			<< "\n\tEvent " << ctx.arg1()
			<< "\n\tApcRoutine " << ctx.arg2()
			<< "\n\tCode " << ctx.arg(5)
			<< "\n\tInputBuffer " << ctx.arg(6)
			<< "\n\tInputBufferLen " << ctx.arg(7)
			<< "\n\tOutputBuffer " << ctx.arg(8)
			<< "\n\tOutputBufferLen " << ctx.arg(9)
			<< "\n";
		if (ctx.arg(7))
		{
			auto ret = ReadProcessMemoryVector(process, (LPVOID)ctx.arg(6), ctx.arg(7));
			for (size_t i = 0; i < ret.size(); i++)
			{
				if (!isprint((uint8_t)ret[i]))
					ret[i] = '.';
			}
			ret.push_back('\n');
			ret.push_back(0);
			OutputDebugStringA(&ret[0]);
		}

		OutputDebugStringW(os.str().c_str());
	};
	BEFORE(NtWriteFile)
	{
		std::wostringstream os;
		os << std::hex << "before NtWriteFile"
			<< "\n\tFileHandle " << ctx.arg0()
			<< "\n\tEvent " << ctx.arg1()
			<< "\n\tApcRoutine " << ctx.arg2()
			<< "\n\tBuffer " << ctx.arg(5)
			<< "\n\tLen " << ctx.arg(6)
			<< "\n";
		if (ctx.arg(6))
		{
			auto ret = ReadProcessMemoryVector(process, (LPVOID)ctx.arg(5), ctx.arg(6));
			for (size_t i = 0; i < ret.size(); i++)
			{
				if (!isprint((uint8_t)ret[i]))
					ret[i] = '.';
			}
			ret.push_back('\n');
			ret.push_back(0);
			OutputDebugStringA(&ret[0]);
		}
		OutputDebugStringW(os.str().c_str());
	};
	BEFORE(NtOpenKey)
	{
		uint64_t p=0;
		if (ctx.bits == 33)
		{
			ReadProcessMemory(process, (LPVOID)(ctx.arg2()+8), &p, 4, nullptr);
			ReadProcessMemory(process, (LPVOID)(p+4), &p, 4, nullptr);
		}
		else if (ctx.bits == 64)
		{
			ReadProcessMemory(process, (LPVOID)(ctx.arg2()+12), &p, 8, nullptr);
			ReadProcessMemory(process, (LPVOID)(p+4), &p, 8, nullptr);
		}
		auto wstr = ReadProcessMemoryUnicodeString(process, (LPVOID)p);
		{
			std::wostringstream os;
			os << L"before NtOpenKey: " << wstr << L'\n';
			OutputDebugStringW(os.str().c_str());
		}
	};
	BEFORE(NtQueryPerformanceCounter)
	{
		args[0] = ctx.arg0();
		args[1] = ctx.arg2();
	};
	AFTER(NtQueryPerformanceCounter)
	{
		LARGE_INTEGER c, f{};
		ReadProcessMemory(process, (LPVOID)args[0], &c, sizeof(c), nullptr);
		{
			std::stringstream os;
			os << "NtQueryPerformanceCounter counter: " << c.QuadPart << '\n';
			OutputDebugStringA(os.str().c_str());
		}

		if (args[1])
		{
			ReadProcessMemory(process, (LPVOID)args[1], &f, sizeof(f), nullptr);
			{
				std::stringstream os;
				os << "                             freq: " << f.QuadPart << '\n';
				OutputDebugStringA(os.str().c_str());
			}

		}
		trace_.Record(&before, SyscallNtQueryPerformanceCounterTrace{ c, f });
	};
	BEFORE(NtQuerySystemInformation)
	{
		{
			std::ostringstream os;
			os << "before NtQuerySystemInformation: "
				<< " class " << ctx.arg1() << " inSize " << ctx.arg3() << '\n';
			OutputDebugStringA(os.str().c_str());
		}
	};
	BEFORE(NtQuerySystemInformationEx)
	{
		{
			std::ostringstream os;
			os << "before NtQuerySystemInformationEx: "
				<< " class " << ctx.arg0() << '\n';
			OutputDebugStringA(os.str().c_str());
		}
	};
	//BEFORE(NtQueryInformationProcess)
	//{
	//	ctx.Rcx; // arg1: ProcessHandle
	//	ctx.Rdx; // arg2: class
	//	{
	//		std::ostringstream os;
	//		os << "before NtQueryInformationProcess: "
	//			<< " ProcessHandle " << std::hex << (ctx.Rcx) << std::dec << " class " << ctx.Rdx << " inSize " << ctx.R9 << '\n';
	//		// 36: ProcessCookie: used for some unique value per process
	//		if (ctx.Rdx != 36)
	//			OutputDebugStringA(os.str().c_str());
	//	}
	//};
	//AFTER(NtQueryInformationProcess)
	//{
	//	if (before.Rdx == 36)
	//	{
	//		// before.R8 :  PVOID ProcessInformation
	//		uint32_t cookie;
	//		ReadProcessMemory(process, (LPVOID)before.R8, (LPVOID)&cookie, 4, nullptr);
	//		trace_.Record(&before, SyscallNtQueryInformationProcessProcessCookieTrace{ cookie });
	//	}
	//};
	BEFORE(NtTerminateProcess)
	{
		{
			std::ostringstream os;
			os << "before NtTerminateProcess: called from " << GetProcessId(process) << " to close "
				<< std::hex << ctx.arg0() << '\n';
			OutputDebugStringA(os.str().c_str());
		}
	};
}

#undef AFTER
#undef BEFORE