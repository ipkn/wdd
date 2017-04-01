#include "stdafx.h"
#include "Session.h"
#include "APIHookDB.h"
Session::Session()
{
}

void Session::StartProcess(const std::wstring & exe_path, const std::wstring & cmd, const std::wstring & env)
{
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	BOOL ret = CreateProcess(exe_path.c_str(), (LPWSTR)cmd.c_str(), nullptr, nullptr,
		FALSE,
		//CREATE_NEW_PROCESS_GROUP |
		CREATE_PRESERVE_CODE_AUTHZ_LEVEL |
		//CREATE_SUSPENDED |
		DEBUG_PROCESS |
		CREATE_UNICODE_ENVIRONMENT |
		//CREATE_NEW_CONSOLE |
		//|EXTENDED_STARTUPINFO_PRESENT
		0,
		nullptr,
		nullptr, // start directory
		&si,
		&pi
	);
	if (!ret)
	{
		std::ostringstream os;
		os << "CreateProcess error: " << GetLastError() << '\n';
		std::cerr << os.str();
		throw std::runtime_error(os.str().c_str());
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	current_task_ = { pi.dwProcessId, pi.dwThreadId };
}


bool Session::Schedule(bool suspend_current_thread)
{
	if (active_tasks_.empty())
	{
		// completed
		return false;
	}
	else if (active_tasks_.size() > 1)
	{
		if (suspend_current_thread)
			SuspendThread(threads_[current_task_.second]);
		auto it = active_tasks_.find(current_task_);
		if (it == active_tasks_.end())
		{
			throw std::runtime_error("invalid task scheduling");
		}
		++it;
		if (it == active_tasks_.end())
			it = active_tasks_.begin();
		current_task_ = it->first;
		ResumeThread(threads_[current_task_.second]);

		//{
		//	std::ostringstream os;
		//	os << "context switching to " << currentTask_.first << ' ' << currentTask_.second << "\n";
		//	OutputDebugStringA(os.str().c_str());
		//}
	}
	else
	{
		// Keep running current task
	}
	return true;
}

void Session::Reschedule()
{
	auto it = active_tasks_.upper_bound(current_task_);
	if (it == active_tasks_.end())
	{
		it = active_tasks_.begin();
	}
	if (it == active_tasks_.end())
	{
		current_task_.first = 0;
		current_task_.second = 0;
		return;
	}
	current_task_ = it->first;
	ResumeThread(threads_[current_task_.second]);
}


void Session::SetSingleStep(ProcessID processId, ThreadID threadId, ThreadContext& ctx,
	bool restore_inst, uint8_t original_inst, std::function<void()> handler)
{
	ctx.eflags(ctx.eflags() | 0x100);
	ctx.ip(ctx.ip() - 1);
	ctx.set();
	if (restore_inst)
		WriteProcessMemory(processes_[processId], (LPVOID)ctx.ip(), &original_inst, 1, nullptr);
	single_step_handlers_.emplace(std::make_pair(processId, ctx.ip()), SingleStepHandler{ std::move(handler) });
	ctx.ip(ctx.ip() + 1);
	ctx.eflags(ctx.eflags() & ~0x100);
}


void Session::TransformSyscallsToBreakpoints(ProcessID processId, LPVOID baseAddress)
{
	HANDLE process = processes_[processId];
	IMAGE_DOS_HEADER dos_header;
	ReadProcessMemory(process, baseAddress, &dos_header, sizeof(dos_header), nullptr);
	uint64_t pe_position = (uint64_t)baseAddress + dos_header.e_lfanew;

	if (bits_[processId] == 33)
	{
		IMAGE_NT_HEADERS32 nt_header;
		ReadProcessMemory(process, (LPVOID)pe_position, &nt_header, sizeof(nt_header), nullptr);

		for (uint64_t p = (uint64_t)baseAddress; p < (uint64_t)baseAddress + nt_header.OptionalHeader.SizeOfImage; p++)
		{
			// hack for win10 x64 1511 version
			uint8_t code[7],code_read[7];
			
			*(uint32_t*)(code + 1) = (uint32_t)PtrToInt(baseAddress)+0x8b5b0;
			code[0] = 0xBA;
			code[5] = 0xFF;
			code[6] = 0xD2;
			ReadProcessMemory(process, (LPVOID)p, code_read, 7, nullptr);
			//  		mov	edx,L4B30B5B0 4B280000

			if (!memcmp(code,code_read,7))
			{
				// syscall; ret;
				syscalls_.emplace(std::make_pair(processId, p+5), SyscallPoint{ code[5] });
				code[5] = 0xCC;
				WriteProcessMemory(process, (LPVOID)(p+5), code+5, 1, nullptr);
			}

		}
	}
	else
	{

		IMAGE_NT_HEADERS64 nt_header;
		ReadProcessMemory(process, (LPVOID)pe_position, &nt_header, sizeof(nt_header), nullptr);

		for (uint64_t p = (uint64_t)baseAddress; p < (uint64_t)baseAddress + nt_header.OptionalHeader.SizeOfImage; p++)
		{
			// hack for win10 x64 1511 version
			uint8_t code[3];
			ReadProcessMemory(process, (LPVOID)p, code, 3, nullptr);
			if (code[0] == 0x0f && code[1] == 0x05 && code[2] == 0xc3)
			{
				// syscall; ret;
				syscalls_.emplace(std::make_pair(processId, p), SyscallPoint{ code[0] });
				code[0] = 0xCC;
				WriteProcessMemory(process, (LPVOID)p, code, 1, nullptr);
			}

		}
	}
}

void Session::RemoveSyscallBreakpoint(ProcessID processId, SyscallCode code)
{
	if (ntdll_path_.empty())
		return;
	auto& info = syscallDB_.find(code);
	//HMODULE mod = LoadLibraryW(ntdll_path_.c_str());
	//uint64_t procAddr = (uint64_t)GetProcAddress(mod, info.name.c_str());
	uint64_t procAddr = APIHookDB::GetVA(ntdll_path_, s2ws(info.name));
	if (procAddr)
	{
		procAddr += nt_base_;
		auto it = syscalls_.lower_bound(std::make_pair(processId, procAddr));
		if (it != syscalls_.end())
		{
			WriteProcessMemory(processes_[processId], (LPVOID)it->first.second, &it->second.original_inst, 1, nullptr);
		}
	}
	//FreeLibrary(mod);
}

DWORD Session::OnException(ProcessID processId, ThreadID threadId, EXCEPTION_DEBUG_INFO & info)
{
	auto bits = bits_[processId];
	info.dwFirstChance;
	info.ExceptionRecord;
	if (!threads_.count(threadId))
	{
		OutputDebugStringA("invalid thread id");
		DebugBreak();
	}

	switch (info.ExceptionRecord.ExceptionCode)
	{
	case 0x4000001F: // sometimes wow64 breakopint hits with this code
	case EXCEPTION_BREAKPOINT:
		// First chance: Display the current 
		// instruction and register values. 
	{
		ThreadContext ctx(processes_[processId], threads_[threadId], bits, CONTEXT_FULL);
		{
			std::ostringstream os;
			os << "OnExceptionBreakpoint " << std::hex << info.ExceptionRecord.ExceptionCode << ' ' << ctx.ip();
			OutputDebugStringA(os.str().c_str());
		}

		auto key = std::make_pair(processId, ctx.ip() - 1);
		if (ctx.ip() - 1 == GetReturnHookAddress(processId))
		{
			OutputDebugStringA("return hook");
			std::pair<ProcessID, ThreadID> key{processId, threadId};

			auto it = return_hooks_.find(key);
			if (it == return_hooks_.end())
			{
				std::cerr << "invalid return hook occured\n";
				throw std::runtime_error("invalid return hook occured");
			}
			auto& info = it->second;
			ctx.ip(info.original_return_address);
			ctx.set();
			info.handler();
			return_hooks_.erase(it);
		}
		else if (syscalls_.count(key))
		{
			OutputDebugStringA("syscall");
			auto rip = ctx.ip() - 1;

			// NOTE HIGHWORD of eax contains some flags, I don't  know it yet
			int op = (int)(ctx.ax() & 0xFFFF); 
			if (!syscallDB_.has(op))
			{
				// ignore untracking syscall
				WriteProcessMemory(processes_[processId], (LPVOID)rip, &syscalls_[key].original_inst, 1, nullptr);
				ctx.ip(ctx.ip() - 1);
				ctx.set();
				return DBG_CONTINUE;
			}

			{
				std::ostringstream os;
				os << "SYSCALL " << std::hex << op << ' ' << syscallDB_.find(op).name << '\n';
				OutputDebugStringA(os.str().c_str());
			}

			ArgPack pack;

			if (syscallDB_.find(op).before_handler)
				syscallDB_.find(op).before_handler(processes_[processId], threads_[threadId], pack, ctx);

			if (!GetAndClearSkipSyscall())
			SetSingleStep(processId, threadId, ctx, true, syscalls_[key].original_inst,
				[this, rip, op, processId, threadId, pack = std::move(pack), ctx]{
				uint8_t inst = 0xCC;
			WriteProcessMemory(processes_[processId], (LPVOID)rip, &inst, 1, nullptr);

			if (ctx.bits == 33)
			{
				ThreadContext ctx_now(processes_[processId], threads_[threadId], ctx.bits);

				SetReturnHook(processId, threadId, ctx_now, [this, op, processId, threadId, ctx, pack] {
						if (syscallDB_.find(op).after_handler)
							syscallDB_.find(op).after_handler(processes_[processId], threads_[threadId], const_cast<ArgPack&>(pack), const_cast<ThreadContext&>(ctx));
				});
			}
			else if (ctx.bits == 64)
			{ 
				if (syscallDB_.find(op).after_handler)
					syscallDB_.find(op).after_handler(processes_[processId], threads_[threadId], const_cast<ArgPack&>(pack), const_cast<ThreadContext&>(ctx));
			}
			});
		}
		else if (api_handlers_.count(key))
		{
			{
				std::ostringstream os;
				os << "API " << std::hex << key.second;
				OutputDebugStringA(os.str().c_str());
			}
			auto& api_handler = api_handlers_[key];
			ArgPack pack;
			if (api_handler.before_handler)
				api_handler.before_handler(processes_[processId], threads_[threadId], pack, ctx);
			if (!GetAndClearSkipReturnHook())
			{

				if (api_handler.after_handler)
				SetReturnHook(processId, threadId, ctx,
					[this, processId, threadId, pack = std::move(pack), &api_handler, ctx]{
				if (api_handler.after_handler)
					{
						api_handler.after_handler(processes_[processId], threads_[threadId], const_cast<ArgPack&>(pack), const_cast<ThreadContext&>(ctx));
					}
				});
				SetSingleStep(processId, threadId, ctx, true, api_handler.original_inst,
					[rip = ctx.ip() - 1, this, processId]{
					uint8_t inst = 0xCC;
					WriteProcessMemory(processes_[processId], (LPVOID)rip, &inst, 1, nullptr);
				});
			}
			else
			{
				// simulate return
				FastReturn(processId, threadId, ctx);
			}
		}
		else if (breakpoints_.count(key))
		{
			OutputDebugStringA("HIT BP");
			auto rip = ctx.ip() - 1;
			auto& bp = breakpoints_[key];
			ArgPack pack;
			if (bp.before_handler)
				bp.before_handler(processes_[processId], threads_[threadId], pack);
			SetSingleStep(processId, threadId, ctx, true, bp.original_inst,
				[this, rip, key, &bp, processId, threadId, pack=std::move(pack)] {
				if (bp.after_handler)
					bp.after_handler(processes_[processId], threads_[threadId], const_cast<ArgPack&>(pack));
				if (bp.oneshot)
				{
					breakpoints_.erase(key);
				}
				else
				{
					uint8_t inst = 0xCC;
					WriteProcessMemory(processes_[processId], (LPVOID)rip, &inst, 1, nullptr);
				}
			});
		}
		else if (!first_breakpoint_[processId])
		{
			first_breakpoint_[processId] = true;
			OnFirstBreakpoint(processId);
		}
		else
		{
			OutputDebugStringW(L"Unexpected debug break occured: \n");
		}
	}
	break;

	case 0x4000001E:
	case EXCEPTION_SINGLE_STEP:
		// First chance: Update the display of the 
		// current instruction and register values. 
	{
		ThreadContext ctx(processes_[processId], threads_[threadId], bits);

		auto it = single_step_handlers_.lower_bound(std::make_pair(processId, ctx.ip()));

		if (it != single_step_handlers_.begin())
		{
			--it;
			auto& handler = it->second;
			handler.handler();
			{
				ctx.eflags(ctx.eflags()&~0x100);
				ctx.set();
			}
			single_step_handlers_.erase(it);
		}
		else
		{
			OutputDebugStringW(L"PANICE invalid single step");
		}
	}
	break;

	case EXCEPTION_ACCESS_VIOLATION:
		// First chance: Pass this on to the system. 
		// Last chance: Display an appropriate error. 
		return DBG_EXCEPTION_NOT_HANDLED;

	case EXCEPTION_DATATYPE_MISALIGNMENT:
		// First chance: Pass this on to the system. 
		// Last chance: Display an appropriate error. 
		return DBG_EXCEPTION_NOT_HANDLED;

	case DBG_CONTROL_C:
		// First chance: Pass this on to the system. 
		// Last chance: Display an appropriate error. 
		return DBG_EXCEPTION_NOT_HANDLED;

	default:
		// Handle other exceptions. 
		OutputDebugStringW(L"PANIC other exception\n");
		{
			ThreadContext ctx(processes_[processId], threads_[threadId], bits_[processId], CONTEXT_FULL);

			std::ostringstream os;
			os << "exception " << std::hex << info.ExceptionRecord.ExceptionCode << " at " << ctx.ip() << '\n';
			OutputDebugStringA(os.str().c_str());
		}
		DebugActiveProcessStop(processId);
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	return DBG_CONTINUE;
}

void Session::OnCreateThread(ProcessID processId, ThreadID threadId, CREATE_THREAD_DEBUG_INFO & info)
{
	std::ostringstream os;
	DWORD newThreadId = GetThreadId(info.hThread);
	os << processId << ' ' << threadId << ' ' << "CreateThread: " << newThreadId << '\n';
	OutputDebugStringA(os.str().c_str());
	threads_[newThreadId] = info.hThread;

	active_tasks_.emplace(std::make_pair(processId, newThreadId), 0);
	SuspendThread(info.hThread);
}

void Session::OnCreateProcess(ProcessID processId, ThreadID threadId, CREATE_PROCESS_DEBUG_INFO & info)
{
	std::ostringstream os;
	DWORD newProcessId = GetProcessId(info.hProcess);
	DWORD newThreadId = GetThreadId(info.hThread);
	os << processId << ' ' << threadId << ' ' << "CreateProcess: " << GetProcessId(info.hProcess) << " with thread: " << GetThreadId(info.hThread) << '\n';
	if (info.hFile)
	{
		std::wstring path;
		GetPathFromHandle(info.hFile, path);
		os << ws2s(path) << '\n';
	}

	BOOL isWow64 = FALSE;
	IsWow64Process(info.hProcess, &isWow64);
	if (isWow64)
		bits_[processId] = 33;
	else
	{
#ifdef _AMD64_
		bits_[processId] = 64;
#else
		bits_[processId] = 32;
		std::cerr << "Fatal: Not supported: 32 bit windows" << std::endl;
		throw std::runtime_error("Fatal: Not supported: 32 bit windows");
#endif
	}

	OutputDebugStringA(os.str().c_str());
	processes_[newProcessId] = info.hProcess;
	threads_[newThreadId] = info.hThread;
	active_tasks_.emplace(std::make_pair(newProcessId, newThreadId), 0);

	PrepareReturnHookPoint(info.hProcess);

	if (!(current_task_.first == newProcessId && current_task_.second == newThreadId))
	{
		SuspendThread(threads_[newThreadId]);
	}

	// hook(info.hProcess)

	CloseHandle(info.hFile);
}

void Session::OnDebugString(ProcessID processId, ThreadID threadId, OUTPUT_DEBUG_STRING_INFO & info)
{
	if (info.fUnicode)
	{
		std::wstring s;
		s.resize(info.nDebugStringLength + 1);
		ReadProcessMemory(processes_[processId], info.lpDebugStringData, &s[0], info.nDebugStringLength * 2 + 2, nullptr);
		OutputDebugStringW(s.c_str());
	}
	else
	{
		std::string s;
		s.resize(info.nDebugStringLength + 1);
		ReadProcessMemory(processes_[processId], info.lpDebugStringData, &s[0], info.nDebugStringLength + 1, nullptr);
		OutputDebugStringA(s.c_str());
	}
	OutputDebugStringA("\n");
}

void Session::OnRIP(ProcessID processId, ThreadID threadId, RIP_INFO & info)
{
	std::ostringstream os;
	os << processId << ' ' << threadId << ' ' << info.dwError << ' ' << info.dwType << '\n';
	OutputDebugStringA(os.str().c_str());
}

void Session::OnFirstBreakpoint(ProcessID processId)
{
}

void Session::SetSkipSyscall()
{
	skip_current_syscall_ = true;
}

bool Session::GetAndClearSkipSyscall()
{
	auto ret = skip_current_syscall_;
	skip_current_syscall_ = false;
	return ret;
}

void Session::SetAPIHook(ProcessID processId, uint64_t address, 
	std::function<void(HANDLE, HANDLE, ArgPack&, ThreadContext&)> before_handler, 
	std::function<void(HANDLE, HANDLE, ArgPack&, ThreadContext&)> after_handler)
{
	{
		std::ostringstream os;
		os << "SetAPIHook " << std::hex << address;
		OutputDebugStringA(os.str().c_str());
	}
	HANDLE process = processes_[processId];
	APIHandler api_handler;
	ReadProcessMemory(process, (LPVOID)address, &api_handler.original_inst, 1, nullptr);

	uint8_t inst = 0xCC;
	WriteProcessMemory(process, (LPVOID)address, &inst, 1, nullptr);

	api_handler.before_handler = std::move(before_handler);
	api_handler.after_handler = std::move(after_handler);
	
	api_handlers_.emplace(std::make_pair(processId, address), std::move(api_handler));

}

void Session::PrepareReturnHookPoint(HANDLE process)
{
	LPVOID base = VirtualAllocEx(process, nullptr, 1024, MEM_COMMIT | MEM_RESERVE /*| MEM_TOP_DOWN*/, 
		PAGE_EXECUTE_READWRITE);
	VirtualProtectEx(process, base, 1024, PAGE_EXECUTE_READWRITE, nullptr);
	unsigned char inst[] = { 0xCC, 0xC3 };
	WriteProcessMemory(process, base, &inst, 2, nullptr);

	hook_base[GetProcessId(process)] = (uint64_t)base;
}

void Session::SetSkipReturnHook()
{
	skip_return_hook_ = true;
}

bool Session::GetAndClearSkipReturnHook()
{
	auto ret = skip_return_hook_;
	skip_return_hook_ = false;
	return ret;
}

void Session::FastReturn(ProcessID processId, ThreadID threadId, ThreadContext& ctx)
{
	ctx.ip(GetReturnHookAddress(processId)+1);
	ctx.set();
}

uint64_t Session::GetReturnHookAddress(ProcessID processId)
{
	return hook_base[processId];
}

void Session::SetReturnHook(ProcessID processId, ThreadID threadId, ThreadContext & ctx, std::function<void()> handler)
{
	uint64_t ret_addr = 0;
	SIZE_T sz = 8;
	if (ctx.bits == 33)
		sz = 4;
	ReadProcessMemory(processes_[processId], (LPVOID)ctx.sp(), &ret_addr, sz, nullptr);
	auto fake_ret_addr = GetReturnHookAddress(processId);
	WriteProcessMemory(processes_[processId], (LPVOID)ctx.sp(), &fake_ret_addr, sz, nullptr);

	//std::cerr << "ReturnHook set " << processId << ' ' << threadId << ' ' << "ret_addr " << std::hex << ret_addr << std::dec << '\n';
	return_hooks_.emplace(std::make_pair(processId, threadId), ReturnHookInfo{ ret_addr, std::move(handler) });
}

std::vector<char> Session::ReadProcessMemoryVector(HANDLE process, LPVOID pos, uint32_t sz)
{
	std::vector<char> v(sz);
	ReadProcessMemory(process, pos, &v[0], sz, nullptr);
	return v;
}

std::wstring Session::ReadProcessMemoryUnicodeString(HANDLE process, LPVOID pos)
{
	std::wstring ret;
	WCHAR ch;
	while (1)
	{
		ReadProcessMemory(process, pos, &ch, sizeof(ch), nullptr);
		if (ch == 0)
			break;
		ret += ch;
		pos = (WCHAR*)pos + 1;
	}
	return ret;
}

void Session::SetBreakpoint(DWORD processId, uint64_t va, bool oneshot, std::function<void(HANDLE, HANDLE, ArgPack&)> before_handler, std::function<void(HANDLE, HANDLE, ArgPack&)> after_handler)
{
	if (!va)
		return;
	uint8_t inst;
	ReadProcessMemory(processes_[processId], (LPVOID)va, &inst, 1, nullptr);
	uint8_t new_inst = 0xCC;
	WriteProcessMemory(processes_[processId], (LPVOID)va, &new_inst, 1, nullptr);
	breakpoints_.emplace(std::make_pair( processId, va ), BreakpointInfo{ inst, std::move(before_handler), std::move(after_handler), oneshot });
}

void Session::OnExitThread(ProcessID processId, ThreadID threadId, EXIT_THREAD_DEBUG_INFO & info)
{
	info.dwExitCode;
	std::ostringstream os;
	os << processId << ' ' << threadId << " ExitThread\n";
	OutputDebugStringA(os.str().c_str());
	if (threads_.count(threadId))
	{
		threads_.erase(threadId);
	}
	active_tasks_.erase(std::make_pair(processId, threadId));
	Reschedule();
}

void Session::OnExitProcess(ProcessID processId, ThreadID threadId, EXIT_PROCESS_DEBUG_INFO & info)
{
	info.dwExitCode;
	std::ostringstream os;
	os << processId << ' ' << threadId << " ExitProcess\n";
	OutputDebugStringA(os.str().c_str());

	if (threads_.count(threadId))
	{
		threads_.erase(threadId);
	}
	if (processes_.count(processId))
	{
		processes_.erase(processId);
	}

	for (auto it = active_tasks_.begin(); it != active_tasks_.end();)
	{
		if (it->first.first == processId)
		{
			threads_.erase(it->first.second);
			it = active_tasks_.erase(it);
		}
		else
		{
			++it;
		}
	}
	Reschedule();
}

void Session::OnUnloadDLL(ProcessID processId, ThreadID threadId, UNLOAD_DLL_DEBUG_INFO & info)
{
	std::ostringstream os;
	os << processId << ' ' << threadId << " UnloadDLL: " << (unsigned long long)info.lpBaseOfDll << '\n';
	OutputDebugStringA(os.str().c_str());
	modules_.erase((uint64_t)info.lpBaseOfDll);
}

void Session::OnLoadDLL(ProcessID processId, ThreadID threadId, LOAD_DLL_DEBUG_INFO& info)
{
	std::ostringstream os;
	os << processId << ' ' << threadId << " LoadDLL: ";
	std::wstring path;
	if (info.hFile)
	{
		GetPathFromHandle(info.hFile, path);
		os << ws2s(path);
	}
	else
	{
		os << "(null)";
	}
	os << ' ' << (unsigned long long)info.lpBaseOfDll << '\n';
	OutputDebugStringA(os.str().c_str());

	modules_.emplace((uint64_t)info.lpBaseOfDll, ModuleInfo{ (uint64_t)info.lpBaseOfDll, GetFileSize(info.hFile, nullptr)} );
	
	if (bits_[processId] == 33)
		if (StrStrIW(path.c_str(), L"syswow64\\ntdll.dll"))
		{
			ntdll_path_ = path;
			nt_base_ = (uint64_t)info.lpBaseOfDll;
		}
		else
			if (StrStrIW(path.c_str(), L"system32\\ntdll.dll"))
			{
				ntdll_path_ = path;
				nt_base_ = (uint64_t)info.lpBaseOfDll;
			}
	CloseHandle(info.hFile);
}

void Session::DebugLoop()
{
	auto self = this;
	//hook(pi.hProcess);

	if (debugLoopBreaked)
	{
		debugLoopBreaked = false;
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continueStatus);
	}

	while (1)
	{
		continueStatus = DBG_CONTINUE;
		ZeroMemory(&de, sizeof(de));
		BOOL ret = WaitForDebugEvent(&de, time_slice_);
		if (!ret)
		{
			// Timeout occured
			if (!Schedule())
				return;

			continue;
		}
		else
		{
			switch (de.dwDebugEventCode)
			{
			case EXCEPTION_DEBUG_EVENT:
				continueStatus = self->OnException(de.dwProcessId, de.dwThreadId, de.u.Exception);
				break;
			case CREATE_THREAD_DEBUG_EVENT:
				self->OnCreateThread(de.dwProcessId, de.dwThreadId, de.u.CreateThread);
				break;
			case CREATE_PROCESS_DEBUG_EVENT:
				self->OnCreateProcess(de.dwProcessId, de.dwThreadId, de.u.CreateProcessInfo);
				break;
			case EXIT_THREAD_DEBUG_EVENT:
				self->OnExitThread(de.dwProcessId, de.dwThreadId, de.u.ExitThread);
				break;
			case EXIT_PROCESS_DEBUG_EVENT:
				self->OnExitProcess(de.dwProcessId, de.dwThreadId, de.u.ExitProcess);
				break;
			case LOAD_DLL_DEBUG_EVENT:
				self->OnLoadDLL(de.dwProcessId, de.dwThreadId, de.u.LoadDll);
				break;
			case UNLOAD_DLL_DEBUG_EVENT:
				self->OnUnloadDLL(de.dwProcessId, de.dwThreadId, de.u.UnloadDll);
				break;
			case OUTPUT_DEBUG_STRING_EVENT:
				self->OnDebugString(de.dwProcessId, de.dwThreadId, de.u.DebugString);
				break;
			case RIP_EVENT:
				// panic
				self->OnRIP(de.dwProcessId, de.dwThreadId, de.u.RipInfo);
				break;
			}
		}
		if (breakDebugLoop_)
		{
			debugLoopBreaked = true;
			break;
		}
		if (IsCurrentTaskInvalid())
			break;
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continueStatus);
	}
}

bool Session::IsCurrentTaskInvalid()
{
	return
		current_task_.first == 0 &&
		current_task_.second == 0;
}