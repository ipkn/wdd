#pragma once
#include "syscalls.h"
#include "ThreadContext.h"

using Task = int;

using ProcessID = DWORD;
using ThreadID = DWORD;

struct ModuleInfo
{
	uint64_t base;
	uint32_t size;
};

struct ReturnHookInfo
{
	uint64_t original_return_address;
	std::function<void()> handler;
};

struct APIHandler
{
	uint8_t original_inst;
	std::function<void(HANDLE, HANDLE, ArgPack&, ThreadContext& ctx)> before_handler;
	std::function<void(HANDLE, HANDLE, ArgPack&, ThreadContext& ctx)> after_handler;
};

struct BreakpointInfo
{
	uint8_t original_inst;
	std::function<void(HANDLE, HANDLE, ArgPack&)> before_handler;
	std::function<void(HANDLE, HANDLE, ArgPack&)> after_handler;
	bool oneshot{ false };
	BreakpointInfo(uint8_t original_inst,
		std::function<void(HANDLE, HANDLE, ArgPack&)> before_handler,
		std::function<void(HANDLE, HANDLE, ArgPack&)> after_handler,
		bool oneshot)
		: original_inst(original_inst),
		before_handler(std::move(before_handler)),
		after_handler(std::move(after_handler)),
		oneshot(oneshot)
	{}
	BreakpointInfo() {}
};

struct SyscallPoint
{
	uint8_t original_inst;
};

struct SingleStepHandler
{
	std::function<void()> handler;
};

class Session
{
public:
	Session();

	// change current task while some task is running
	bool Schedule(bool suspend_current_thread = true);

	// current task completed; find another
	void Reschedule();

	void StartProcess(const std::wstring& exe_path, const std::wstring& cmd, const std::wstring& env);

	template <typename T, typename U>
	void Match(T&& expected, U&& actual)
	{
		if (expected != actual)
		{
			std::cerr << "replay diverges!\n" << std::hex << "Expected: " << expected << "Actual: " << actual << '\n';
			throw std::runtime_error("replay diverges!");
		}
	}

	void SetDebugLoopBreak(bool set = true)
	{
		breakDebugLoop_ = set;
	}
	
	bool IsCurrentTaskInvalid();
	void DebugLoop();

protected:
	void TransformSyscallsToBreakpoints(ProcessID processId, LPVOID baseAddress);
	void RemoveSyscallBreakpoint(ProcessID processId, SyscallCode code);

	virtual void OnLoadDLL(ProcessID processId, ThreadID threadId, LOAD_DLL_DEBUG_INFO& info);
	virtual void OnExitThread(ProcessID processId, ThreadID threadId, EXIT_THREAD_DEBUG_INFO& info);
	virtual void OnExitProcess(ProcessID processId, ThreadID threadId, EXIT_PROCESS_DEBUG_INFO& info);
	virtual DWORD OnException(ProcessID processId, ThreadID threadId, EXCEPTION_DEBUG_INFO& info);
	virtual void OnCreateThread(ProcessID processId, ThreadID threadId, CREATE_THREAD_DEBUG_INFO& info);
	virtual void OnCreateProcess(ProcessID processId, ThreadID threadId, CREATE_PROCESS_DEBUG_INFO& info);
	virtual void OnUnloadDLL(ProcessID processId, ThreadID threadId, UNLOAD_DLL_DEBUG_INFO& info);
	virtual void OnDebugString(ProcessID processId, ThreadID threadId, OUTPUT_DEBUG_STRING_INFO& info);
	virtual void OnRIP(ProcessID processId, ThreadID threadId, RIP_INFO & info);
	virtual void OnFirstBreakpoint(ProcessID processId);

	void SetSingleStep(ProcessID processId, ThreadID threadId, ThreadContext& ctx,
		bool restore_inst, uint8_t original_inst, std::function<void()> handler);

	void SetSkipSyscall();
	bool GetAndClearSkipSyscall();

	void SetAPIHook(ProcessID processId, 
		uint64_t address,
		std::function<void(HANDLE, HANDLE, ArgPack&, ThreadContext&)> before_handler,
		std::function<void(HANDLE, HANDLE, ArgPack&, ThreadContext&)> after_handler);

	void PrepareReturnHookPoint(HANDLE process);
	void SetSkipReturnHook();
	bool GetAndClearSkipReturnHook();
	void FastReturn(ProcessID processId, ThreadID threadId, ThreadContext& ctx);

	uint64_t GetReturnHookAddress(ProcessID processId);
	void SetReturnHook(ProcessID processId, ThreadID threadId, ThreadContext& ctx, std::function<void()> handler);

	std::vector<char> ReadProcessMemoryVector(HANDLE process, LPVOID pos, uint32_t sz);
	std::wstring ReadProcessMemoryUnicodeString(HANDLE process, LPVOID pos);

	void SetBreakpoint(DWORD processId, uint64_t va, bool oneshot,
		std::function<void(HANDLE, HANDLE, ArgPack&)> before_handler,
		std::function<void(HANDLE, HANDLE, ArgPack&)> after_handler);
protected:
	// intentionally ordered container
	std::map<std::pair<ProcessID, ThreadID>, Task> active_tasks_;
	std::pair<ProcessID, ThreadID> current_task_;
	bool need_reschedule_{ false };

	std::unordered_map<ProcessID, HANDLE> processes_;
	std::unordered_map<ThreadID, HANDLE> threads_;

	std::map<std::pair<ProcessID, uint64_t>, SyscallPoint> syscalls_;
	std::map<std::pair<ProcessID, uint64_t>, BreakpointInfo> breakpoints_;

	std::map<std::pair<ProcessID, uint64_t>, SingleStepHandler> single_step_handlers_;

	std::map<std::pair<ProcessID, uint64_t>, APIHandler> api_handlers_;
	std::map<std::pair<ProcessID, ThreadID>, ReturnHookInfo> return_hooks_;

	std::unordered_map<ProcessID, int> bits_;
	std::unordered_map<ProcessID, bool> first_breakpoint_;

	std::unordered_map<uint64_t, ModuleInfo> modules_;

	SyscallDB syscallDB_;
	std::wstring ntdll_path_;
	uint64_t nt_base_;
	bool skip_current_syscall_{ false };
	bool skip_return_hook_{ false };

	uint32_t time_slice_{ 5 };

	std::unordered_map<ProcessID, uint64_t> hook_base;

	bool breakDebugLoop_{ false };
	bool debugLoopBreaked{ false };
	DEBUG_EVENT de;
	DWORD continueStatus;
};