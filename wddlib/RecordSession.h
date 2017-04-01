#pragma once
#include "trace.h"
#include "Session.h"

class RecordSession : public Session
{
public:
	RecordSession(const std::vector<std::wstring>& args);

	void Start();

	void OnLoadDLL(ProcessID processId, ThreadID threadId, LOAD_DLL_DEBUG_INFO& info);
	void OnExitThread(ProcessID processId, ThreadID threadId, EXIT_THREAD_DEBUG_INFO& info);
	void OnExitProcess(ProcessID processId, ThreadID threadId, EXIT_PROCESS_DEBUG_INFO& info);
	DWORD OnException(ProcessID processId, ThreadID threadId, EXCEPTION_DEBUG_INFO& info);
	void OnCreateThread(ProcessID processId, ThreadID threadId, CREATE_THREAD_DEBUG_INFO& info);
	void OnCreateProcess(ProcessID processId, ThreadID threadId, CREATE_PROCESS_DEBUG_INFO& info);
	void OnUnloadDLL(ProcessID processId, ThreadID threadId, UNLOAD_DLL_DEBUG_INFO& info);
	void OnDebugString(ProcessID processId, ThreadID threadId, OUTPUT_DEBUG_STRING_INFO& info);
	void OnRIP(ProcessID processId, ThreadID threadId, RIP_INFO& info);

private:
	void PrepareSyscallDBForRecord();
		
	RecordTrace trace_;
};
