#pragma once

#include "../wddlib/ReplaySession.h"
#include "../wddlib/Symbols.h"

struct Frame
{
	uint32_t id;
	uint32_t threadId;
	CComPtr<IDiaSymbol> func;
	CComPtr<IDiaStackFrame> frame;
	std::map<uint64_t, int> lines;
	uint64_t retAddr;
	uint64_t base;

	void SetFunction(CComPtr<IDiaSymbol> f, SymbolTable& st);
};

struct VarSet
{
	std::string name;
	std::unordered_set<uint32_t> dataKinds;
	uint32_t frameId;
};

class VsCodeDebugEngine : public ReplaySession
{
public:
	VsCodeDebugEngine();
	~VsCodeDebugEngine();

	void Run();

	void OnFirstBreakpoint(ProcessID processId);
	void OnCreateProcess(ProcessID processId, ThreadID threadId, CREATE_PROCESS_DEBUG_INFO& info);
	void OnCreateThread(ProcessID processId, ThreadID threadId, CREATE_THREAD_DEBUG_INFO& info);
	void OnExitThread(ProcessID processId, ThreadID threadId, EXIT_THREAD_DEBUG_INFO& info);
	void OnExitProcess(ProcessID processId, ThreadID threadId, EXIT_PROCESS_DEBUG_INFO& info);

private:
	void Loop();
	nlohmann::json StackWalk(DWORD processId, DWORD threadId, int startFrame, int level);
	void SetUserBreakpoint(uint64_t va, const std::string& reason, bool invisible = false);
	void ClearInvisibleBreakPoints(uint64_t except_va = 0);
	void ClearUserBreakpoints();

	void ClearStackCache(DWORD threadId);

	std::string clientId_;
	std::string adapterId_;
	struct Config
	{
		bool lineStartAt1;
		bool columnsStartAt1;
		std::string pathFormat;
		bool supportsVariableType;
		bool supportsVariablePaging;
		bool supportsRunInTerminalRequest;
	} config_;

	std::unique_ptr<SymbolTable> st_;
	bool first_process_created_{ false };
	bool stopOnEntry_{ false };

	std::unordered_map<uint32_t, Frame> frames_;
	std::unordered_map<uint32_t, std::vector<Frame*>> framesPerThread_;
	std::unordered_map<uint32_t, VarSet> vars_;
	uint32_t frameIdGen_{ 1 };
	uint32_t varsIdGen_{ 1 };

	std::vector<uint64_t> invisibleBreakpointPositions_;
	uint32_t invisibleBreakpointProcessId_;
};

