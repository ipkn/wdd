#include "stdafx.h"
#include "VsCodeDebugEngine.h"
#include "../wddlib/Symbols.h"

using json = nlohmann::json;

namespace
{
	int sequenceNumber_{ 1 };
}

void SendMsg(json& msg)
{
	msg["seq"] = sequenceNumber_++;
	auto ret = msg.dump();
	std::cout << "Content-Length: " << ret.size() << "\n\n";
	std::cout.write(ret.data(), ret.size());
	OutputDebugStringA(ret.c_str());
	std::cout.flush();
}

void SendRes(json& req, json& body = json{})
{
	json res{
		{ "type", "response" },
		{ "request_seq", req["seq"] },
		{ "success", true },
		{ "command", req["command"] } };
	if (!body.empty())
		res["body"] = body;

	SendMsg(res);
}

void SendErr(json& req, const std::string& msg, const json& body = json{})
{
	json res{
		{ "type", "response" },
		{ "request_seq", req["seq"] },
		{ "success", false },
		{ "command", req["command"] },
		{ "message", msg } };
	if (!body.empty())
		res["body"] = body;

	SendMsg(res);
}


void SendEvent(const std::string& eventType, const json& body = json{})
{
	json res{
		{ "type", "event" },
		{ "event", eventType }};
	if (!body.empty())
		res["body"] = body;

	SendMsg(res);
}

VsCodeDebugEngine::VsCodeDebugEngine()
{
}


VsCodeDebugEngine::~VsCodeDebugEngine()
{
}

void VsCodeDebugEngine::Run()
{
	Loop();
}

void VsCodeDebugEngine::ClearUserBreakpoints()
{
	auto it = breakpoints_.begin();
	while (it != breakpoints_.end())
	{
		auto& kv = it->first;
		if (kv.first == invisibleBreakpointProcessId_ &&
			std::find(
				invisibleBreakpointPositions_.begin(),
				invisibleBreakpointPositions_.end(),
				kv.second) != invisibleBreakpointPositions_.end())
		{
			++it;
			continue;
		}
		std::ostringstream os;
		os << "ClearUserBreakpoints " << kv.first << ' ' << std::hex << kv.second;
		OutputDebugStringA(os.str().c_str());
		it = breakpoints_.erase(it);
	}
}

void VsCodeDebugEngine::ClearInvisibleBreakPoints(uint64_t except_va)
{
	if (!invisibleBreakpointPositions_.empty())
	{
		for (auto p : invisibleBreakpointPositions_)
		{
			if (p == except_va)
				continue;
			auto it = breakpoints_.find(std::make_pair(invisibleBreakpointProcessId_, p));
			if (it != breakpoints_.end())
			{
				std::ostringstream os;
				os << "ClearInvisibleBreakPoints " << it->first.first << ' ' << std::hex << it->first.second;
				OutputDebugStringA(os.str().c_str());

				WriteProcessMemory(processes_[it->first.first], (LPVOID)it->first.second, &it->second.original_inst, 1, nullptr);
				breakpoints_.erase(it);
			}

		}
	}
	invisibleBreakpointPositions_.clear();
}

void VsCodeDebugEngine::SetUserBreakpoint(uint64_t va, const std::string& reason, bool invisible)
{
	{
		std::ostringstream os;
		os << "SetUserBreakpoint " << reason << ' ' << std::hex << va << ' ' << invisible;
		OutputDebugStringA(os.str().c_str());
	}
	if (invisible)
	{
		if (breakpoints_.count(std::make_pair(current_task_.first, va)))
		{
			OutputDebugStringA("skip");
			return;
		}

		invisibleBreakpointProcessId_ = current_task_.first;
		invisibleBreakpointPositions_.push_back(va);
	}
	SetBreakpoint(current_task_.first, va, true, [this, reason, va](HANDLE process, HANDLE thread, ArgPack&) {
		OutputDebugStringA("UB hit before");
		SetDebugLoopBreak();
		SendEvent("stopped",
		{ { "reason", reason },
		//{ "description", "Stopped at program startup" },
		{ "threadId", current_task_.second },
		{ "allThreadsStopped", true }
		});
		ClearInvisibleBreakPoints(va);
	}, nullptr);
}

void VsCodeDebugEngine::ClearStackCache(DWORD threadId)
{
	if (!framesPerThread_.count(threadId))
		return;
	for (auto pFrame : framesPerThread_[threadId])
	{
		frames_.erase(pFrame->id);
	}
	framesPerThread_.erase(threadId);
}

void VsCodeDebugEngine::OnFirstBreakpoint(ProcessID processId)
{
	SetDebugLoopBreak();
	if (stopOnEntry_ && st_)
	{
		wchar_t* entries[] = {L"_main", L"_wmain", L"WinMain", L"DllMain"};
		for (int i = 0; i < 4; i++)
		{
			auto va = st_->GetVA(entries[i], true);
			if (va)
			{
				std::wostringstream os;
				os << L"Set breakpoint at " << entries[i] << std::hex << ' ' << va;
				OutputDebugStringW(os.str().c_str());
				SetUserBreakpoint(va, "entry", true);
			}
		}
	}
	SendEvent("initialized");
}

void VsCodeDebugEngine::OnCreateProcess(ProcessID processId, ThreadID threadId, CREATE_PROCESS_DEBUG_INFO & info)
{
	if (!first_process_created_)
	{
		st_->SetBase((uint64_t)info.lpBaseOfImage);
	}
	ReplaySession::OnCreateProcess(processId, threadId, info);
}

void VsCodeDebugEngine::OnCreateThread(ProcessID processId, ThreadID threadId, CREATE_THREAD_DEBUG_INFO & info)
{
	ReplaySession::OnCreateThread(processId, threadId, info);
	SendEvent("thread", json{ { "reason", "started" },{ "threadId", GetThreadId(info.hThread) } });
}

void VsCodeDebugEngine::OnExitThread(ProcessID processId, ThreadID threadId, EXIT_THREAD_DEBUG_INFO & info)
{
	ReplaySession::OnExitThread(processId, threadId, info);
	SendEvent("thread", json{ {"reason", "exited"}, {"threadId", threadId}});
}

void VsCodeDebugEngine::OnExitProcess(ProcessID processId, ThreadID threadId, EXIT_PROCESS_DEBUG_INFO & info)
{
	ReplaySession::OnExitProcess(processId, threadId, info);
	SendEvent("exited", json{ {"exitCode", info.dwExitCode} });

	// NOTE assume there's only 1 process 
	SendEvent("terminated");
}

struct DiaStackWalkHelper : public IDiaStackWalkHelper
{
	long m_refCount{ 0 };
	HANDLE process;
	HANDLE thread;
	int bits;
	ThreadContext ctx;
	SymbolTable& symbolTable;
	std::unordered_map<uint64_t, ModuleInfo>& modules;
	DiaStackWalkHelper(HANDLE process, HANDLE thread, int bits, SymbolTable& symbolTable, std::unordered_map<uint64_t, ModuleInfo>& modules)
		: process(process), thread(thread), bits(bits), ctx(process, thread, bits), symbolTable(symbolTable), modules(modules)
	{
	}

	virtual ULONG STDMETHODCALLTYPE AddRef()
	{
		InterlockedIncrement(&m_refCount);
		return m_refCount;
	}

	virtual ULONG STDMETHODCALLTYPE Release()
	{
		InterlockedDecrement(&m_refCount);
		if (m_refCount == 0)
		{
			delete this;
			return 0;
		}
		return m_refCount;
	}

	virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject)
	{
		if (!ppvObject)
		{
			return E_INVALIDARG;
		}

		if (riid == __uuidof(IDiaLoadCallback))
		{
			*ppvObject = (IDiaLoadCallback*)this;
			AddRef();
			return S_OK;
		}
		else if (riid == __uuidof(IUnknown))
		{
			*ppvObject = (IUnknown*)this;
			AddRef();
			return S_OK;
		}

		return E_NOINTERFACE;
	}

	virtual /* [id][helpstring][propget] */ HRESULT STDMETHODCALLTYPE get_registerValue(
		/* [in] */ DWORD index,
		/* [retval][out] */ ULONGLONG *pRetVal)
	{
		switch (index)
		{
		case CV_REG_EAX:
			*pRetVal = ctx.ctx86.Eax;
			break;
		case CV_REG_ECX:
			*pRetVal = ctx.ctx86.Ecx;
			break;
		case CV_REG_EDX:
			*pRetVal = ctx.ctx86.Edx;
			break;
		case CV_REG_EBX:
			*pRetVal = ctx.ctx86.Ebx;
			break;
		case CV_REG_ESP:
			*pRetVal = ctx.ctx86.Esp;
			break;
		case CV_REG_EBP:
			*pRetVal = ctx.ctx86.Ebp;
			break;
		case CV_REG_EIP:
			*pRetVal = ctx.ctx86.Eip;
			break;
		case CV_REG_ESI:
			*pRetVal = ctx.ctx86.Esi;
			break;
		case CV_REG_EDI:
			*pRetVal = ctx.ctx86.Edi;
			break;
		case CV_REG_EFLAGS:
			*pRetVal = ctx.ctx86.EFlags;
			break;
		case CV_REG_CS:
			*pRetVal = ctx.ctx86.SegCs;
			break;
		case CV_REG_FS:
			*pRetVal = ctx.ctx86.SegFs;
			break;
		case CV_REG_ES:
			*pRetVal = ctx.ctx86.SegEs;
			break;
		case CV_REG_DS:
			*pRetVal = ctx.ctx86.SegDs;
			break;
#ifdef _AMD64_
			TODO
		case CV_AMD64_RAX] = m_context.Rax;
		case CV_AMD64_RCX] = m_context.Rcx;
		case CV_AMD64_RDX] = m_context.Rdx;
		case CV_AMD64_RBX] = m_context.Rbx;
		case CV_AMD64_RSP] = m_context.Rsp;
		case CV_AMD64_RBP] = m_context.Rbp;
		case CV_AMD64_RIP] = m_context.Rip;
		case CV_AMD64_RSI] = m_context.Rsi;
		case CV_AMD64_RDI] = m_context.Rdi;
		case CV_AMD64_R8] = m_context.R8;
		case CV_AMD64_R9] = m_context.R9;
		case CV_AMD64_R10] = m_context.R10;
		case CV_AMD64_R11] = m_context.R11;
		case CV_AMD64_R12] = m_context.R12;
		case CV_AMD64_R13] = m_context.R13;
		case CV_AMD64_R14] = m_context.R14;
		case CV_AMD64_R15] = m_context.R15;
		case CV_AMD64_EFLAGS:
		case CV_AMD64_CS:
		case CV_AMD64_FS:
		case CV_AMD64_ES:
		case CV_AMD64_DS:
			return ctx.ctx.
#endif
		default:
			return E_INVALIDARG;
		}
		return S_OK;
	}

	virtual /* [id][helpstring][propput] */ HRESULT STDMETHODCALLTYPE put_registerValue(
		/* [in] */ DWORD index,
		/* [in] */ ULONGLONG NewVal)
	{
		switch (index)
		{
		case CV_REG_EAX:
			ctx.ctx86.Eax = (DWORD)NewVal;
			break;
		case CV_REG_ECX:
			ctx.ctx86.Ecx = (DWORD)NewVal;
			break;
		case CV_REG_EDX:
			ctx.ctx86.Edx = (DWORD)NewVal;
			break;
		case CV_REG_EBX:
			ctx.ctx86.Ebx = (DWORD)NewVal;
			break;
		case CV_REG_ESP:
			ctx.ctx86.Esp = (DWORD)NewVal;
			break;
		case CV_REG_EBP:
			ctx.ctx86.Ebp = (DWORD)NewVal;
			break;
		case CV_REG_EIP:
			ctx.ctx86.Eip = (DWORD)NewVal;
			break;
		case CV_REG_ESI:
			ctx.ctx86.Esi = (DWORD)NewVal;
			break;
		case CV_REG_EDI:
			ctx.ctx86.Edi = (DWORD)NewVal;
			break;
		case CV_REG_EFLAGS:
			ctx.ctx86.EFlags = (DWORD)NewVal;
			break;
		case CV_REG_CS:
			ctx.ctx86.SegCs = (DWORD)NewVal;
			break;
		case CV_REG_FS:
			ctx.ctx86.SegFs = (DWORD)NewVal;
			break;
		case CV_REG_ES:
			ctx.ctx86.SegEs = (DWORD)NewVal;
			break;
		case CV_REG_DS:
			ctx.ctx86.SegDs = (DWORD)NewVal;
			break;
#ifdef _AMD64_
			TODO
				case CV_AMD64_RAX] = m_context.Rax;
				case CV_AMD64_RCX] = m_context.Rcx;
				case CV_AMD64_RDX] = m_context.Rdx;
				case CV_AMD64_RBX] = m_context.Rbx;
				case CV_AMD64_RSP] = m_context.Rsp;
				case CV_AMD64_RBP] = m_context.Rbp;
				case CV_AMD64_RIP] = m_context.Rip;
				case CV_AMD64_RSI] = m_context.Rsi;
				case CV_AMD64_RDI] = m_context.Rdi;
				case CV_AMD64_R8] = m_context.R8;
				case CV_AMD64_R9] = m_context.R9;
				case CV_AMD64_R10] = m_context.R10;
				case CV_AMD64_R11] = m_context.R11;
				case CV_AMD64_R12] = m_context.R12;
				case CV_AMD64_R13] = m_context.R13;
				case CV_AMD64_R14] = m_context.R14;
				case CV_AMD64_R15] = m_context.R15;
				case CV_AMD64_EFLAGS:
				case CV_AMD64_CS:
				case CV_AMD64_FS:
				case CV_AMD64_ES:
				case CV_AMD64_DS:
					return ctx.ctx.
#endif
				default:
					return E_INVALIDARG;
		}
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE readMemory(
		/* [in] */ enum MemoryTypeEnum type,
		/* [in] */ ULONGLONG va,
		/* [in] */ DWORD cbData,
		/* [out] */ DWORD *pcbData,
		/* [size_is][out] */ BYTE *pbData)
	{
		if (pbData)
		{
			for (DWORD i = 0; i < cbData; i++)
			{
				SIZE_T nRead = 0;
				BOOL ret = ReadProcessMemory(process, (LPVOID)(va + i), pbData + i, 1, &nRead);
				if (!ret || !nRead)
				{
					if (i == 0)
						return E_FAIL;
					if (pcbData)
						*pcbData = i;
					return S_OK;
				}
			}
			if (pcbData)
				*pcbData = cbData;
			return S_OK;
		}
		else
		{
			for (DWORD i = 0; i < cbData; i++)
			{
				SIZE_T nRead = 0;
				BYTE x;
				BOOL ret = ReadProcessMemory(process, (LPVOID)(va + i), &x, 1, &nRead);
				if (!ret || !nRead)
				{
					if (i == 0)
						return E_FAIL;
					if (pcbData)
						*pcbData = i;
					return S_OK;
				}
			}
			if (pcbData)
				*pcbData = cbData;
			return S_OK;
		}
	}

	virtual HRESULT STDMETHODCALLTYPE searchForReturnAddress(
		/* [in] */ IDiaFrameData *frame,
		/* [out] */ ULONGLONG *returnAddress)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE searchForReturnAddressStart(
		/* [in] */ IDiaFrameData *frame,
		/* [in] */ ULONGLONG startAddress,
		/* [out] */ ULONGLONG *returnAddress)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE frameForVA(
		/* [in] */ ULONGLONG va,
		/* [out] */ IDiaFrameData **ppFrame)
	{
		HRESULT hr = NOERROR;

		CComPtr<IDiaEnumFrameData> pDiaEnumFrameData;
		hr = symbolTable.GetEnumFrameData(&pDiaEnumFrameData);

		if (SUCCEEDED(hr))
		{
			hr = pDiaEnumFrameData->frameByVA(va, ppFrame);
		}

		return hr;
	}

	virtual HRESULT STDMETHODCALLTYPE symbolForVA(
		/* [in] */ ULONGLONG va,
		/* [out] */ IDiaSymbol **ppSymbol)
	{
		return symbolTable.findSymbolByVA(va, ppSymbol);
	}

	virtual HRESULT STDMETHODCALLTYPE pdataForVA(
		/* [in] */ ULONGLONG va,
		/* [in] */ DWORD cbData,
		/* [out] */ DWORD *pcbData,
		/* [size_is][out] */ BYTE *pbData)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE imageForVA(
		/* [in] */ ULONGLONG vaContext,
		/* [out] */ ULONGLONG *pvaImageStart)
	{
		for (auto& kv : modules)
		{
			if (vaContext >= kv.second.base &&
				vaContext < kv.second.base + kv.second.size)
			{
				*pvaImageStart = kv.second.base;
				return S_OK;
			}
		}

		return S_FALSE;
	}
	virtual HRESULT STDMETHODCALLTYPE addressForVA(
		/* [in] */ ULONGLONG va,
		/* [out] */ DWORD *pISect,
		/* [out] */ DWORD *pOffset)
	{
		return symbolTable.addressForVA(va, pISect, pOffset);
	}

	virtual HRESULT STDMETHODCALLTYPE numberOfFunctionFragmentsForVA(
		/* [in] */ ULONGLONG vaFunc,
		/* [in] */ DWORD cbFunc,
		/* [out] */ DWORD *pNumFragments)
	{
		if (pNumFragments)
			*pNumFragments = 0;
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE functionFragmentsForVA(
		/* [in] */ ULONGLONG vaFunc,
		/* [in] */ DWORD cbFunc,
		/* [in] */ DWORD cFragments,
		/* [out] */ ULONGLONG *pVaFragment,
		/* [out] */ DWORD *pLenFragment)
	{
		return S_OK;
	}

};

json VsCodeDebugEngine::StackWalk(DWORD processId, DWORD threadId, int startFrame, int level)
{
	if (level == 0)
		level = 10000;
	CComPtr<IDiaStackWalker> pDiaStackWalker;
	HRESULT hr = ::CoCreateInstance(CLSID_DiaStackWalker,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_IDiaStackWalker,
		(LPVOID*)&pDiaStackWalker);

	if (!SUCCEEDED(hr))
	{
		MessageBoxA(nullptr, "Fail to create CLSID_DiaStackWalker", "error", MB_OK);
	}
	int bits = bits_[processId];
	DiaStackWalkHelper* pHelper = new DiaStackWalkHelper(
		processes_[processId],
		threads_[threadId],
		bits,
		*st_,
		modules_);

	CComQIPtr<IDiaStackWalkHelper> pStackWalkHelper = pHelper;
	{
		std::ostringstream os;
		os << "start " << std::hex << pHelper->ctx.ip();
		OutputDebugStringA(os.str().c_str());
	}

	CComPtr<IDiaEnumStackFrames> pDiaStackFramesEnum;
	pDiaStackWalker->getEnumFrames(pHelper, &pDiaStackFramesEnum);

	ULONG cActual;
	CComPtr<IDiaStackFrame> pStackFrame;

	pDiaStackFramesEnum->Reset();
	pDiaStackFramesEnum->Next(1, &pStackFrame, &cActual);
	int frameIndex = 0;
	json stackFrames;
	while (cActual == 1 && frameIndex < startFrame + level)
	{
		//thread->AddStackFrame(gcnew ThreadContext(pStackFrame));
		//if (frameIndex >= startFrame)
		{
			ULONGLONG ip;
			if (bits == 33)
			{
				pStackFrame->get_registerValue(CV_REG_EIP, &ip);
			}
#ifdef _AMD64_
			else if (bits == 64)
			{
				pStackFrame->get_registerValue(CV_AMD64_RIP, &ip);
			}
#endif
			{
				std::ostringstream os;
				os << "frame " << frameIndex << ' ' << std::hex << ip;
				OutputDebugStringA(os.str().c_str());
			}
			DWORD frameId = frameIdGen_++;
			frames_[frameId].id = frameId;
			frames_[frameId].threadId = threadId;
			frames_[frameId].frame = pStackFrame;
			framesPerThread_[threadId].push_back(&frames_[frameId]);
			if (frameIndex >= startFrame)
				stackFrames[frameIndex - startFrame]["id"] = frameId;
			CComPtr<IDiaSymbol> func;
			if (S_OK == st_->findSymbolByVA(ip, &func))
			{
				frames_[frameId].SetFunction(func, *st_);
				pStackFrame->get_returnAddress(&frames_[frameId].retAddr);
				pStackFrame->get_localsBase(&frames_[frameId].base);
				if (frameIndex >= startFrame)
				{
					BSTR name;
					if (S_OK == (func->get_name(&name)))
					{
						stackFrames[frameIndex - startFrame]["name"] = ws2s(name);
					}
					else
					{
						std::ostringstream os;
						os << "unnamed:";
						if (bits == 33)
							os << std::hex << std::setfill('0') << std::setw(8) << ip;
						else if (bits == 64)
							os << std::hex << std::setfill('0') << std::setw(16) << ip;
						stackFrames[frameIndex - startFrame]["name"] = os.str();
					}
				}
			}
			else
				if (frameIndex >= startFrame)
			{
				std::ostringstream os;
				if (bits == 33)
					os << std::hex << std::setfill('0') << std::setw(8) << ip;
				else if (bits == 64)
					os << std::hex << std::setfill('0') << std::setw(16) << ip;
				stackFrames[frameIndex - startFrame]["name"] = os.str();
			}
			if (frameIndex >= startFrame)
			{
				bool line_number_valid = false;
				auto* enumLineNumbers = st_->GetEnumLineNumbers(ip);
				if (enumLineNumbers)
				{
					LONG cnt = 0;
					enumLineNumbers->get_Count(&cnt);
					if (cnt)
					{
						IDiaLineNumber* pLine;
						{
							std::ostringstream os;
							os << "EnumLineNumbers " << cnt;
							OutputDebugStringA(os.str().c_str());
						}
						enumLineNumbers->Item(0, &pLine);
						if (pLine)
						{
							line_number_valid = true;

							DWORD lineNum;
							DWORD lineNumEnd;
							DWORD columnNum;
							DWORD columnNumEnd;

							pLine->get_lineNumber(&lineNum);
							stackFrames[frameIndex - startFrame]["line"] = lineNum;
							if (SUCCEEDED(pLine->get_lineNumberEnd(&lineNumEnd)))
							{
								stackFrames[frameIndex - startFrame]["endLine"] = lineNumEnd;
							}
							pLine->get_columnNumber(&columnNum);
							stackFrames[frameIndex - startFrame]["column"] = columnNum;
							if (SUCCEEDED(pLine->get_columnNumberEnd(&columnNumEnd)))
							{
								stackFrames[frameIndex - startFrame]["endColumn"] = columnNumEnd;
							}

							IDiaSourceFile* source_info{};
							if (SUCCEEDED(pLine->get_sourceFile(&source_info)))
							{
								BSTR filename;
								if (SUCCEEDED(source_info->get_fileName(&filename)) && PathFileExistsW(filename))
								{
									auto name = ws2s(filename);
									stackFrames[frameIndex - startFrame]["source"]["name"] = name;
									stackFrames[frameIndex - startFrame]["source"]["path"] = name;
								}
							}
						}
					}

				}

				if (!line_number_valid)
				{
					stackFrames[frameIndex - startFrame]["line"] = 0;
					stackFrames[frameIndex - startFrame]["column"] = 0;
				}
			}
		}

		pStackFrame.Release();
		pDiaStackFramesEnum->Next(1, &pStackFrame, &cActual);
		frameIndex++;
	}
	return stackFrames;
}

template <typename T>
bool ReadSymbolValue(HANDLE process, Frame& frame, IDiaSymbol* symbol, T& out)
{
	OutputDebugStringA("ReadSymbolValue 1");
	IDiaSymbol* type;
	if (symbol->get_type(&type) != S_OK)
		return false;
	enum SymTagEnum typeTag;
	type->get_symTag((DWORD*)&typeTag);
	if (typeTag != SymTagBaseType)
	{
		// TODO not supported yet
		out = "???";
		return true;
	}

	OutputDebugStringA("ReadSymbolValue 2");
	BasicType baseType;
	type->get_baseType((DWORD*)&baseType);

	ULONGLONG typeLength;
	if (type->get_length(&typeLength) != S_OK)
		return false;
	if (typeLength > 8)
		return false;

	DWORD locType;
	if (symbol->get_locationType(&locType) != S_OK)
		return false;
	char buf[8];
	memset(buf, 0, sizeof(buf));

	switch (locType)
	{
	case LocIsThisRel:
	{
		OutputDebugStringA("ReadSymbolValue 3");
		LONG offset;
		symbol->get_offset(&offset);
		uint64_t self;
#ifdef _AMD64_
		frame.frame->get_registerValue(CV_AMD64_RCX, &self);
#else
		frame.frame->get_registerValue(CV_REG_ECX, &self);
#endif
		BOOL ret = ReadProcessMemory(process, (LPVOID)(self + offset), buf, (SIZE_T)typeLength, nullptr);
		if (!ret)
		{
			out = "???";
			return true;
		}
	}
	break;
	case LocIsEnregistered:
	{
		OutputDebugStringA("ReadSymbolValue 4");
		DWORD registerId;
		if (symbol->get_registerId(&registerId) != S_OK)
			return false;
		if (frame.frame->get_registerValue(registerId, (ULONGLONG*) buf) != S_OK)
			return false;
	}
		break;
	case LocIsRegRel:
	{
		OutputDebugStringA("ReadSymbolValue 5");
		LONG offset;
		symbol->get_offset(&offset);
		uint64_t self;
		DWORD registerId;
		if (symbol->get_registerId(&registerId) != S_OK)
			return false; 
		if (frame.frame->get_registerValue(registerId, &self) != S_OK)
		{
			if (registerId == CV_ALLREG_VFRAME)
			{
				self = frame.base;
			}
			else
				return false;
		}
		{
			std::ostringstream os;
			os << typeLength << ' ' << baseType << ' ' << offset << ' ' << registerId << ' ' <<std::hex << self << ' ' << frame.base;
			OutputDebugStringA(os.str().c_str());
		}
		BOOL ret = ReadProcessMemory(process, (LPVOID)(self + offset), buf, (SIZE_T)typeLength, nullptr);
		if (!ret)
		{
			out = "???";
			return true;
		}
	}		break;
	default:
		out = "???";
		return true;
	}

	if (baseType == btULong || baseType == btUInt || baseType == btWChar || baseType == btChar)
	{
		OutputDebugStringA("ReadSymbolValue 6");
		switch (typeLength)
		{
		case 1:
			out = std::to_string(*(uint8_t*)buf);
			break;
		case 2:
			out = std::to_string(*(uint16_t*)buf);
			break;
		case 4:
			out = std::to_string(*(uint32_t*)buf);
			break;
		case 8:
			out = std::to_string(*(uint64_t*)buf);
			break;
		}
	}
	else
	{
		OutputDebugStringA("ReadSymbolValue 7");
		switch (typeLength)
		{
		case 1:
			out = std::to_string(*(int8_t*)buf);
			break;
		case 2:
			out = std::to_string(*(int16_t*)buf);
			break;
		case 4:
			out = std::to_string(*(int32_t*)buf);
			break;
		case 8:
			out = std::to_string(*(int64_t*)buf);
			break;
		}
	}
	return true;
}

void VsCodeDebugEngine::Loop()
{
	OutputDebugStringW(L"Start wdd-vscode");
	while (1)
	{
		//std::vector<std::string> headers;
		size_t sz = 0;
		while (1)
		{
			std::string line;
			std::getline(std::cin, line);
			if (line.empty())
				break;
			//headers.push_back(line);
			if (line.substr(0, 16) == "Content-Length: ")
			{
				sz = std::stoul(line.substr(16));
			}
		}
		if (!sz)
			break;
		std::string buffer(sz, ' ');
		std::cin.read(&buffer[0], sz);
		OutputDebugStringA(buffer.c_str());

		json req = json::parse(buffer);
		if (req["type"] == "request")
		{
			if (req["command"] == "initialize")
			{
				clientId_ = req["arguments"]["clientID"];
				adapterId_ = req["arguments"]["adapterID"];
				config_.lineStartAt1 = req["arguments"]["linesStartAt1"];
				config_.columnsStartAt1 = req["arguments"]["columnsStartAt1"];
				config_.pathFormat = req["arguments"]["pathFormat"];
				config_.supportsVariableType = req["arguments"]["supportsVariableType"];
				config_.supportsVariablePaging = req["arguments"]["supportsVariablePaging"];
				config_.supportsRunInTerminalRequest = req["arguments"]["supportsRunInTerminalRequest"];

				OutputDebugStringA("send init response");
				SendRes(req, json{
					{ "supportsConfigurationDoneRequest", true },
					//{ "supportsEvaluateForHovers", true}
					//{ "supportsStepBack", true }
				});
			}
			else if (req["command"] == "launch")
			{
				auto& args = req["arguments"];
				auto p = args["program"].get<std::string>();
				if (args.count("stopOnEntry") && args["stopOnEntry"])
					stopOnEntry_ = true;
				st_.reset(new SymbolTable(s2ws(p)));
				SendRes(req);
				Start({ s2ws(args["program"].get<std::string>()) });
			}
			else if (req["command"] == "configurationDone")
			{
				SendRes(req);
				/*SendEvent("stopped",
				{ {"reason", "entry"},
				{"description", "Stopped at program startup"},
				{"threadId", currentTask_.second},
				{"allThreadsStopped", true}
				});*/
				SetDebugLoopBreak(false);
				DebugLoop();
			}
			else if (req["command"] == "disconnect")
			{
				SendRes(req);
				exit(0);
			}
			else if (req["command"] == "threads")
			{
				json threads;
				int idx = 0;
				for (auto& kv : active_tasks_)
				{
					threads["threads"][idx]["id"] = kv.first.second;
					std::ostringstream os;
					os << "thread-" << kv.first.first << '-' << kv.first.second;
					threads["threads"][idx]["name"] = os.str();
					idx++;
				}
				SendRes(req, threads);
			}
			else if (req["command"] == "scopes")
			{
				uint32_t frameId = req["arguments"]["frameId"];
				if (frames_.count(frameId)==0 || frames_[frameId].func.p == nullptr)
				{
					OutputDebugStringA("scope 1");
					SendRes(req, json{ {"scopes",json::array()} });
				}
				else
				{
					auto func = frames_[frameId].func;
					CComPtr<IDiaEnumSymbols> pEnum;
					func->findChildren(SymTagData, NULL, nsNone, &pEnum);
					LONG cnt;
					pEnum->get_Count(&cnt);
					int varsLocalsId = 0;
					int varsArgsId = 0;
					json localScope;
					json argsScope;
					localScope["expensive"] = false;
					localScope["namedVariables"] = 0;
					argsScope["expensive"] = false;
					argsScope["indexedVariables"] = 0;
					for (int i = 0; i < cnt; i++)
					{
						CComPtr<IDiaSymbol> symbol;
						ULONG actual;
						pEnum->Next(1, &symbol, &actual);

						DWORD dataKind;
						if (S_OK != symbol->get_dataKind(&dataKind))
							continue;
						if (dataKind == DataIsParam)
						{
							if (!varsArgsId) 
							{
								varsArgsId = varsIdGen_++;
								argsScope["name"] = vars_[varsArgsId].name = "Arguments";
								vars_[varsArgsId].dataKinds.insert(DataIsParam);
								vars_[varsArgsId].frameId = frameId;
								argsScope["variablesReference"] = varsArgsId;
							}
							argsScope["indexedVariables"]= (int)argsScope["indexedVariables"]+1;
						}
						else if (dataKind == DataIsLocal)
						{
							if (!varsLocalsId)
							{ 
								varsLocalsId = varsIdGen_++;
								localScope["name"] = vars_[varsLocalsId].name = "Locals";
								vars_[varsLocalsId].dataKinds.insert(DataIsLocal);
								vars_[varsLocalsId].frameId = frameId;
								localScope["variablesReference"] = varsLocalsId;
							}
							localScope["namedVariables"]= (int)localScope["namedVariables"] +1;

						}
						else if (dataKind == DataIsObjectPtr)
						{
							if (!varsLocalsId)
							{
								varsLocalsId = varsIdGen_++;
								localScope["name"] = vars_[varsLocalsId].name = "Locals";
								vars_[varsLocalsId].dataKinds.insert(DataIsObjectPtr);
								vars_[varsLocalsId].frameId = frameId;
								localScope["variablesReference"] = varsLocalsId;
							}
							localScope["namedVariables"] = (int)localScope["namedVariables"] + 1;
						}
					}
					if (varsArgsId && varsLocalsId)
					{
						OutputDebugStringA("scope 2");
						SendRes(req, json{ {"scopes", {argsScope, localScope}} });
					}
					else if (varsArgsId)
					{
						OutputDebugStringA("scope 3");
						SendRes(req, json{ { "scopes",json{ {argsScope,} } } });
					}
					else if (varsLocalsId)
					{
						OutputDebugStringA("scope 4");
						SendRes(req, json{ { "scopes",json{ {localScope,} } } });
					}
					else
					{
						OutputDebugStringA("scope 5");
						SendRes(req, json{ { "scopes",json::array() } });
					}
					
				}
			}
			//else if (req["command"] == "stepIn")
			//{

			//}
			//else if (req["command"] == "stepOut")
			//{
			//}
			else if (req["command"] == "continue")
			{
				SetDebugLoopBreak(false);
				DebugLoop();
			}
			else if (req["command"] == "variables")
			{
				uint32_t varRef = req["arguments"]["variablesReference"];
				if (!vars_.count(varRef))
				{
					SendErr(req, "invalid variablesReference");
				}
				else
				{
					auto& varSet = vars_[varRef];
					CComPtr<IDiaEnumSymbols> pEnum;
					if (!frames_.count(varSet.frameId))
					{
						SendErr(req, "invalid frame");
					}
					else
					{
						auto& frame = frames_[varSet.frameId];
						frame.func->findChildren(SymTagData, NULL, nsNone, &pEnum);
						IDiaSymbol* symbol;
						ULONG celt;
						json body;
						int var_index = 0;
						while (pEnum->Next(1, &symbol, &celt) == S_OK)
						{

							DWORD dataKind;
							if (S_OK != symbol->get_dataKind(&dataKind))
								continue;
							if (!varSet.dataKinds.count(dataKind))
								continue;
							BSTR name;
							symbol->get_name(&name);
							json v;
							if (ReadSymbolValue(processes_[current_task_.first], frame, symbol, v))
							{
								body[var_index++] = json{ {"name", ws2s(name)}, {"value", v}, {"variablesReference", 0} };
							}
						}
						SendRes(req, json{ {"variables",body} });
					}

				}

			}
			else if (req["command"] == "next")
			{
				DWORD threadId = req["arguments"]["threadId"];
				if (framesPerThread_.count(threadId) && framesPerThread_[threadId].size() >= 1)
				{
					auto& topFrame = framesPerThread_[threadId][0];
					ThreadContext ctx(processes_[current_task_.first], threads_[threadId], bits_[current_task_.first]);
					auto it = topFrame->lines.upper_bound(ctx.ip());
					if (it != topFrame->lines.end())
					{
						SetUserBreakpoint(it->first, "step", true);
					}
					SetUserBreakpoint(topFrame->retAddr, "step", true);
					SendRes(req, json{});
					SetDebugLoopBreak(false);
					DebugLoop();
				}
				else
				{
					SendErr(req, "cannot find context");
				}
			}
			else if (req["command"] == "evaluate")
			{
				// [25792] {"command":"evaluate","arguments":{"expression":"now","frameId":1,"context":"watch"},"type":"request","seq":8}

				auto& args = req["arguments"];
				std::string expr = args["expression"];
				std::wstring wexpr = s2ws(expr);
				OutputDebugStringA("evaluate 0");
				uint32_t frameId;
				if (args.count("frameId"))
					frameId = args["frameId"];
				else
				{
					if (!framesPerThread_.count(current_task_.second) || framesPerThread_[current_task_.second].empty())
					{
						OutputDebugStringA("evaluate 0-1");
						frameId = (uint32_t)-1;
					}
					else
						frameId = framesPerThread_[current_task_.second][0]->id;
				}
				if (!frames_.count(frameId))
				{
					OutputDebugStringA("evaluate 1");
					SendErr(req, "invalid frame");
				}
				else
				{
					OutputDebugStringA("evaluate 2");
					auto& frame = frames_[frameId];
					CComPtr<IDiaEnumSymbols> pEnum;
					frame.func->findChildren(SymTagData, NULL, nsNone, &pEnum);
					ULONG celt;
					IDiaSymbol* symbol;
					bool found = false;
					json body;
					while (pEnum->Next(1, &symbol, &celt) == S_OK)
					{
						BSTR name;
						if (symbol->get_name(&name) == S_OK && name == wexpr)
						{
							found = ReadSymbolValue(processes_[current_task_.first], frame, symbol, body["result"]);
							
							break;
						}
					}
					if (!found)
					{
						// TODO check global variables
					}
					if (!found)
					{
						SendErr(req, "cannot find variable");
					}
					else
					{
						body["variablesReference"] = 0;
						SendRes(req, body);
					}
				}
				//args["context"] // repl watch hover
			}
			else if (req["command"] == "stackTrace")
			{
				auto& args = req["arguments"];
				int level = args["levels"];
				int startFrame = args["startFrame"];
				DWORD threadId = args["threadId"];
				ClearStackCache(threadId);

				bool sentRes = false;
				for (auto& kv : active_tasks_)
				{
					if (kv.first.second == threadId)
					{
						sentRes = true;
						auto stackFrames = StackWalk(kv.first.first, threadId, startFrame, level);
						SendRes(req, json{ { "stackFrames", stackFrames } });
						break;
					}
				}
				if (!sentRes)
				{
					std::ostringstream os;
					os << "StackTrace Fail: " << threadId;
					OutputDebugStringA(os.str().c_str());
				}
			}
			else if (req["command"] == "setBreakpoints")
			{
				ClearUserBreakpoints();
				auto& args = req["arguments"];
				std::string path = args["source"]["path"];
				auto wpath = s2ws(path);
				auto& bps = args["breakpoints"];
				IDiaEnumSourceFiles* pEnumFile;
				IDiaSourceFile* pFile;
				DWORD celt;
				HRESULT hr;
				
				json body;

				hr = st_->session_->findFile(NULL, wpath.c_str(), nsFNameExt, &pEnumFile);
				if (hr == S_OK)
					while (pEnumFile->Next(1, &pFile, &celt) == S_OK)
					{
						IDiaEnumSymbols* pEnumCompilands;
						IDiaSymbol* pCompiland;

						pFile->get_compilands(&pEnumCompilands);
						while (pEnumCompilands->Next(1, &pCompiland, &celt) == S_OK)
						{
							for (size_t i = 0; i < bps.size(); i++)
							{
								body["breakpoints"][i]["verified"] = false;
								IDiaEnumLineNumbers* pEnum;
								// Find first compiland closest to line 1 of the file.  
								if (st_->session_->findLinesByLinenum(pCompiland, pFile, (DWORD)bps[i]["line"], 0, &pEnum) == S_OK)
								{
									IDiaLineNumber *pLineNumber;
									DWORD lineCount;
									while (pEnum->Next(1, &pLineNumber, &lineCount) == S_OK)
									{
										std::ostringstream os;
										DWORD lineNum;
										if (pLineNumber->get_lineNumber(&lineNum) == S_OK)
										{
											os << "line: " << lineNum;
											body["breakpoints"][i]["line"] = lineNum;
										}
										uint64_t va;
										if (pLineNumber->get_virtualAddress(&va) == S_OK)
										{
											os << " va: " << std::hex << va;
											body["breakpoints"][i]["verified"] = true;
											SetUserBreakpoint(va, "breakpoint");
										}
										OutputDebugStringA(os.str().c_str());
									}
								}
							}
						}
					}

				SendRes(req, body);
			}
			else
			{
				auto d = req.dump();
				MessageBoxA(NULL,d.c_str(), ("Not implemented request type "+ req["command"].get<std::string>()).c_str(), MB_OK);
			}
		}
		else if (req["type"] == "response")
		{

		}
		else if (req["type"] == "event")
		{

		}

	}
}

void Frame::SetFunction(CComPtr<IDiaSymbol> f, SymbolTable& st)
{
	func = f;
	uint64_t func_length;
	uint64_t va;
	func->get_virtualAddress(&va);
	func->get_length(&func_length);
	auto pLines = st.GetEnumLineNumbers(va, (DWORD)func_length);
	LONG cnt;
	pLines->get_Count(&cnt);
	for (int i = 0; i < cnt; i++)
	{
		ULONG fetched = 0;
		IDiaLineNumber* pLine;
		pLines->Next(1, &pLine, &fetched);
		DWORD line_number;
		pLine->get_lineNumber(&line_number);
		uint64_t line_va;
		pLine->get_virtualAddress(&line_va);
		lines[line_va] = line_number;
	}
}
