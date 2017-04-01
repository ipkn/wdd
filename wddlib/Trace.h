#pragma once

#include "SyscallCodes.h"
#include "dumpable\dumpable.h"
#include "ThreadContext.h"

enum class TraceType : uint16_t
{
	None,
	Syscall,
	Config,
	API,
	PrecessThread,
};

struct Trace
{
	TraceType trace_type;
	Trace(TraceType trace_type) : trace_type(trace_type) {}

	bool Validate()
	{
		return true;
	}

	template <typename T> T* as()
	{
		T* self = (T*)this;
		if (!self->Validate())
		{
			return nullptr;
		}
		return self;
	}
};

template <TraceType trace_typeI>
struct TraceI : public Trace
{
	TraceI() : Trace(trace_typeI) {}

	bool Validate()
	{
		return trace_type == trace_typeI;
	}
};

struct ConfigTrace : public TraceI<TraceType::Config>
{
	dumpable::dwstring exe_path;
	dumpable::dwstring cmdline;
	dumpable::dwstring env;
	uint32_t time_slice;
	ConfigTrace(const std::wstring& exe_path,
		const std::wstring& cmdline,
		const std::wstring& env,
		uint32_t time_slice)
		: exe_path(exe_path), cmdline(cmdline), env(env), time_slice(time_slice)
	{

	}
};

using ProcessThreadTrace = TraceI<TraceType::PrecessThread>;

template <int opI>
struct ProcessThreadTraceI : public ProcessThreadTrace
{
	int op;
	ProcessThreadTraceI() : op(opI) {}
	bool Validate()
	{
		return trace_type == TraceType::API && opI == op;
	}
};

using APITrace = TraceI<TraceType::API>;

template <int opI>
struct APITraceI : public APITrace
{
	int op;
	APITraceI() : op(opI) {}

	bool Validate()
	{
		return trace_type == TraceType::API && opI == op;
	}
};

struct GetTickCountTrace : public APITraceI<1>
{
	DWORD tick;
	GetTickCountTrace(DWORD tick) : tick(tick) {}
};

struct RtlGenRandomTrace : public APITraceI<2>
{
	dumpable::dvector<char> generated;
};

struct RtlGetSystemTimePreciseTrace : public APITraceI<3>
{
	uint64_t ft;
};

using SyscallTrace = TraceI<TraceType::Syscall>;

template <SyscallCode opI, int sub_opI>
struct SyscallTraceI : public SyscallTrace
{
	SyscallCode op;
	int sub_op;
	SyscallTraceI() : op(opI), sub_op(sub_opI) {}

	bool Validate()
	{
		return trace_type == TraceType::Syscall && opI == op && sub_opI == sub_op;
	}
};

struct SyscallNtQueryPerformanceCounterTrace : public SyscallTraceI<SyscallCode::NtQueryPerformanceCounter, 0>
{
	LARGE_INTEGER c;
	LARGE_INTEGER f;
	SyscallNtQueryPerformanceCounterTrace(LARGE_INTEGER c, LARGE_INTEGER f)
		: c(c), f(f)
	{}
};

struct SyscallNtQueryInformationProcessProcessCookieTrace : public SyscallTraceI<SyscallCode::NtQueryPortInformationProcess, 36>
{
	uint32_t cookie;
	SyscallNtQueryInformationProcessProcessCookieTrace(uint32_t cookie) : cookie(cookie) {}
};

class BaseTrace
{
public:
	void Prepare(const std::wstring& key);
protected:
	std::wstring basePath_;
};

const int TraceVersion = MAKELONG(0, 1);

class RecordTrace : BaseTrace
{
public:
	void Prepare(const std::wstring& key);
	template<typename T> 
	void Record(ThreadContext* ctx, const T& trace)
	{
		uint32_t sz = 0;
		if (ctx)
		{
			sz = 1;
			trace_file_.write((char*)&sz, 1);
			trace_file_.write((char*)ctx, sizeof(*ctx));
			sz = 0;
		}
		else
		{
			trace_file_.write((char*)&sz, 1);
		}
		auto p = trace_file_.tellp();
		trace_file_.write((char*)&sz, 4);
		dumpable::write(trace, trace_file_);
		auto p_after = trace_file_.tellp();
		trace_file_.seekp(p);
		sz = (uint32_t)(p_after - p - 4);
		trace_file_.write((char*)&sz, 4);
		trace_file_.seekp(p_after);
	}
private:
	std::ofstream trace_file_;
};

class ReplayTrace : BaseTrace
{
public:
	struct Fragment
	{
		ThreadContext* ctx;
		uint32_t size;
		Trace* trace;
		size_t pos;
		ReplayTrace* parent;

		Fragment() : ctx(nullptr), size(0), trace(nullptr), pos((size_t)-1), parent(nullptr) {}
		Fragment(ThreadContext* ctx, uint32_t size, Trace* trace, size_t pos, ReplayTrace* parent) : ctx(ctx), size(size), trace(trace), pos(pos), parent(parent) {}


		Fragment Next();
		Fragment Prev();

		template <typename T>
		T* get()
		{
			if (sizeof(T) > size)
				return nullptr;
			return trace->as<T>();
		}

		template <typename T>
		T* as()
		{
			auto ret = get<T>();
			if (ret == nullptr)
			{
				std::ostringstream dump;
				dump << std::hex << std::setfill('0');
				for (uint32_t i = 0; i < size; i++)
				{
					dump << std::setw(2) << (uint8_t)*((char*)trace + i) << std::setw(0) << ' ';
				}

				std::cerr << "Not expected trace type\n";
				throw std::runtime_error(("Not expected trace type: " + dump.str()).c_str());
			}
			return ret;
		}

		bool IsInvalid()
		{
			return trace == nullptr;
		}

	};

	void Prepare(const std::wstring& key);

	Fragment GetFirstFragment();
private:
	bool ReadNextFragment();

	Fragment BufferToFragment(size_t pos, char* buffer);

	Fragment PrevFragment(size_t pos);
	Fragment NextFragment(size_t pos);

	std::ifstream trace_file_;
	size_t pos_last;
	std::map<size_t, char*> buffers_;

	friend struct Fragment;
};