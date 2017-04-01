#pragma once


#ifdef NDEBUG

#define WDD_ASSERT(expression) ((void)0)
#else
#define WDD_ASSERT(x) if (!(x))\
{\
	std::cerr << "Assertion failed: " << #x << ' ' << __FILE__ << ':' << __LINE__ << '\n';\
}
#endif

struct ThreadContext
{
	HANDLE process;
	HANDLE thread;
	int bits;
	union
	{
#ifdef _AMD64_
		CONTEXT ctx;
#endif
		WOW64_CONTEXT ctx86;
	};

	ThreadContext(HANDLE process, HANDLE thread, int bits, int ContextFlags=CONTEXT_FULL)
		: process(process), thread(thread), bits(bits)
	{
		if (bits == 33)
		{
			ctx86.ContextFlags = ContextFlags;
			Wow64GetThreadContext(thread, &ctx86);
		}
#ifdef _AMD64_
		else if (bits == 64)
		{
			ctx.ContextFlags = ContextFlags;
			GetThreadContext(thread, &ctx);
		}
#endif
	}

	void set()
	{
		if (bits == 33)
		{
			Wow64SetThreadContext(thread, &ctx86);
		}
#ifdef _AMD64_
		else if (bits == 64)
		{
			SetThreadContext(thread, &ctx);
		}
#endif
	}
#ifdef _AMD64_

#define REG_RW(name)\
	uint64_t name()\
	{\
		if (bits == 33)\
		{\
			return ctx86.E##name;\
		}\
		else if (bits == 64)\
		{\
			return ctx.R##name;\
		}\
		WDD_ASSERT(!"invalid architecture");\
		return 0;\
	}\
	\
	void name(uint64_t v)\
	{\
		if (bits == 33)\
		{\
			ctx86.E##name = (DWORD)v;\
		}\
		else if (bits == 64)\
		{\
			ctx.R##name = v;\
		}\
	}
#define REG_RW64(name)\
	uint64_t r##name()\
	{\
		if (bits == 33)\
		{\
			WDD_ASSERT(!"no register named R" ## #name);\
			return 0;\
		}\
		else if (bits == 64)\
		{\
			return ctx.R##name;\
		}\
		WDD_ASSERT(!"invalid architecture");\
		return 0;\
	}\
	\
	void r##name(uint64_t v)\
	{\
		if (bits == 33)\
		{\
			WDD_ASSERT(!"no register named R" ## #name);\
		}\
		else if (bits == 64)\
		{\
			ctx.R##name = v;\
		}\
	}
#else
#define REG_RW(name)\
	uint64_t name()\
	{\
		if (bits == 33)\
		{\
			return ctx86.E##name;\
		}\
		WDD_ASSERT(!"invalid architecture");\
		return 0;\
	}\
	\
	void name(uint64_t v)\
	{\
		if (bits == 33)\
		{\
			ctx86.E##name = (DWORD)v;\
		}\
	}
#define REG_RW64(name)\
	uint64_t r##name()\
	{\
		if (bits == 33)\
		{\
			WDD_ASSERT(!"no register named R" ## #name);\
			return 0;\
		}\
		WDD_ASSERT(!"invalid architecture");\
		return 0;\
	}\
	\
	void r##name(uint64_t v)\
	{\
		if (bits == 33)\
		{\
			WDD_ASSERT(!"no register named R" ## #name);\
		}\
	}
#endif
	REG_RW(ax);
	REG_RW(bx);
	REG_RW(cx);
	REG_RW(dx);
	REG_RW(ip);
	REG_RW(sp);
	REG_RW(bp);
	REG_RW(si);
	REG_RW(di);
	REG_RW64(8);
	REG_RW64(9);
	REG_RW64(10);
	REG_RW64(11);
	REG_RW64(12);
	REG_RW64(13);
	REG_RW64(14);
	REG_RW64(15);


	DWORD eflags()
	{
		if (bits == 33)
		{
			return ctx86.EFlags; 
		}
#ifdef _AMD64_
		else if (bits == 64)
		{
			return ctx.EFlags;
		}
#endif
		WDD_ASSERT(!"invalid architecture"); 
		return 0;
	}
	
	void eflags(DWORD v)
	{
		if (bits == 33)
		{
			ctx86.EFlags = v;
		}
#ifdef _AMD64_
		else if (bits == 64)
		{
			ctx.EFlags = v;
		}
#endif
	}

	uint64_t arg0()
	{
		if (bits == 33)
		{
			DWORD ret;
			ReadProcessMemory(process, (LPVOID)((char*)0+ctx86.Esp + 4), &ret, 4, nullptr);
			return ret;
		}
#ifdef _AMD64_
		else if (bits == 64)
		{
			return ctx.Rcx;
		}
#endif
		WDD_ASSERT(!"invalid architecture");
		return 0;
	}

	uint64_t arg1()
	{
		if (bits == 33)
		{
			DWORD ret;
			ReadProcessMemory(process, (LPVOID)((char*)0 + ctx86.Esp + 8), &ret, 4, nullptr);
			return ret;
		}
#ifdef _AMD64_
		else if (bits == 64)
		{
			return ctx.Rdx;
		}
#endif
		WDD_ASSERT(!"invalid architecture");
		return 0;
	}
	uint64_t arg2()
	{
		if (bits == 33)
		{
			DWORD ret;
			ReadProcessMemory(process, (LPVOID)((char*)0 + ctx86.Esp + 12), &ret, 4, nullptr);
			return ret;
		}
#ifdef _AMD64_
		else if (bits == 64)
		{
			return ctx.R8;
		}
#endif
		WDD_ASSERT(!"invalid architecture");
		return 0;
	}
	uint64_t arg3()
	{
		if (bits == 33)
		{
			DWORD ret;
			ReadProcessMemory(process, (LPVOID)((char*)0 + ctx86.Esp + 16), &ret, 4, nullptr);
			return ret;
		}
#ifdef _AMD64_
		else if (bits == 64)
		{
			return ctx.R9;
		}
#endif
		WDD_ASSERT(!"invalid architecture");
		return 0;
	}
	uint64_t arg(int n)
	{
		n += 1;
		if (n == 1)
			return arg0();
		else if (n == 2)
			return arg1();
		else if (n == 3)
			return arg2();
		else if (n == 4)
			return arg3();
		if (bits == 33)
		{
			DWORD ret;
			ReadProcessMemory(process, (LPVOID)((char*)0 + ctx86.Esp + 4*n), &ret, 4, nullptr);
			return ret;
		}
#ifdef _AMD64_
		else if (bits == 64)
		{
			uint64_t ret;
			ReadProcessMemory(process, (LPVOID)((char*)0 + ctx.Rsp + 8 * n), &ret, 8, nullptr);
			return ret;
		}
#endif
		WDD_ASSERT(!"invalid architecture");
		return 0;
	}
	uint64_t ret4()
	{
		if (bits == 33)
			return ctx86.Eax;
#ifdef _AMD64_
		if (bits == 64)
			return ctx.Rax;
#endif
		WDD_ASSERT(!"invalid architecture");
		return 0;
	}

	void ret4(DWORD ret)
	{
		if (bits == 33)
		{
			ctx86.Eax = ret;
		}
#ifdef _AMD64_
		if (bits == 64)
		{
			ctx.Rax = ret;
		}
#endif
	}

	uint64_t ret8()
	{
		if (bits == 33)
		{
			return ((uint64_t)ctx86.Edx << 32) + ctx86.Eax;
		}
#ifdef _AMD64_
		if (bits == 64)
		{
			return ctx.Rax;
		}
#endif
	}

	void ret8(uint64_t ret)
	{
		if (bits == 33)
		{
			ctx86.Eax = ret & 0xFFFFFFFFFFFFFFFF;
			ctx86.Edx = (ret >> 32)&0xFFFFFFFFFFFFFFFF;
		}
#ifdef _AMD64_
		if (bits == 64)
		{
			ctx.Rax = ret;
		}
#endif
	}
};
