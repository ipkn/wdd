#include "stdafx.h"
#include "../wddlib/RecordSession.h"
#include "../wddlib/ReplaySession.h"
#include "../wddlib/Symbols.h"

void usage()
{
	std::cout << R"(To record:
	wdd record [command] [arg1] [arg2] ...

To replay:
	wdd replay [command]
)";
}

int wmain(int argc, wchar_t* argv[])
{
	CoInitializeEx(nullptr, COINIT_MULTITHREADED);

	std::vector<std::wstring> args(argv+1, argv+argc);
	if (args.empty())
	{
		usage();
		return -1;
	}

	if (args[0] == L"record")
	{
		args.erase(args.begin());
		RecordSession rs(std::move(args));

		rs.Start();
	}
	else if (args[0] == L"replay")
	{
		args.erase(args.begin());
		ReplaySession rs;

		rs.Start(args);
	}
	else if (args[0] == L"symbol")
	{
		SymbolTable st(args[1]);
		st.EnumerateAll();
	}
	else if (args[0] == L"symbollines")
	{
		SymbolTable st(args[1]);
		auto va = st.GetVA(args[2], true);
		IDiaSymbol* func;
		st.findSymbolByVA(va, &func);
		uint64_t func_length;
		func->get_virtualAddress(&va);
		func->get_length(&func_length);
		auto pLines = st.GetEnumLineNumbers(va, func_length);
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
			std::wcout << line_number << L'\t' << std::hex << line_va << std::dec << std::endl;
		}
	}
	else
	{
		RecordSession rs(std::move(args));

		rs.Start();
	}
	CoUninitialize();

    return 0;
}

