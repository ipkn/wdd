// wdd-vscode.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "VsCodeDebugEngine.h"

int wmain(int argc, WCHAR** argv)
{
	HMODULE mod1;
	HMODULE mod2;
	{
		// some hacking
		WCHAR path[2048];
		WCHAR* filename;
		GetFullPathNameW(argv[0], 1024, path, &filename);
		*filename = 0;
		auto path_s = std::wstring(path);
		mod1 = LoadLibraryW((path_s + L"symsrv.dll").c_str());
		mod2 = LoadLibraryW((path_s + L"dbghelp.dll").c_str());
		_wchdir(path_s.c_str());

	}
	CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	VsCodeDebugEngine engine;
	try
	{
		engine.Run();
	}
	catch (std::exception& e)
	{
		MessageBoxA(nullptr, e.what(), "error", MB_OK);
	}
	CoUninitialize();
	FreeLibrary(mod2);
	FreeLibrary(mod1);
	return 0;
}

