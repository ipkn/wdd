#include "stdafx.h"
#include "Symbols.h"
#include <sstream>

class CCallback : 
	public IDiaLoadCallback2
{
public:
	virtual HRESULT STDMETHODCALLTYPE NotifyDebugDir(
		/* [in] */ BOOL fExecutable,
		/* [in] */ DWORD cbData,
		/* [size_is][in] */ BYTE *pbData) {
		//std::wcout << fExecutable << '\n';
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE NotifyOpenDBG(
		/* [in] */ LPCOLESTR dbgPath,
		/* [in] */ HRESULT resultCode) {
		//std::wcout << dbgPath << ' ' << resultCode << '\n';
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE NotifyOpenPDB(
		/* [in] */ LPCOLESTR pdbPath,
		/* [in] */ HRESULT resultCode) {
		OutputDebugStringW(L"[PDB] ");
		OutputDebugStringW(pdbPath);
		std::wostringstream os;
		os << std::hex << (DWORD)resultCode;
		OutputDebugStringW(os.str().c_str());
		//std::wcout << pdbPath << ' ' << resultCode << '\n';
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE RestrictRegistryAccess(void)
	{
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE RestrictSymbolServerAccess(void)
	{
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID rid, _Outptr_ void **ppUnk)
	{
		if (ppUnk == NULL) {
			return E_INVALIDARG;
		}
		if (rid == __uuidof(IDiaLoadCallback2))
			*ppUnk = (IDiaLoadCallback2 *)this;
		else if (rid == __uuidof(IDiaLoadCallback))
			*ppUnk = (IDiaLoadCallback *)this;
		else if (rid == __uuidof(IUnknown))
			*ppUnk = (IUnknown *)this;
		else
			*ppUnk = NULL;
		if (*ppUnk != NULL) {
			AddRef();
			return S_OK;
		}
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef()
	{
		return 1;
	}
	ULONG STDMETHODCALLTYPE Release()
	{
		return 1;
	}

	virtual HRESULT STDMETHODCALLTYPE RestrictOriginalPathAccess(void) { return S_OK; }

	virtual HRESULT STDMETHODCALLTYPE RestrictReferencePathAccess(void) { return S_OK; }

	virtual HRESULT STDMETHODCALLTYPE RestrictDBGAccess(void) { return S_OK; }

	virtual HRESULT STDMETHODCALLTYPE RestrictSystemRootAccess(void) { return S_OK; }
};

SymbolTable::SymbolTable(const std::wstring & name)
{
	CComPtr<IDiaDataSource> pSource;
	HRESULT hr = CoCreateInstance(CLSID_DiaSource,
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(IDiaDataSource),
		(void **)&pSource);
	CCallback callback;
	hr = pSource->loadDataForExe(name.c_str(), L"srv*.wdd\\_symbols*https://msdl.microsoft.com/download/symbols", &callback);
	if (!SUCCEEDED(hr))
	{
//		MessageBoxA(nullptr, "Check symsrv.dll for current directory", "Error", MB_OK);
	}
	hr = pSource->openSession(&session_);

	hr = session_->get_globalScope(&global_);

}

uint64_t SymbolTable::GetVA(const std::wstring & function_name, bool exact)
{
	HRESULT hr;
	CComPtr<IDiaEnumSymbols> enumerator;
	if (exact)
	{
		hr = global_->findChildren(SymTagPublicSymbol, function_name.c_str(), nsRegularExpression, &enumerator);
	}
	else
	{
		hr = global_->findChildren(SymTagPublicSymbol, (L"*" + function_name + L"*").c_str(), nsRegularExpression, &enumerator);
	}
	if (hr != S_OK)
		return 0;
	CComPtr<IDiaSymbol> symbol;
	ULONG celt = 0;
	hr = enumerator->Next(1, &symbol, &celt);
	if (hr != S_OK)
		return 0;
	ULONGLONG va;
	hr = symbol->get_virtualAddress(&va);
	if (hr != S_OK)
		return 0;
	{
		std::wostringstream os;
		os << L"GetVA " << function_name << std::hex << ' ' << va;
		OutputDebugStringW(os.str().c_str());
	}
	return va;
}

template <typename T>
struct EnumNamesHelper
{
	static std::unordered_map<T, std::wstring> names;
};

template <typename T>
std::unordered_map<T, std::wstring> EnumNamesHelper<T>::names;

struct EnumNames
{
	EnumNames()
	{
#define REGISTER(x) EnumNamesHelper<decltype(x)>::names.emplace(x, L#x)
		REGISTER(SymTagNull);
		REGISTER(SymTagExe);
		REGISTER(SymTagCompiland);
		REGISTER(SymTagCompilandDetails);
		REGISTER(SymTagCompilandEnv);
		REGISTER(SymTagFunction);
		REGISTER(SymTagBlock);
		REGISTER(SymTagData);
		REGISTER(SymTagAnnotation);
		REGISTER(SymTagLabel);
		REGISTER(SymTagPublicSymbol);
		REGISTER(SymTagUDT);
		REGISTER(SymTagEnum);
		REGISTER(SymTagFunctionType);
		REGISTER(SymTagPointerType);
		REGISTER(SymTagArrayType);
		REGISTER(SymTagBaseType);
		REGISTER(SymTagTypedef);
		REGISTER(SymTagBaseClass);
		REGISTER(SymTagFriend);
		REGISTER(SymTagFunctionArgType);
		REGISTER(SymTagFuncDebugStart);
		REGISTER(SymTagFuncDebugEnd);
		REGISTER(SymTagUsingNamespace);
		REGISTER(SymTagVTableShape);
		REGISTER(SymTagVTable);
		REGISTER(SymTagCustom);
		REGISTER(SymTagThunk);
		REGISTER(SymTagCustomType);
		REGISTER(SymTagManagedType);
		REGISTER(SymTagDimension);
		REGISTER(SymTagCallSite);
		REGISTER(SymTagInlineSite);
		REGISTER(SymTagBaseInterface);
		REGISTER(SymTagVectorType);
		REGISTER(SymTagMatrixType);
		REGISTER(SymTagHLSLType);
		REGISTER(SymTagCaller);
		REGISTER(SymTagCallee);
		REGISTER(SymTagExport);
		REGISTER(SymTagHeapAllocationSite);
		REGISTER(SymTagCoffGroup);
		REGISTER(SymTagMax);

#undef REGISTER
	}

} *enumNames;

template <typename T>
auto getName(T x)
{
	return EnumNamesHelper<T>::names[x];
}

void SymbolTable::EnumerateAll()
{
	if (!enumNames)
		enumNames = new EnumNames();
	std::unordered_set<DWORD> visit;
	auto Enumerate = [&](IDiaSymbol* s, int depth, auto Enumerate)->void {
		std::wstring tab(depth, L'\t');
		DWORD id;
		s->get_symIndexId(&id);
		if (visit.count(id))
		{
			std::wcout << tab << L"(already) x" << id << L"x" << std::endl;
			return;
		}
		visit.insert(id);
		CComPtr<IDiaEnumSymbols> enumerator;
		s->findChildren(SymTagNull, L"*", nsRegularExpression, &enumerator);
		if (!enumerator)
			return;
		HRESULT hr;
		LONG cnt=0;
		hr = enumerator->get_Count(&cnt);
		std::vector<CComPtr<IDiaSymbol>> symbols;
		for (int i = 0; i < cnt; i++)
		{
			CComPtr<IDiaSymbol> symbol;
			ULONG celt = 0;

			hr = enumerator->Next(1, &symbol, &celt);
			if (hr == S_FALSE)
				continue;
			symbols.push_back(symbol);
		}
		enumerator = nullptr;
		int i = 0;
		std::wcout << tab << cnt << L' ' << symbols.size() << std::endl;
		for(auto symbol:symbols)
		{
			std::wcout << tab << i + 1 << L"/" << cnt << std::endl;
			{
				// dump properties
				DWORD symIndexId;
				symbol->get_symIndexId(&symIndexId);

				BSTR name;
				if (S_OK == symbol->get_name(&name))
				{
					std::wcout << tab << L"- " << name << L" x" << symIndexId <<L"x"<< std::endl;
				}
				else
				{
					std::wcout << tab << L"- (unnamed) x" << symIndexId <<L"x"<<std::endl;
				}
				DWORD symTag;
				if (S_OK == symbol->get_symTag(&symTag))
				{
					std::wcout << tab<< L"  symTag\t" << getName<enum SymTagEnum>((enum SymTagEnum)symTag) << std::endl;
				}
				ULONGLONG va;
				hr = symbol->get_virtualAddress(&va);
				if (hr == S_OK)
				{
					std::wcout << tab << L"  virtualAddress\t" << std::hex << va << std::dec << std::endl;
				}
			}

			Enumerate(symbol, depth + 1, Enumerate);
			i++;
		}
	};
	Enumerate(global_, 0, Enumerate);
}

void SymbolTable::SetBase(uint64_t base)
{
	std::ostringstream os;
	os << "SetBase " << std::hex << base;
	OutputDebugStringA(os.str().c_str());
	session_->put_loadAddress(base);
}


HRESULT SymbolTable::GetEnumFrameData(IDiaEnumFrameData** ppEnumFrameData)
{
	HRESULT hr = NOERROR;
	CComPtr<IDiaEnumTables> pEnumTables;
	CComPtr<IDiaTable> pTable;
	REFIID iid = __uuidof(IDiaEnumFrameData);
	ULONG celt = 0;

	hr = session_->getEnumTables(&pEnumTables);

	if (SUCCEEDED(hr))
	{
		while ((hr = pEnumTables->Next(1, &pTable, &celt)) == S_OK && celt == 1)
		{
			HRESULT hr = pTable->QueryInterface(iid, (void**)ppEnumFrameData);
			pTable.Release();
			if (hr == S_OK)
			{
				break;
			}
		}
	}

	return hr;
}