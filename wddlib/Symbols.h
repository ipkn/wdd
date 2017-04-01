#pragma once
#pragma comment (lib, "diaguids.lib")

class SymbolTable
{
public:
	SymbolTable(const std::wstring& name);

	uint64_t GetVA(const std::wstring& function_name, bool exact = false);
	void EnumerateAll();

	void SetBase(uint64_t base);

	HRESULT GetEnumFrameData(IDiaEnumFrameData** ppEnumFrameData);

	HRESULT findSymbolByVA(ULONGLONG va, IDiaSymbol** ppSymbol)
	{
		return session_->findSymbolByVA(va, SymTagFunction, ppSymbol);
	}

	HRESULT addressForVA(ULONGLONG va, _Out_ DWORD *pISect, _Out_ DWORD *pOffset)
	{
		return session_->addressForVA(va, pISect, pOffset);
	}

	IDiaEnumLineNumbers* GetEnumLineNumbers(ULONGLONG va, DWORD sz = 1)
	{
		IDiaEnumLineNumbers* pEnum{};
		session_->findLinesByVA(va, sz, &pEnum);
		return pEnum;
	}

	CComPtr<IDiaSession> session_;
	CComPtr<IDiaSymbol> global_;
};