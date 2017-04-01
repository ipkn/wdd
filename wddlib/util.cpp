#include "stdafx.h"
#include "util.h"
// from https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/

void
ArgvQuote(
	const std::wstring& Argument,
	std::wstring& CommandLine,
	bool Force
)

/*++

Routine Description:

This routine appends the given argument to a command line such
that CommandLineToArgvW will return the argument string unchanged.
Arguments in a command line should be separated by spaces; this
function does not add these spaces.

Arguments:

Argument - Supplies the argument to encode.

CommandLine - Supplies the command line to which we append the encoded argument string.

Force - Supplies an indication of whether we should quote
the argument even if it does not contain any characters that would
ordinarily require quoting.

Return Value:

None.

Environment:

Arbitrary.

--*/

{
	//
	// Unless we're told otherwise, don't quote unless we actually
	// need to do so --- hopefully avoid problems if programs won't
	// parse quotes properly
	//

	if (Force == false &&
		Argument.empty() == false &&
		Argument.find_first_of(L" \t\n\v\"") == Argument.npos)
	{
		CommandLine.append(Argument);
	}
	else {
		CommandLine.push_back(L'"');

		for (auto It = Argument.begin(); ; ++It) {
			unsigned NumberBackslashes = 0;

			while (It != Argument.end() && *It == L'\\') {
				++It;
				++NumberBackslashes;
			}

			if (It == Argument.end()) {

				//
				// Escape all backslashes, but let the terminating
				// double quotation mark we add below be interpreted
				// as a metacharacter.
				//

				CommandLine.append(NumberBackslashes * 2, L'\\');
				break;
			}
			else if (*It == L'"') {

				//
				// Escape all backslashes and the following
				// double quotation mark.
				//

				CommandLine.append(NumberBackslashes * 2 + 1, L'\\');
				CommandLine.push_back(*It);
			}
			else {

				//
				// Backslashes aren't special here.
				//

				CommandLine.append(NumberBackslashes, L'\\');
				CommandLine.push_back(*It);
			}
		}

		CommandLine.push_back(L'"');
	}
}

std::wstring BuildCommandLine(const std::vector<std::wstring>& args)
{
	std::wstring cmd;
	for (auto& arg : args)
	{
		if (!cmd.empty())
			cmd += L' ';
		ArgvQuote(arg, cmd, false);
	}
	return cmd;
}

// from http://stackoverflow.com/questions/65170/how-to-get-name-associated-with-open-handle
t_NtQueryObject NtQueryObject()
{
	static t_NtQueryObject f_NtQueryObject = NULL;
	if (!f_NtQueryObject)
	{
		HMODULE h_NtDll = GetModuleHandle(L"Ntdll.dll"); // Ntdll is loaded into EVERY process!
		f_NtQueryObject = (t_NtQueryObject)GetProcAddress(h_NtDll, "NtQueryObject");
	}
	return f_NtQueryObject;
}

DWORD GetNtPathFromHandle(HANDLE h_File, std::wstring& ps_NTPath)
{
	if (h_File == 0 || h_File == INVALID_HANDLE_VALUE)
		return ERROR_INVALID_HANDLE;

	// NtQueryObject() returns STATUS_INVALID_HANDLE for Console handles
	if (IsConsoleHandle(h_File))
	{
		//ps_NTPath->Format(L"\\Device\\Console%04X", (DWORD)(DWORD_PTR)h_File);
		ps_NTPath = L"\\Device\\Console";
		return 0;
	}

	BYTE  u8_Buffer[2000];
	DWORD u32_ReqLength = 0;

	UNICODE_STRING* pk_Info = &((OBJECT_NAME_INFORMATION*)u8_Buffer)->Name;
	pk_Info->Buffer = 0;
	pk_Info->Length = 0;

	// IMPORTANT: The return value from NtQueryObject is bullshit! (driver bug?)
	// - The function may return STATUS_NOT_SUPPORTED although it has successfully written to the buffer.
	// - The function returns STATUS_SUCCESS although h_File == 0xFFFFFFFF
	NtQueryObject()(h_File, ObjectNameInformation, u8_Buffer, sizeof(u8_Buffer), &u32_ReqLength);

	// On error pk_Info->Buffer is NULL
	if (!pk_Info->Buffer || !pk_Info->Length)
		return ERROR_FILE_NOT_FOUND;

	pk_Info->Buffer[pk_Info->Length / 2] = 0; // Length in Bytes!

	ps_NTPath = pk_Info->Buffer;
	return 0;
}

DWORD GetPathFromHandle(HANDLE hFile, std::wstring & path)
{
	std::wstring ntpath;
	DWORD ret = GetNtPathFromHandle(hFile, ntpath);
	if (ret)
		return ret;
	return GetDosPathFromNtPath(ntpath.c_str(), path);
}

// converts
// "\Device\HarddiskVolume3"                                -> "E:"
// "\Device\HarddiskVolume3\Temp"                           -> "E:\Temp"
// "\Device\HarddiskVolume3\Temp\transparent.jpeg"          -> "E:\Temp\transparent.jpeg"
// "\Device\Harddisk1\DP(1)0-0+6\foto.jpg"                  -> "I:\foto.jpg"
// "\Device\TrueCryptVolumeP\Data\Passwords.txt"            -> "P:\Data\Passwords.txt"
// "\Device\Floppy0\Autoexec.bat"                           -> "A:\Autoexec.bat"
// "\Device\CdRom1\VIDEO_TS\VTS_01_0.VOB"                   -> "H:\VIDEO_TS\VTS_01_0.VOB"
// "\Device\Serial1"                                        -> "COM1"
// "\Device\USBSER000"                                      -> "COM4"
// "\Device\Mup\ComputerName\C$\Boot.ini"                   -> "\\ComputerName\C$\Boot.ini"
// "\Device\LanmanRedirector\ComputerName\C$\Boot.ini"      -> "\\ComputerName\C$\Boot.ini"
// "\Device\LanmanRedirector\ComputerName\Shares\Dance.m3u" -> "\\ComputerName\Shares\Dance.m3u"
// returns an error for any other device type
DWORD GetDosPathFromNtPath(const WCHAR* u16_NTPath, std::wstring& ps_DosPath)
{
	DWORD u32_Error;

	if (wcsnicmp(u16_NTPath, L"\\Device\\Serial", 14) == 0 || // e.g. "Serial1"
		wcsnicmp(u16_NTPath, L"\\Device\\UsbSer", 14) == 0)   // e.g. "USBSER000"
	{
		HKEY h_Key;
		if (u32_Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"Hardware\\DeviceMap\\SerialComm", 0, KEY_QUERY_VALUE, &h_Key))
			return u32_Error;

		WCHAR u16_ComPort[50];

		DWORD u32_Type;
		DWORD u32_Size = sizeof(u16_ComPort);
		if (u32_Error = RegQueryValueEx(h_Key, u16_NTPath, 0, &u32_Type, (BYTE*)u16_ComPort, &u32_Size))
		{
			RegCloseKey(h_Key);
			return ERROR_UNKNOWN_PORT;
		}

		ps_DosPath = u16_ComPort;
		RegCloseKey(h_Key);
		return 0;
	}

	if (wcsnicmp(u16_NTPath, L"\\Device\\LanmanRedirector\\", 25) == 0) // Win XP
	{
		ps_DosPath = L"\\\\";
		ps_DosPath += (u16_NTPath + 25);
		return 0;
	}

	if (wcsnicmp(u16_NTPath, L"\\Device\\Mup\\", 12) == 0) // Win 7
	{
		ps_DosPath = L"\\\\";
		ps_DosPath += (u16_NTPath + 12);
		return 0;
	}

	WCHAR u16_Drives[300];
	if (!GetLogicalDriveStrings(300, u16_Drives))
		return GetLastError();

	WCHAR* u16_Drv = u16_Drives;
	while (u16_Drv[0])
	{
		WCHAR* u16_Next = u16_Drv + wcslen(u16_Drv) + 1;

		u16_Drv[2] = 0; // the backslash is not allowed for QueryDosDevice()

		WCHAR u16_NtVolume[1000];
		u16_NtVolume[0] = 0;

		// may return multiple strings!
		// returns very weird strings for network shares
		if (!QueryDosDevice(u16_Drv, u16_NtVolume, sizeof(u16_NtVolume) / 2))
			return GetLastError();

		int s32_Len = (int)wcslen(u16_NtVolume);
		if (s32_Len > 0 && wcsnicmp(u16_NTPath, u16_NtVolume, s32_Len) == 0)
		{
			ps_DosPath = u16_Drv;
			ps_DosPath += (u16_NTPath + s32_Len);
			return 0;
		}

		u16_Drv = u16_Next;
	}
	return ERROR_BAD_PATHNAME;
}

// from http://stackoverflow.com/questions/4804298/how-to-convert-wstring-into-string
std::wstring s2ws(const std::string& str)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(str);
}

std::string ws2s(const std::wstring& wstr)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}