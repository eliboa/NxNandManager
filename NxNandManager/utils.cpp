#include "utils.h"
using namespace std;

wchar_t *convertCharArrayToLPCWSTR(const char* charArray)
{
	wchar_t* wString = new wchar_t[4096];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
	return wString;
}

LPWSTR convertCharArrayToLPWSTR(const char* charArray)
{
	int nSize = MultiByteToWideChar(CP_ACP, 0, charArray, -1, NULL, 0);
	LPWSTR wString = new WCHAR[nSize];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
	return wString;
}


u64 GetFilePointerEx (HANDLE hFile) {
	LARGE_INTEGER liOfs={0};
	LARGE_INTEGER liNew={0};
	SetFilePointerEx(hFile, liOfs, &liNew, FILE_CURRENT);
	return liNew.QuadPart;
}

unsigned long sGetFileSize(std::string filename)
{
	struct stat stat_buf;
	int rc = stat(filename.c_str(), &stat_buf);
	return rc == 0 ? stat_buf.st_size : -1;
}

std::string GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) return std::string(); //No error message has been recorded

	LPSTR messageBuffer = NULL;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}


constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
std::string hexStr(unsigned char *data, int len)
{
	std::string s(len * 2, ' ');
	for (int i = 0; i < len; ++i)
	{
		s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return s;
}

BOOL AskYesNoQuestion(const char* question)
{
	BOOL bContinue = TRUE;
	string s;
	while (bContinue)
	{
		printf("%s (Y/N)\n", question);
		cin >> ws;
		getline(cin, s);
		if (s.empty())
		{
			continue;
		}
		switch (toupper(s[0]))
		{
		case 'Y':
			return TRUE;
			break;
		case 'N':
			return FALSE;
			break;
		}
	}
}

const char* GetNxStorageTypeAsString(int type)
{
	switch (type)
	{
	case BOOT0:
		return "BOOT0";
		break;
	case BOOT1:
		return "BOOT1";
		break;
	case RAWNAND:
		return "RAWNAND";
		break;
	default:
		return "UNKNOWN";
		break;
	}
}