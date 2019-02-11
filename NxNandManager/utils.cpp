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
		printf("%s (Y/N) : ", question);
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
	return FALSE;
}

/*
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
*/
std::string GetReadableSize(u64 size)
{
	char buf[100];
	if (size / (1024 * 1024 * 1024) > 0)
	{
		sprintf_s(buf, sizeof(buf), "%.2f Gb", (double)size / (1024 * 1024 * 1024));
	}
	else if (size / (1024 * 1024) > 0)
	{
		sprintf_s(buf, sizeof(buf), "%.2f Mb", (double)size / (1024 * 1024));
	}
	else if (size / 1024 > 0)
	{
		sprintf_s(buf, sizeof(buf), "%.2f Kb", (double)size / 1024);
	}
	else 
	{
		sprintf_s(buf, sizeof(buf), "%I64d byte%s", size, size>1 ? "s" : "");
	}	
	return std::string(buf);
}

void throwException(const char* errorStr)
{
	if(NULL != errorStr) printf("%s\n", errorStr);
	system("PAUSE");
	exit(EXIT_FAILURE);
}
// Concatenate every compatible physical disk n° in a string
std::string ListPhysicalDrives()
{
	int num_drive = 0;
	std::string compatibleDrives;

	for (int drive = 0; drive < 26; drive++)
	{		
		char driveName[256];
		sprintf_s(driveName, 256, "\\\\.\\PhysicalDrive%d", drive);		

		HANDLE hPhysicalDriveIOCTL = 0;
		hPhysicalDriveIOCTL = CreateFileW(convertCharArrayToLPWSTR(driveName), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hPhysicalDriveIOCTL == INVALID_HANDLE_VALUE)
		{
			break;
		}

		STORAGE_PROPERTY_QUERY query;
		DWORD cbBytesReturned = 0;
		char local_buffer[10000];

		memset((void *)& query, 0, sizeof(query));
		query.PropertyId = StorageDeviceProperty;
		query.QueryType = PropertyStandardQuery;

		memset(local_buffer, 0, sizeof(local_buffer));

		if (DeviceIoControl(hPhysicalDriveIOCTL, IOCTL_STORAGE_QUERY_PROPERTY, &query, 
			sizeof(query), &local_buffer[0], sizeof(local_buffer), &cbBytesReturned, NULL))
		{
			STORAGE_DEVICE_DESCRIPTOR * descrip = (STORAGE_DEVICE_DESCRIPTOR *)& local_buffer;
			char productId[1000];
			char vendorId[1000];
			flipAndCodeBytes(local_buffer, descrip->VendorIdOffset, 0, vendorId); 
			flipAndCodeBytes(local_buffer, descrip->ProductIdOffset, 0, productId);

			//printf("Vendor Id = %s / Product Id = %s\n", vendorId, productId);				
			char VID[] = "Linux";
			char PID[] = "UMS disk ";
			if (strncmp(vendorId, VID, array_countof(VID) - 1) == 0 && strncmp(productId, PID, array_countof(PID) - 1) == 0)
			{
				std::string s = std::to_string(drive);
				compatibleDrives.append("\\\\.\\PhysicalDrive" + s + "\n");
				num_drive++;
			}
		}
	}
	//compatibleDrives[num_drive] = '\0';
	if (compatibleDrives == "")
	{
		compatibleDrives = "No compatible drive detected.\n\n";
	} else {
		compatibleDrives = compatibleDrives + "\n";
	}
	return compatibleDrives;
}

char * flipAndCodeBytes(const char * str,  int pos, int flip, char * buf) 
{
	int i;
	int j = 0;
	int k = 0;

	buf[0] = '\0';
	if (pos <= 0)
		return buf;

	if (!j)
	{
		char p = 0;

		// First try to gather all characters representing hex digits only.
		j = 1;
		k = 0;
		buf[k] = 0;
		for (i = pos; j && str[i] != '\0'; ++i)
		{
			char c = tolower(str[i]);

			if (isspace(c))
				c = '0';

			++p;
			buf[k] <<= 4;

			if (c >= '0' && c <= '9')
				buf[k] |= (unsigned char)(c - '0');
			else if (c >= 'a' && c <= 'f')
				buf[k] |= (unsigned char)(c - 'a' + 10);
			else
			{
				j = 0;
				break;
			}

			if (p == 2)
			{
				if (buf[k] != '\0' && !isprint(buf[k]))
				{
					j = 0;
					break;
				}
				++k;
				p = 0;
				buf[k] = 0;
			}

		}
	}

	if (!j)
	{
		// There are non-digit characters, gather them as is.
		j = 1;
		k = 0;
		for (i = pos; j && str[i] != '\0'; ++i)
		{
			char c = str[i];

			if (!isprint(c))
			{
				j = 0;
				break;
			}

			buf[k++] = c;
		}
	}

	if (!j)
	{
		// The characters are not there or are not printable.
		k = 0;
	}

	buf[k] = '\0';

	if (flip)
		// Flip adjacent characters
		for (j = 0; j < k; j += 2)
		{
			char t = buf[j];
			buf[j] = buf[j + 1];
			buf[j + 1] = t;
		}

	// Trim any beginning and end space
	i = j = -1;
	for (k = 0; buf[k] != '\0'; ++k)
	{
		if (!isspace(buf[k]))
		{
			if (i < 0)
				i = k;
			j = k;
		}
	}

	if ((i >= 0) && (j >= 0))
	{
		for (k = i; (k <= j) && (buf[k] != '\0'); ++k)
			buf[k - i] = buf[k];
		buf[k - i] = '\0';
	}

	return buf;
}