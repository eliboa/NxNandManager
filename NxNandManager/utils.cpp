#include "utils.h"
using namespace std;

wchar_t *convertCharArrayToLPCWSTR(const char* charArray)
{
	wchar_t* wString = new wchar_t[4096];
	MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wString, 4096); //Fix issue #1
	return wString;
}

LPWSTR convertCharArrayToLPWSTR(const char* charArray)
{

	//int nSize = MultiByteToWideChar(CP_ACP, 0, charArray, -1, NULL, 0);
	int nSize = MultiByteToWideChar(CP_UTF8, 0, charArray, -1, NULL, 0); //Fix issue #1
	LPWSTR wString = new WCHAR[nSize];
	MultiByteToWideChar(CP_UTF8, 0, charArray, -1, wString, 4096);
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
		s[2 * i]	 = hexmap[(data[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	for (auto & c: s) c = toupper(c);

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

std::string GetReadableElapsedTime(std::chrono::duration<double> elapsed_seconds)
{
	char buf[64];
	int seconds = (int)elapsed_seconds.count();
	int minutes = seconds / 60;
	if (minutes > 0) seconds = seconds % 60;
	int hours = minutes / 60;
	if (hours > 0) minutes = minutes % 60;

	if ((int)elapsed_seconds.count() > 1)
	{
		sprintf_s(buf, 64, "%02d:%02d:%02d", hours, minutes, seconds);
	} else {
		sprintf_s(buf, 64, "%.2fs", elapsed_seconds.count());
	}
	return std::string(buf);
}
void throwException(int rc, const char* errorStr)
{
	if (NULL != errorStr) printf("%s\n", errorStr);
	else {
		for (int i=0; i < (int)array_countof(ErrorLabelArr); i++)
		{
			if(ErrorLabelArr[i].error == rc)
			{
				printf("ERROR: %s\n", ErrorLabelArr[i].label);
			}
		}
	}
	SetThreadExecutionState(ES_CONTINUOUS);
	exit(rc);
}
void throwException(const char* errorStr)
{
	SetThreadExecutionState(ES_CONTINUOUS);
	if(NULL != errorStr) printf("%s\n", errorStr);
	exit(EXIT_FAILURE);
}


// Concatenate every compatible physical disk n� in a string
std::string ListPhysicalDrives(BOOL noError)
{
	int num_drive = 0;
	std::string compatibleDrives;

	for (int drive = 0; drive < 26; drive++)
	{

		DiskSector ds;
		CPartitionManager m_pm;

		char driveName0[256];
		sprintf_s(driveName0, 256, "PhysicalDrive%d", drive);
		char driveName[256];
		sprintf_s(driveName, 256, "\\\\.\\PhysicalDrive%d", drive);

		if (!ds.OpenPhysicalDrive(drive))
			continue;

		ULONGLONG diskLength;
		if (!ds.GetDiskLength(diskLength)) {
			ds.Close();
			continue;
		}

		m_pm.m_bIncludeExtendedPartitionDefinitions = true;

		bool found = false;
		// Read MBR
		if (m_pm.ReadPartitionTable(drive, 0)) {

			// Iterate partitions
			size_t nbPartsTotal = 0, nbParts = m_pm.partlist.size();
			for (size_t i = 0; i < nbParts; i++)
			{
				partition_info &pi = m_pm.partlist[i];

				// Offset must be in range
				if (pi.lba_start + 0x8002 > pi.lba_end)
					continue;

				// Look for BOOT0 at offset pi.lba_start + 0x8002 + 0x130
				unsigned char buff[512] = { 0 };
				ds.ReadSector(pi.lba_start + 0x8002, &buff);
				if (hexStr(&buff[0x130], 12) == "010021000E00000009000000") {
					std::string s = std::to_string(drive);
					compatibleDrives.append("\\\\.\\PhysicalDrive" + s + " [" + GetReadableSize(diskLength) + " - MMC Partition detected]\n");
					num_drive++;
					found = true;
				}
			}
		}
		ds.Close();

		if (found)
			continue;

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
				compatibleDrives.append("\\\\.\\PhysicalDrive" + s + " [ " + GetReadableSize(diskLength) + " - Memloader drive]\n");
				num_drive++;
			}			
			
		}
	}
	
	//compatibleDrives[num_drive] = '\0';
	if (num_drive == 0)
	{
		if(!noError) throwException(ERR_NO_LIST_DISK, "No compatible drive detected.");
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

std::string ExePath()
{
	wchar_t buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);
	wstring ws(buffer);
	return string(ws.begin(), ws.end());
}

HMODULE GetCurrentModule()
{
	HMODULE hModule = NULL;
	GetModuleHandleEx(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
				(LPCTSTR)GetCurrentModule,
				&hModule);

	return hModule;
}

bool is_file_exist(const wchar_t * fileName)
{
#if defined(__MINGW32__) || defined(__MINGW64__) || defined(__MSYS__)
	char buffer[_MAX_PATH];
	std::wcstombs(buffer, fileName, _MAX_PATH);
	std::ifstream infile(buffer);
#else
	std::ifstream infile(fileName);
#endif
	return infile.good();
}

const std::string WHITESPACE = " \n\r\t\f\v";

std::string ltrim(const std::string& s)
{
	size_t start = s.find_first_not_of(WHITESPACE);
	return (start == std::string::npos) ? "" : s.substr(start);
}

std::string rtrim(const std::string& s)
{
	size_t end = s.find_last_not_of(WHITESPACE);
	return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

std::string trim(const std::string& s)
{
	return rtrim(ltrim(s));
}

int parseKeySetFile(const char *keyset_file, KeySet* biskeys)
{

    int num_keys = 0;
	ifstream readFile(keyset_file);
	string readout;
	std::string delimiter = ":";
	std::string value = "";
	if (readFile.is_open())
	{			
		memset(biskeys->crypt0, 0, 33);
		memset(biskeys->tweak0, 0, 33);
		memset(biskeys->crypt1, 0, 33);
		memset(biskeys->tweak1, 0, 33);
		memset(biskeys->crypt2, 0, 33);
		memset(biskeys->tweak2, 0, 33);
		memset(biskeys->crypt3, 0, 33);
		memset(biskeys->tweak3, 0, 33);

		while (getline(readFile, readout)) {
			value.clear();
			if (readout.find("BIS KEY 0 (crypt)") != std::string::npos) {						
				value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
				strcpy_s(biskeys->crypt0, value.substr(0, 32).c_str());
				num_keys++;
			} else if (readout.find("BIS KEY 0 (tweak)") != std::string::npos) {						
				value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
				strcpy_s(biskeys->tweak0, value.substr(0, 32).c_str());
				num_keys++;
			} else if (readout.find("BIS KEY 1 (crypt)") != std::string::npos) {						
				value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
				strcpy_s(biskeys->crypt1, value.substr(0, 32).c_str());
				num_keys++;
			} else if (readout.find("BIS KEY 1 (tweak)") != std::string::npos) {						
				value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
				strcpy_s(biskeys->tweak1, value.substr(0, 32).c_str());
				num_keys++;
			} else if (readout.find("BIS KEY 2 (crypt)") != std::string::npos) {						
				value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
				strcpy_s(biskeys->crypt2, value.substr(0, 32).c_str());
				num_keys++;
			} else if (readout.find("BIS KEY 2 (tweak)") != std::string::npos) {						
				value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
				strcpy_s(biskeys->tweak2, value.substr(0, 32).c_str());
				num_keys++;
			} else if (readout.find("BIS KEY 3 (crypt)") != std::string::npos) {						
				value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
				strcpy_s(biskeys->crypt3, value.substr(0, 32).c_str());
				num_keys++;
			} else if (readout.find("BIS KEY 3 (tweak)") != std::string::npos) {						
				value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
				strcpy_s(biskeys->tweak3, value.substr(0, 32).c_str());
				num_keys++;
			} else if (readout.find("bis_key_00") != std::string::npos) {						
				value = trim(readout.substr(readout.find("=") + 2, readout.length() + 1));
				strcpy_s(biskeys->crypt0, value.substr(0, 32).c_str());				
				strcpy_s(biskeys->tweak0, value.substr(32, 32).c_str());
				num_keys += 2;
			} else if (readout.find("bis_key_01") != std::string::npos) {						
				value = trim(readout.substr(readout.find("=") + 2, readout.length() + 1));
				strcpy_s(biskeys->crypt1, value.substr(0, 32).c_str());
				strcpy_s(biskeys->tweak1, value.substr(32, 32).c_str());
				num_keys += 2;
			}else if (readout.find("bis_key_02") != std::string::npos) {						
				value = trim(readout.substr(readout.find("=") + 2, readout.length() + 1));
				strcpy_s(biskeys->crypt2, value.substr(0, 32).c_str());
				strcpy_s(biskeys->tweak2, value.substr(32, 32).c_str());
				num_keys += 2;
			} else if (readout.find("bis_key_03") != std::string::npos) {						
				value = trim(readout.substr(readout.find("=") + 2, readout.length() + 1));
				strcpy_s(biskeys->crypt3, value.substr(0, 32).c_str());
				strcpy_s(biskeys->tweak3, value.substr(32, 32).c_str());
				num_keys += 2;
			}
		}
	} else {
		return 0;
	}

	// toupper keys
	for(int i=0;i<strlen(biskeys->crypt0);i++) biskeys->crypt0[i] = toupper(biskeys->crypt0[i]);
	for(int i=0;i<strlen(biskeys->crypt1);i++) biskeys->crypt1[i] = toupper(biskeys->crypt1[i]);
	for(int i=0;i<strlen(biskeys->crypt2);i++) biskeys->crypt2[i] = toupper(biskeys->crypt2[i]);
	for(int i=0;i<strlen(biskeys->crypt3);i++) biskeys->crypt3[i] = toupper(biskeys->crypt3[i]);
	for(int i=0;i<strlen(biskeys->tweak0);i++) biskeys->tweak0[i] = toupper(biskeys->tweak0[i]);
	for(int i=0;i<strlen(biskeys->tweak1);i++) biskeys->tweak1[i] = toupper(biskeys->tweak1[i]);
	for(int i=0;i<strlen(biskeys->tweak2);i++) biskeys->tweak2[i] = toupper(biskeys->tweak2[i]);
	for(int i=0;i<strlen(biskeys->tweak3);i++) biskeys->tweak3[i] = toupper(biskeys->tweak3[i]);

	readFile.close();
	return num_keys;
}

int digit_to_int(char d)
{
	char str[2];

	str[0] = d;
	str[1] = '\0';
	return (int)strtol(str, NULL, 10);
}