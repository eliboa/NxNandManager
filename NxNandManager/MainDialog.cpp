// MainDialog.cpp : implementation file
//

#include "stdafx.h"
#include "MainDialog.h"
#include "afxdialogex.h"

// MainDialog dialog

IMPLEMENT_DYNAMIC(MainDialog, CDialog)

MainDialog::MainDialog(const char* arg_input, const char* arg_output, CWnd* pParent /*=NULL*/)
	: CDialog(IDD_MAINDIALOG, pParent)
{
	input = (char*)arg_input;
	output = (char*)arg_output;
}

MainDialog::~MainDialog()
{
}

BOOL MainDialog::OnInitDialog()
{
	CDialog::OnInitDialog();
	//std::string drives = ListPhysicalDrives(TRUE);
	InitInputCombo(IDC_INPUT_COMBO);
	InitInputCombo(IDC_OUTPUT_COMBO);

	isDirOutput = FALSE;
	if (NULL != input)
	{
		CString Filename(input);
		CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_INPUT_COMBO);
		AddInputComboString(IDC_INPUT_COMBO, Filename);
		pComboBox->SetCurSel(pComboBox->GetCount()-1);
		OnChangeINPUT();
	}
	if (NULL != output)
	{
		CString Filename(output);
		CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_OUTPUT_COMBO);
		AddInputComboString(IDC_OUTPUT_COMBO, Filename);
		pComboBox->SetCurSel(pComboBox->GetCount() - 1);
		OnEnChangeOUTPUT();
		//GetDlgItem(IDC_OUTPUT)->SetWindowTextW(Filename);
	}

	return TRUE;
}


// This is the main function called for dump operations
// Unless it fails controls, a new dialog box will pop, in a new thread (until dump ends in main thread)
int MainDialog::dumpStorage(NxStorage* nxInput, NxStorage* nxOutput, u64* bytesWritten, const char* partition)
{
	if (DEBUG_MODE) printf("MainDialog::dumpStorage");
	// Open dialog in new thread
	m_pThread = new CUIThread();
	m_pThread->m_bAutoDelete = FALSE;
	m_pThread->SetParent(this);
	//m_pThread->SetString(TEXT("0"));
	EnableWindow(FALSE);
	m_pThread->CreateThread();

	HANDLE hDisk, hDiskOut;
	u64 bytesToRead = nxInput->size, readAmount = 0, writeAmount = 0;
	BOOL bSuccess;
	int rc;
	CButton *m_ctlCheck = (CButton*)GetDlgItem(IDC_BYPASSMD5);
	BOOL bypassMD5 = (m_ctlCheck->GetCheck() == 1) ? true : false;

	// Get handle for input
	rc = nxInput->GetIOHandle(&hDisk, GENERIC_READ, NULL, partition, NULL != partition ? &bytesToRead : NULL);
	if (rc < -1)
	{
		if (m_pThread->IsRunning()) m_pThread->Kill();
		MessageBox(_T("Failed to get handle to input file/disk"), _T("Error"), MB_OK | MB_ICONERROR);
		return -2;
	}
	// Get handle for output
	rc = nxOutput->GetIOHandle(&hDiskOut, GENERIC_WRITE, bytesToRead, partition, NULL != partition ? &bytesToRead : NULL);
	if (rc < -1)
	{
		if (m_pThread->IsRunning()) m_pThread->Kill();
		if (rc == ERR_NO_SPACE_LEFT) MessageBox(_T("Output disk : not enough space !"), _T("Error"), MB_OK | MB_ICONERROR);
		else MessageBox(_T("Failed to get handle to output file/disk"), _T("Error"), MB_OK | MB_ICONERROR);
		return -2;
	}

	// Disable start button
	CWnd* pWnd = GetDlgItem(IDOK);
	pWnd->EnableWindow(FALSE);
	
	// Crypto
	hProv = 0;
	hHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	std::string md5hash;
	DWORD cbHash = MD5LEN;
	BYTE rgbHash[MD5LEN];
	
	if (!bypassMD5)
	{
		// Get handle to the crypto provider
		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			if (m_pThread->IsRunning()) m_pThread->Kill();
			MessageBox(L"Crypto provider error", _T("Error"), MB_OK | MB_ICONERROR);
			return ERR_CRYPTO_MD5;
		}

		// Create the hash
		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			if (m_pThread->IsRunning()) m_pThread->Kill();
			MessageBox(L"Crypto provider error", _T("Error"), MB_OK | MB_ICONERROR);
			return ERR_CRYPTO_MD5;
		}
	}
	
	// Dump data
	int percent = 0;
	m_pThread->SetPercent(_T("0"));

	CString message, part(partition), type(nxInput->GetNxStorageTypeAsString());
	message.Format(_T("Dumping %s... (%d%%)"), NULL != partition ? part : type, percent);
	m_pThread->SetString(message);
	if (DEBUG_MODE) printf("MainDialog::dumpStorage nxInput->dumpStorage()");
	while (bSuccess = nxInput->dumpStorage(&hDisk, &hDiskOut, &readAmount, &writeAmount, bytesToRead, !bypassMD5 ? &hHash : NULL))
	//while (bSuccess = nxInput->dumpStorage(&hDisk, &hDiskOut, &readAmount, &writeAmount, bytesToRead))
	{
		if (!m_pThread->IsRunning())
		{
			break;
		}
		int percent2 = (u64)writeAmount * 100 / (u64)bytesToRead;
		if (percent2 > percent)
		{
			percent = percent2;
			m_szMessage.Empty();
			m_szMessage.Format(TEXT("%d"), percent);
			m_pThread->SetPercent(m_szMessage);
			message.Format(_T("Dumping %s... (%d%%)"), NULL != partition ? part : type, percent);
			m_pThread->SetString(message);
		}
	}
	CloseHandle(hDisk);
	CloseHandle(hDiskOut);

	*bytesWritten = writeAmount;
	if (writeAmount != bytesToRead)
	{
		if (m_pThread->IsRunning())	m_pThread->Kill();
		char buff[256];
		sprintf_s(buff, 256, "ERROR : %I64d bytes to read but %I64d bytes written", bytesToRead, writeAmount);
		CString message(buff);
		MessageBox(message, _T("Error"), MB_OK | MB_ICONERROR);
		return -1;
	}

	
	if (!bypassMD5)
	{
		// Build checksum for input file/drive
		if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
		{
			char* buf;
			size_t sz;
			for (DWORD i = 0; i < cbHash; i++)
			{
				sz = snprintf(NULL, 0, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
				buf = (char*)malloc(sz + 1);
				snprintf(buf, sz + 1, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
				md5hash.append(buf);
			}
		} else {
			if (m_pThread->IsRunning()) m_pThread->Kill();
			MessageBox(L"Crypto provider error", _T("Error"), MB_OK | MB_ICONERROR);
			return ERR_CRYPTO_MD5;
		}
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		

		if (DEBUG_MODE) printf("MainDialog::dumpStorage nxOutput->InitStorage()");
		// Compute then compare output checksums
		nxOutput->InitStorage(); // We need to update output obj first (mandatory!)
		// Get handle to the file or I/O device
		if (nxOutput->GetIOHandle(&hDisk, GENERIC_READ, NULL, partition, &bytesToRead) < 0)
		{
			if (m_pThread->IsRunning()) m_pThread->Kill();
			return -4;
		}

		HCRYPTPROV hProv2 = 0;
		// Get handle to the crypto provider
		if (!CryptAcquireContext(&hProv2, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			printf("CryptAcquireContext failed");
			CloseHandle(hDisk);
			return NULL;
		}

		HCRYPTHASH hHash_out = 0;
		if (!CryptCreateHash(hProv2, CALG_MD5, 0, 0, &hHash_out))
		{
			if (m_pThread->IsRunning()) m_pThread->Kill();
			return ERR_CRYPTO_MD5;
		}
		
		DWORD buffSize = BUFSIZE, bytesRead = 0, bytesHash = 0;
		DWORD cbHash2 = MD5LEN;
		BYTE *buffRead = new BYTE[BUFSIZE];
		BYTE *hbuffer = new BYTE[BUFSIZE];
		
		if (DEBUG_MODE) printf("MainDialog::dumpStorage Computing checksum");
		percent = 0; readAmount = 0;
		m_pThread->SetPercent(L"0");
		m_pThread->SetString(_T("Computing checksum... (0%)"));
		
		while (bSuccess = ReadFile(hDisk, buffRead, buffSize, &bytesRead, NULL))
		{

			if (0 == bytesRead) break;
			readAmount += (u64)bytesRead;

			if (readAmount > bytesToRead)
			{
				// Adjust write buffer
				memcpy(hbuffer, &buffRead[0], buffSize - (readAmount - bytesToRead));
				bytesHash = buffSize - (readAmount - bytesToRead);
				if (bytesHash == 0) {
					delete[] buffRead;
					delete[] hbuffer;
					return FALSE;
				}
			} else {
				// Copy read to write buffer
				memcpy(hbuffer, &buffRead[0], buffSize);
				bytesHash = bytesRead;
			}
			// Hash every read buffer
			if (!CryptHashData(hHash_out, hbuffer, bytesHash, 0))
			{
				CryptReleaseContext(hProv, 0);
				CryptDestroyHash(hHash);
				CloseHandle(hDisk);
				if (m_pThread->IsRunning()) m_pThread->Kill();
				MessageBox(L"Crypto provider error", _T("Error"), MB_OK | MB_ICONERROR);
				delete[] buffRead;
				delete[] hbuffer;
				return ERR_CRYPTO_MD5;
			}


			int percent2 = (u64)readAmount * 100 / (u64)bytesToRead;
			if (percent2 > percent)
			{
				percent = percent2;
				m_szMessage.Empty();
				m_szMessage.Format(TEXT("%d"), percent);
				m_pThread->SetPercent(m_szMessage);
				message.Format(_T("Computing checksum... (%d%%)"), percent);
				m_pThread->SetString(message);
			}

			//printf("Computing MD5 checksum... (%d%%) \r", (int)(readAmount * 100 / bytesToRead));
			if (readAmount >= bytesToRead) break;
		}
		CloseHandle(hDisk);		

		// Build checksum
		std::string md5hash_out;
		if (CryptGetHashParam(hHash_out, HP_HASHVAL, rgbHash, &cbHash2, 0))
		{
			char* buf;
			size_t sz;
			for (DWORD i = 0; i < cbHash; i++)
			{
				sz = snprintf(NULL, 0, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
				buf = (char*)malloc(sz + 1);
				snprintf(buf, sz + 1, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
				md5hash_out.append(buf);
			}
		} else {
			if (m_pThread->IsRunning()) m_pThread->Kill();
			MessageBox(L"Crypto provider error", _T("Error"), MB_OK | MB_ICONERROR);
			delete[] buffRead;
			delete[] hbuffer;
			return ERR_CRYPTO_MD5;
		}		
		CryptDestroyHash(hHash_out);
		CryptReleaseContext(hProv2, 0);
		
		if (md5hash != md5hash_out)
		{
			if (m_pThread->IsRunning()) m_pThread->Kill();
			MessageBox(L"ERROR : checksums are DIFFERENT", _T("Error"), MB_OK | MB_ICONERROR);	
			delete[] buffRead;
			delete[] hbuffer;
			return ERR_MD5_COMPARE;
		}
		
		delete[] buffRead;
		delete[] hbuffer;
	}	
	
	if (m_pThread->IsRunning())	m_pThread->Kill();
	return 0;
}

BOOL MainDialog::isDirectory(const char* dirName) {
	DWORD attribs = GetFileAttributesA(dirName);
	if (attribs == INVALID_FILE_ATTRIBUTES) {
		return false;
	}
	return (attribs & FILE_ATTRIBUTE_DIRECTORY);
}

void MainDialog::InitInputCombo(int combo)
{
	CComboBox *pComboBox = (CComboBox*)GetDlgItem(combo);
	int j = 0;
	pComboBox->ResetContent();

	// Fist item is always Select file
	pComboBox->InsertString(j, _T("-> Select file..."));

	if (combo == IDC_OUTPUT_COMBO)
	{
		pComboBox->InsertString(j, _T("-> Select directory..."));
		j++;
	}

	// Add all drives
	std::string drives = ListPhysicalDrives(TRUE);
	CString csDrives(drives.c_str()), driveName;
	for (int i = 0; i < csDrives.GetLength(); ++i)
	{
		if (csDrives[i] == '\n' && driveName.GetLength() > 0) {
			j++;
			driveName.MakeUpper();
			pComboBox->InsertString(j, driveName);
			driveName = "";
		} else {
			driveName += csDrives[i];
		}
	}
}

CString MainDialog::GetCurrentInput(int combo)
{
	CComboBox *pComboBox = (CComboBox*)GetDlgItem(combo);
	CString file;
	int sel = pComboBox->GetCurSel(), n = pComboBox->GetLBTextLen(sel);
	if (sel <= 0)
	{
		file = "";
		return file;
	}
	pComboBox->GetLBText(sel, file.GetBuffer(n));
	file.ReleaseBuffer();
	return file;
}

void MainDialog::AddInputComboString(int combo, CString inStr)
{
	CComboBox *pComboBox = (CComboBox*)GetDlgItem(combo);
	int count = pComboBox->GetCount();
	for (int i = 0; i < count; i++)
	{
		CString curStr;
		int n = pComboBox->GetLBTextLen(i);
		pComboBox->GetLBText(i, curStr.GetBuffer(n));
		curStr.ReleaseBuffer();

		if (curStr == inStr)
		{
			// String already exists
			return;
		}
	}
	// Add string
	pComboBox->InsertString(count, inStr);
}

/*
 *  ****************
 *  MESSAGE HANDLERS
 *  ****************
 */


void MainDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(MainDialog, CDialog)
	ON_BN_CLICKED(IDC_DUMP_ALL, &MainDialog::OnBnClickedDumpAll)
	ON_BN_CLICKED(IDOK, &MainDialog::OnBnClickedOk)
	ON_MESSAGE(WM_INFORM_CLOSE, OnClosing)
	ON_LBN_SELCHANGE(IDC_PARTLIST, &MainDialog::OnLbnSelchangePartlist)
	ON_CBN_SELCHANGE(IDC_INPUT_COMBO, &MainDialog::OnChangeINPUT)
	ON_CBN_SELCHANGE(IDC_OUTPUT_COMBO, &MainDialog::OnEnChangeOUTPUT)
END_MESSAGE_MAP()


void MainDialog::OnChangeINPUT()
{	
	m_pThread = new CUIThread();
	m_pThread->m_bAutoDelete = FALSE;
	m_pThread->SetParent(this);
	m_pThread->SetString(TEXT("Analysing input...(please wait)"));

	// Get selected input string
	CString file(GetCurrentInput(IDC_INPUT_COMBO));

	CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_INPUT_COMBO);
	// "Select file..." is selected
	if(pComboBox->GetCurSel() == 0)
	{
		GetDlgItem(IDC_INPUT_COMBO)->SetWindowTextW(_T(""));
		CListBox* pListBox = (CListBox*)GetDlgItem(IDC_PARTLIST);
		pListBox->ResetContent();
		// Set filters for file dialog
		CString szFilter;
		szFilter = "NX & Bin files (*.bin;PRODINFO;BOOT...)|*.bin;PRODINFO;PRODINFOF;BCPKG2-1-Normal-Main;"
					"BCPKG2-2-Normal-Sub;BCPKG2-3-SafeMode-Main;BCPKG2-4-SafeMode-Sub;BOOT0;BOOT1;"
					"BCPKG2-5-Repair-Main;BCPKG2-6-Repair-Sub;SAFE;SYSTEM;USER"
					"|All files (*.*)|*.*||";
		
		// Open select file dialogbox
		CFileDialog FileOpenDialog(
			TRUE,
			NULL,
			NULL,
			OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST,
			szFilter,                       // filter 
			AfxGetMainWnd());               // the parent window  

		// Use current file as init dir
		FileOpenDialog.m_ofn.lpstrInitialDir = file;

		if (FileOpenDialog.DoModal() == IDOK)
		{
			// Open dialog in new thread
			if (!m_pThread->IsRunning())
			{								
				m_pThread->CreateThread();				
			}

			// File selected
			CFile File2;
			VERIFY(File2.Open(FileOpenDialog.GetPathName(), CFile::modeRead));
			CString Filename;
			Filename = File2.GetFilePath();
			
			// Reset then add new file to combo
			InitInputCombo(IDC_INPUT_COMBO);
			AddInputComboString(IDC_INPUT_COMBO, Filename);

			AfxGetMainWnd()->UpdateWindow();
			pComboBox->SetCurSel(pComboBox->GetCount() - 1);
			// Overwrite input file
			file = GetCurrentInput(IDC_INPUT_COMBO);

		} else {			
			if (m_pThread->IsRunning()) m_pThread->Kill();
			// No file selected, exit func
			return;
		}
	}

	
	// Open dialog in new thread
	if (!m_pThread->IsRunning())
	{
		m_pThread->CreateThread();
	}

	CT2A inputStr(file);
	input = inputStr;
	// New NxStorage for INPUT
	NxStorage nxInput(inputStr);
	
	// Reset partitions list
	CListBox*pListBox = (CListBox*)GetDlgItem(IDC_PARTLIST);
	pListBox->ResetContent();

	// If input is RAWNAND and GPT partition exists => List & add partitions to list box
	if (nxInput.type == RAWNAND && NULL != nxInput.firstPartion)
	{
		GptPartition *cur = nxInput.firstPartion;
		while (NULL != cur)
		{
			char buff[128];
			u64 size = ((u64)cur->lba_end - (u64)cur->lba_start) * (int)NX_EMMC_BLOCKSIZE;
			sprintf_s(buff, 128, "%s (%s)", cur->name, GetReadableSize(size).c_str());
			CString name(buff);
			pListBox->AddString(name);
			cur = cur->next;
		}
	}

	// If input is boot0 or boot1, add single partition in list box
	if (nxInput.type == BOOT0 || nxInput.type == BOOT1 || nxInput.type == PARTITION)
	{
		char buff[128];
		sprintf_s(buff, 128, "%s (%s)", nxInput.GetNxStorageTypeAsString(), GetReadableSize(nxInput.size).c_str());
		CString part(buff);
		pListBox->AddString(part);
	}

	CButton *m_ctlCheck = (CButton*)GetDlgItem(IDC_DUMP_ALL);
	BOOL IsCheckChecked = (m_ctlCheck->GetCheck() == 1) ? true : false;
	// Check "Dump all partitions" checkbox
	if (pListBox->GetCount() > 0)
	{
		// We always want to dump all partitions (default) whenever new input is selected
		if (!IsCheckChecked)
		{
			m_ctlCheck->SetCheck(1);
			this->OnBnClickedDumpAll();			
		}
	}
	if (pListBox->GetCount() <= 1)	m_ctlCheck->EnableWindow(FALSE);
	else m_ctlCheck->EnableWindow(TRUE);

	// Kill thread
	if (m_pThread->IsRunning()) m_pThread->Kill();
}

void MainDialog::OnEnChangeOUTPUT()
{
	// Get selected output string
	CString file(GetCurrentInput(IDC_OUTPUT_COMBO));

	m_pThread = new CUIThread();
	m_pThread->m_bAutoDelete = FALSE;
	m_pThread->SetParent(this);
	m_pThread->SetString(TEXT("Analysing output...(please wait)"));

	CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_OUTPUT_COMBO);
	// "Select file..." is selected
	if (pComboBox->GetCurSel() == 1)
	{

		GetDlgItem(IDC_OUTPUT_COMBO)->SetWindowTextW(_T(""));
		// Selet file
		// Set filters for file dialog
		CString szFilter;
		szFilter = "NX & Bin files (*.bin;PRODINFO;BOOT...)|*.bin;PRODINFO;PRODINFOF;BCPKG2-1-Normal-Main;"
			"BCPKG2-2-Normal-Sub;BCPKG2-3-SafeMode-Main;BCPKG2-4-SafeMode-Sub;BOOT0;BOOT1;"
			"BCPKG2-5-Repair-Main;BCPKG2-6-Repair-Sub;SAFE;SYSTEM;USER"
			"|All files (*.*)|*.*||";

		// Open select file dialogbox
		CFileDialog FileOpenDialog(
			FALSE,
			NULL,
			NULL,
			OFN_HIDEREADONLY,
			szFilter,                       // filter 
			AfxGetMainWnd());               // the parent window  

											// Use current file as init dir
		FileOpenDialog.m_ofn.lpstrInitialDir = file;

		if (FileOpenDialog.DoModal() == IDOK)
		{
			// Open dialog in new thread
			if (!m_pThread->IsRunning())
			{
				m_pThread->CreateThread();
				m_pThread->SetString(TEXT("Analysing output...(please wait)"));
			}
			// File selected
			file.Empty();
			file.Append(FileOpenDialog.GetPathName());
		} else {
			if (m_pThread->IsRunning()) m_pThread->Kill();
			return;
		}
	}
	// "Select directory..." is selected
	else if (pComboBox->GetCurSel() == 0)
	{
		GetDlgItem(IDC_OUTPUT_COMBO)->SetWindowTextW(_T("")); 

		// Select dir
		CFolderPickerDialog folderPickerDialog(file, OFN_FILEMUSTEXIST | OFN_ALLOWMULTISELECT | OFN_ENABLESIZING, this, sizeof(OPENFILENAME));
		CString folderPath;
		if (folderPickerDialog.DoModal() == IDOK)
		{
			// Open dialog in new thread
			if (!m_pThread->IsRunning())
			{
				m_pThread->CreateThread();
				m_pThread->SetString(TEXT("Analysing output...(please wait)"));
			}

			file.Empty();
			POSITION pos = folderPickerDialog.GetStartPosition();
			while (pos)
			{
				file = folderPickerDialog.GetNextPathName(pos);
			}
		} else {
			if (m_pThread->IsRunning()) m_pThread->Kill();
			return;
		}
	}

	if (pComboBox->GetCurSel() <= 1)
	{
		// Reset then add new file to combo
		InitInputCombo(IDC_OUTPUT_COMBO);
		AddInputComboString(IDC_OUTPUT_COMBO, file);

		AfxGetMainWnd()->UpdateWindow();
		pComboBox->SetCurSel(pComboBox->GetCount() - 1);
	}

	CT2A outputStr(file);
	NxStorage nxOutput(outputStr);
	CButton *m_ctlCheck = (CButton*)GetDlgItem(IDC_BYPASSMD5);
	if (nxOutput.isDrive) {
		m_ctlCheck->SetCheck(1);
		m_ctlCheck->EnableWindow(FALSE);
	} else {
		m_ctlCheck->SetCheck(0);
		m_ctlCheck->EnableWindow(TRUE);
	}
	if (m_pThread->IsRunning()) m_pThread->Kill();
}

void MainDialog::OnBnClickedDumpAll()
{
	CButton *m_ctlCheck = (CButton*)GetDlgItem(IDC_DUMP_ALL);
	BOOL IsCheckChecked = (m_ctlCheck->GetCheck() == 1) ? true : false;
	CWnd* pListBox = GetDlgItem(IDC_PARTLIST);
	if (IsCheckChecked)
	{		
		pListBox->EnableWindow(FALSE);
		CListBox* pListBox = (CListBox*)GetDlgItem(IDC_PARTLIST);
		for (int i = 0; i <= (int)pListBox->GetCount(); i++)
		{
			pListBox->SetSel(i, FALSE);
		}
	} else {
		pListBox->EnableWindow(TRUE);
	}
}

void MainDialog::OnLbnSelchangePartlist()
{
	/*
	GetDlgItem(IDC_GROUP_OUTPUT)->SetWindowTextW(TEXT("Output directory : "));
	isDirOutput = TRUE;

	CWinAppEx* pApp = DYNAMIC_DOWNCAST(CWinAppEx, AfxGetApp());
	if (pApp != NULL)
	{
		pApp->InitShellManager();
	}
	CMFCEditBrowseCtrl* pEditBrowse = (CMFCEditBrowseCtrl*)GetDlgItem(IDC_OUTPUT);
	pEditBrowse->EnableFolderBrowseButton();

	CString out;
	GetDlgItem(IDC_OUTPUT)->GetWindowTextW(out);
	CT2A outbuf(out);
	if (out.GetLength() > 0 && !isDirectory(outbuf)) {
		GetDlgItem(IDC_OUTPUT)->SetWindowTextW(TEXT(""));
	}
	*/
}

void MainDialog::OnTimer(UINT nIDEvent)
{
	//CDialog::OnTimer(nIDEvent);
}

LRESULT MainDialog::OnClosing(WPARAM wParam, LPARAM lParam)
{
	DWORD dwStatus;

	// Removing UI thread
	if (m_pThread != NULL)
	{
		VERIFY(::GetExitCodeThread(m_pThread->m_hThread, &dwStatus));
		if (dwStatus == STILL_ACTIVE)
		{
			// If the thread is still running, try to remove it 
			// in the next round.
			PostMessage(WM_INFORM_CLOSE, 0, 0);
		} else
		{
			// Completely remove the thread object
			delete m_pThread;
			m_pThread = NULL;

			CWnd* pWnd = GetDlgItem(IDOK);
			pWnd->EnableWindow(TRUE);
			EnableWindow(TRUE);
			SetActiveWindow();

		}
	}

	return 0;
}

void MainDialog::OnBnClickedOk()
{
	if (NULL != m_pThread) m_pThread = NULL;
	
	CString in(GetCurrentInput(IDC_INPUT_COMBO)), out(GetCurrentInput(IDC_OUTPUT_COMBO));
	char errbuff[512];
	CButton *m_ctlCheck = (CButton*)GetDlgItem(IDC_DUMP_ALL);
	BOOL isDumpAll = (m_ctlCheck->GetCheck() == 1) ? true : false, bSuccess = FALSE;
	CListBox* pListBox = (CListBox*)GetDlgItem(IDC_PARTLIST);
		
	if (in.GetLength() == 0 || out.GetLength() == 0)
	{
		MessageBox(_T("You have to specify both input and output."), _T("Error"), MB_OK | MB_ICONERROR);
		return;
	}

	m_pThread = new CUIThread();
	m_pThread->m_bAutoDelete = FALSE;
	m_pThread->SetParent(this);
	m_pThread->SetString(TEXT("Analysing input and output... (please wait)"));
	m_pThread->CreateThread();
	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	CT2A inputStr(in), outputStr(out);
	NxStorage nxInput(inputStr);
	NxStorage nxOutput(outputStr);

	if (nxInput.type == UNKNOWN || nxInput.type == INVALID)
	{
		if (m_pThread->IsRunning()) m_pThread->Kill();
		sprintf_s(errbuff, 512, "Input %s is not a valid NX storage type (%s)", nxInput.isDrive ? "drive" : "file", nxInput.GetNxStorageTypeAsString());
		MessageBox(convertCharArrayToLPWSTR(errbuff), _T("Error"), MB_OK | MB_ICONERROR);
		return;
	}
	if (in.MakeUpper() == out.MakeUpper())
	{
		if (m_pThread->IsRunning()) m_pThread->Kill();
		const int result = MessageBox(L"Output has to be different from input", L"Error", MB_OK | MB_ICONERROR);
		if (result != IDYES) return;
	}

	if (isDumpAll && nxOutput.type == INVALID && isDirectory(nxOutput.path))
	{
		if (m_pThread->IsRunning()) m_pThread->Kill();
		MessageBox(_T("Only one partition to copy, output must be a file"), _T("Error"), MB_OK | MB_ICONERROR);
		return;
	}

	if (isDumpAll && nxOutput.size > 0 && nxOutput.type != nxInput.type)
	{
		if (nxInput.type == PARTITION && nxOutput.type == RAWNAND) {}
		else {
			if (m_pThread->IsRunning()) m_pThread->Kill();
			sprintf_s(errbuff, 512, "Input type (%s) doesn't match output type (%s)", nxInput.GetNxStorageTypeAsString(), nxOutput.GetNxStorageTypeAsString());
			MessageBox(convertCharArrayToLPWSTR(errbuff), _T("Error"), MB_OK | MB_ICONERROR);
			return;
		}
	}

	if (nxOutput.size > 0 && !nxOutput.isDrive && isDumpAll && nxInput.type != PARTITION )
	{
		if (m_pThread->IsRunning()) m_pThread->Kill();
		const int result = MessageBox(L"Output file already exists. Do you want to overwrite it ?", L"Warning", MB_YESNO);
		if (result != IDYES) return;
	}

	int num_check = 0;
	u64 bytesWritten = 0, writeAmount = 0;
	
	if (NULL == m_pThread || m_pThread->IsRunning())
	{
		if(NULL != m_pThread) m_pThread->Kill();
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
	AfxGetMainWnd()->UpdateWindow();

	auto start = std::chrono::system_clock::now();
	if (!isDumpAll && NULL != nxInput.firstPartion)
	{
		int selCount = pListBox->GetSelCount();
		if (selCount <= 0) {
			MessageBox(_T("You have to select at least one partition"), _T("Error"), MB_OK | MB_ICONERROR);
			return;
		}
		if (nxOutput.type != RAWNAND && selCount > 1 && !isDirectory(outputStr)) {
			MessageBox(_T("More than one partition selected, output must be a directory"), _T("Error"), MB_OK | MB_ICONERROR);
			return;
		}
		if (nxOutput.type != RAWNAND && selCount == 1 && isDirectory(outputStr)) {
			MessageBox(_T("Only one partition selected, output must be a file"), _T("Error"), MB_OK | MB_ICONERROR);
			return;
		}
		int num_ok_part = 0;
		BOOL toRAWNAND = FALSE;

		CUIThread* m_pThread2 = new CUIThread();
		m_pThread2->m_bAutoDelete = TRUE;
		m_pThread2->SetParent(this);

		// 2 iterations, one for control, second for dump
		for (int it = 0; it <= 1; it++)
		{
			BOOL DUMP = it;
			num_check = 0;
			bSuccess = FALSE;

			if (!DUMP)
			{
				m_pThread2->CreateThread();
				m_pThread2->SetString(TEXT("Controlling partitions... (please wait)"));
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
				AfxGetMainWnd()->UpdateWindow();
			} else {
				if (m_pThread2->IsRunning()) {
					m_pThread2->Kill();
					std::this_thread::sleep_for(std::chrono::milliseconds(1000));
					AfxGetMainWnd()->UpdateWindow();
				}
			}


			if (DUMP && toRAWNAND)
			{
				std::string outpath(nxOutput.path);
				sprintf_s(errbuff, 512, "You are about to restore %d partition%S to Nx storage (RAWNAND) : %s.\n"
					"\nAre you sure you want to continue ?", num_ok_part, num_ok_part > 1 ? "s" : "",  base_name(outpath).c_str());
				const int result = MessageBox(convertCharArrayToLPWSTR(errbuff), L"Warning", MB_YESNO);
				if (result != IDYES) return;
			}

			int count = pListBox->GetCount() - 1;
			if (nxInput.type == PARTITION) count = 1;
			for (int i = 0; i <= count; i++)
			{
				// For every selected partition
				if (pListBox->GetSel(i))
				{
					num_check++;
					GptPartition *cur = nxInput.firstPartion;
					int num_part = 0;
					// Look for wanted partition in input partition list 
					while (NULL != cur)
					{
						if (num_part == i)
						{
							CString nout;
							if (nxOutput.type == RAWNAND || (selCount == 1 && !isDirectory(outputStr))) {
								nout = out;
							} else {
								// Set output filename (partition_name.bin)
								CString part(cur->name);
								nout.Format(_T("%s%s%s.bin"), out, out.GetAt((int)out.GetLength() - 1) == '\\' ? "" : "\\", part);
							}

							//NxStorage cur_nxInput(inStr);
							NxStorage *cur_nxInput = &nxInput;
							NxStorage *cur_nxOutput = &nxOutput;


							if (!DUMP) // Control
							{
								if (cur_nxOutput->type == RAWNAND)
								{
									toRAWNAND = TRUE;
									u64 size = (cur->lba_end - cur->lba_start + 1) * NX_EMMC_BLOCKSIZE;
									if (cur_nxOutput->IsValidPartition(cur->name, size) < 0) {
										sprintf_s(errbuff, 512, "%s is not a valid partition in output %s", cur->name, nxInput.isDrive ? "drive" : "file");
										MessageBox(convertCharArrayToLPWSTR(errbuff), _T("Error"), MB_OK | MB_ICONERROR);
										return;
									} else {
										num_ok_part++;
									}
								}
							} else {


								// New NxStorage for output
								CT2A outStr(nout);
								NxStorage cur_nxOutput2(outStr);

								// Dump input into output
								if (dumpStorage(cur_nxInput, &cur_nxOutput2, &bytesWritten, cur->name) >= 0) {
									bSuccess = TRUE;
									writeAmount += bytesWritten;
								}
							}
						}
						num_part++;
						cur = cur->next;
					}
				}
			}

		}
	} 

	// User selected raw dump
	if(isDumpAll || num_check == 0)
	{
		std::string out_part;
		BOOL part_exists = FALSE;
		if (nxInput.type == PARTITION && nxOutput.type == RAWNAND)
		{
			std::string basename = base_name(std::string(nxInput.path));
			basename = remove_extension(basename);
			if (nxOutput.IsValidPartition(basename.c_str(), nxInput.size))
			{
				out_part = basename;
				part_exists = TRUE;
				std::string outpath(nxOutput.path);
				sprintf_s(errbuff, 512, "You are about to restore partition \"%s\" to Nx storage (RAWNAND) : %s.\n"
					"\nAre you sure you want to continue ?", out_part.c_str(), base_name(outpath).c_str());
				const int result = MessageBox(convertCharArrayToLPWSTR(errbuff), L"Warning", MB_YESNO);
				if (result != IDYES) return;
			} else {
				sprintf_s(errbuff, 512, "%s is not a valid partition in output %s", basename.c_str(), nxInput.isDrive ? "drive" : "file");
				MessageBox(convertCharArrayToLPWSTR(errbuff), _T("Error"), MB_OK | MB_ICONERROR);
				return;
			}
		}

		if (nxOutput.isDrive && nxInput.type != PARTITION)
		{
			const int result = MessageBox(L"You are about to copy data to a physical drive.\nBE VERY CAUTIOUS !\nAre your sure you want to continue ?", L"Warning", MB_YESNOCANCEL);
			if (result != IDYES) return;
		}

		if (dumpStorage(&nxInput, &nxOutput, &bytesWritten, part_exists ? out_part.c_str() : NULL) >= 0)
		{
			bSuccess = TRUE;
			writeAmount = bytesWritten;
		}
	}

	// When every operation is over & success, format message
	if (bSuccess)
	{
		auto end = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsed_seconds = end - start;
		CString elapsed(GetReadableElapsedTime(elapsed_seconds).c_str());
		CString message, buf;
		if (num_check > 0) buf.Format(_T("%d partition%s dumped."), num_check, num_check > 1 ? _T("s") : _T(""));
		CString size(GetReadableSize(writeAmount).c_str());
		message.Format(_T("Finished. %s\n%s written.\nElapsed time : %s"), num_check > 0 ? buf : _T(""), size, elapsed);
		MessageBox(message, _T("Information"), MB_OK | MB_ICONINFORMATION);
	}
}

