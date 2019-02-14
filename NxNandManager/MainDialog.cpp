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
	InitInputCombo();

	isDirOutput = FALSE;
	if (NULL != input)
	{
		CString Filename(input);
		CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_INPUT_COMBO);
		AddInputComboString(Filename);
		pComboBox->SetCurSel(pComboBox->GetCount()-1);
		//GetDlgItem(IDC_INPUT_COMBO)->SetWindowTextW(Filename);
		OnChangeINPUT();
	}
	if (NULL != output)
	{
		CString Filename(output);
		GetDlgItem(IDC_OUTPUT)->SetWindowTextW(Filename);
	}

	return TRUE;
}


// This is the main function called for dump operations
// Unless it fails controls, a new dialog box will pop, in a new thread (until dump ends in main thread)
int MainDialog::dumpStorage(NxStorage* nxInput, NxStorage* nxOutput, u64* bytesWritten, const char* partition)
{
	HANDLE hDisk, hDiskOut;
	u64 bytesToRead = nxInput->size, readAmount = 0, writeAmount = 0;
	BOOL bSuccess;
	int rc;

	// Get handle for input
	rc = nxInput->GetIOHandle(&hDisk, GENERIC_READ, NULL, partition, NULL != partition ? &bytesToRead : NULL);
	if (rc < -1)
	{
		MessageBox(_T("Failed to get handle to input file/disk"), _T("Error"), MB_OK | MB_ICONERROR);
		return -2;
	}
	// Get handle for output
	rc = nxOutput->GetIOHandle(&hDiskOut, GENERIC_WRITE, bytesToRead, partition, NULL != partition ? &bytesToRead : NULL);
	if (rc < -1)
	{
		if (rc == ERR_NO_SPACE_LEFT) MessageBox(_T("Output disk : not enough space !"), _T("Error"), MB_OK | MB_ICONERROR);
		else MessageBox(_T("Failed to get handle to output file/disk"), _T("Error"), MB_OK | MB_ICONERROR);
		return -2;
	}

	// Open dialog in new thread
	m_pThread = new CUIThread();
	m_pThread->m_bAutoDelete = FALSE;
	m_pThread->SetParent(this);
	m_pThread->SetString(TEXT("0"));
	m_pThread->CreateThread();

	// Disable start button
	CWnd* pWnd = GetDlgItem(IDOK);
	pWnd->EnableWindow(FALSE);

	// Dump data
	int percent = 0;
	m_pThread->SetPercent(_T("0"));

	CString message, part(partition), type(nxInput->GetNxStorageTypeAsString());
	message.Format(_T("Dumping %s... (%d%%)"), NULL != partition ? part : type, percent);
	m_pThread->SetString(message);
	while (bSuccess = nxInput->dumpStorage(&hDisk, &hDiskOut, &readAmount, &writeAmount, bytesToRead))
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

	// Kill thread
	if (m_pThread->IsRunning())
	{
		m_pThread->Kill();
	}

	if (writeAmount != bytesToRead)
	{
		char buff[256];
		sprintf_s(buff, 256, "ERROR : %I64d bytes to read but %I64d bytes written", bytesToRead, writeAmount);
		CString message(buff);
		MessageBox(message, _T("Error"), MB_OK | MB_ICONERROR);
		return -1;
	}
	return 0;
}

BOOL MainDialog::isDirectory(const char* dirName) {
	DWORD attribs = GetFileAttributesA(dirName);
	if (attribs == INVALID_FILE_ATTRIBUTES) {
		return false;
	}
	return (attribs & FILE_ATTRIBUTE_DIRECTORY);
}

void MainDialog::InitInputCombo()
{
	CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_INPUT_COMBO);
	int j = 0;
	pComboBox->ResetContent();

	// Fist item is always Select file
	pComboBox->InsertString(0, _T("-> Select file..."));

	// Add all drives
	std::string drives = ListPhysicalDrives();
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

CString MainDialog::GetCurrentInput()
{
	CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_INPUT_COMBO);
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

void MainDialog::AddInputComboString(CString inStr)
{
	CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_INPUT_COMBO);
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
	ON_EN_CHANGE(IDC_OUTPUT, &MainDialog::OnEnChangeOutput)
	ON_BN_CLICKED(IDOK, &MainDialog::OnBnClickedOk)
	ON_WM_TIMER()
	ON_MESSAGE(WM_INFORM_CLOSE, OnClosing)
	ON_LBN_SELCHANGE(IDC_PARTLIST, &MainDialog::OnLbnSelchangePartlist)
	ON_CBN_SELCHANGE(IDC_INPUT_COMBO, &MainDialog::OnChangeINPUT)
END_MESSAGE_MAP()


void MainDialog::OnChangeINPUT()
{	
	// Get selected input string
	CString file(GetCurrentInput());

	CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_INPUT_COMBO);
	// "Select file..." is selected
	if(pComboBox->GetCurSel() == 0)
	{
		GetDlgItem(IDC_INPUT_COMBO)->SetWindowTextW(_T(""));

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
			// File selected
			CFile File2;
			VERIFY(File2.Open(FileOpenDialog.GetPathName(), CFile::modeRead));
			CString Filename;
			Filename = File2.GetFilePath();
			
			// Reset then add new file to combo
			InitInputCombo(); 
			AddInputComboString(Filename);

			AfxGetMainWnd()->UpdateWindow();
			pComboBox->SetCurSel(pComboBox->GetCount() - 1);
			// Overwrite input file
			file = GetCurrentInput();

		} else {			
			// No file selected, exit func
			return;
		}
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
	if (nxInput.type == BOOT0 || nxInput.type == BOOT1)
	{
		char buff[128];
		sprintf_s(buff, 128, "%s (%s)", nxInput.GetNxStorageTypeAsString(), GetReadableSize(nxInput.size).c_str());
		CString part(buff);
		pListBox->AddString(part);
	}

	// Check "Dump all partitions" checkbox
	if (pListBox->GetCount() > 0)
	{
		// We always want to dump all partitions (default) whenever new input is selected
		CButton *m_ctlCheck = (CButton*)GetDlgItem(IDC_DUMP_ALL);
		BOOL IsCheckChecked = (m_ctlCheck->GetCheck() == 1) ? true : false;
		if (!IsCheckChecked)
		{
			m_ctlCheck->SetCheck(1);
			this->OnBnClickedDumpAll();
		}
		// So output is a file
		GetDlgItem(IDC_GROUP_OUTPUT)->SetWindowTextW(TEXT("Output file : "));
	}
}

void MainDialog::OnEnChangeOutput()
{
	CString file;
	GetDlgItem(IDC_OUTPUT)->GetWindowTextW(file);
	CT2A outputStr(file);
	output = outputStr;
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
		GetDlgItem(IDC_GROUP_OUTPUT)->SetWindowTextW(TEXT("Output file : "));

		CString out;
		GetDlgItem(IDC_OUTPUT)->GetWindowTextW(out);
		CT2A outbuf(out);
		if (out.GetLength() > 0 && isDirectory(outbuf))
		{
			CWinAppEx* pApp = DYNAMIC_DOWNCAST(CWinAppEx, AfxGetApp());
			if (pApp != NULL)
			{
				pApp->InitShellManager();
			}
			CMFCEditBrowseCtrl* pEditBrowse = (CMFCEditBrowseCtrl*)GetDlgItem(IDC_OUTPUT);
			pEditBrowse->EnableFileBrowseButton();

			GetDlgItem(IDC_OUTPUT)->SetWindowTextW(TEXT(""));
		}
		isDirOutput = FALSE;
	} else {
		pListBox->EnableWindow(TRUE);
	}
}

void MainDialog::OnLbnSelchangePartlist()
{
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

		}
	}

	return 0;
}

void MainDialog::OnBnClickedOk()
{
	if (m_pThread == NULL)
	{
		BOOL bSuccess = FALSE;
		CString in(GetCurrentInput()), out;
		GetDlgItem(IDC_INPUT_COMBO)->GetWindowTextW(in);
		GetDlgItem(IDC_OUTPUT)->GetWindowTextW(out);
		if (in.GetLength() == 0 || out.GetLength() == 0)
		{
			MessageBox(_T("You have to specify both input and output."), _T("Error"), MB_OK | MB_ICONERROR);
			return;
		}
		
		CButton *m_ctlCheck = (CButton*)GetDlgItem(IDC_DUMP_ALL);
		BOOL isDumpAll = (m_ctlCheck->GetCheck() == 1) ? true : false;

		CT2A inputStr(in);
		char buff[64];
		NxStorage nxInput(inputStr);
		if (nxInput.size <= 0)
		{
			sprintf_s(buff, 64, "Error while trying to read input stream\n");
		}
		CT2A outputStr(out);
		NxStorage nxOutput(outputStr);
		// TODO : Add controls for output (& intput ?)
		/*
		if (nxOutput.type == INVALID)
		{
			sprintf_s(buff, 64, "Error while trying to open output stream\n");
		}
		
		CString message(buff);
		if (nxInput.size <= 0 || nxOutput.type == INVALID)
		{
			MessageBox(message, _T("Error"), MB_OK | MB_ICONERROR);
			return;
		}
		*/

		CWnd* pListBox = GetDlgItem(IDC_PARTLIST);
		int num_check = 0;
		u64 bytesWritten = 0, writeAmount = 0;

		// User selected partitions
		if (!isDumpAll && NULL != nxInput.firstPartion)
		{
			CListBox* pListBox = (CListBox*)GetDlgItem(IDC_PARTLIST);
			for (int i = 0; i <= (int)pListBox->GetCount() - 1; i++)
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
							// Set ouutput filename (partition_name.bin)
							CString nout, part(cur->name);
							nout.Format(_T("%s%s%s.bin"), out, out.GetAt((int)out.GetLength() - 1) == '\\' ? "" : "\\", part);
							CT2A outStr(nout);
						
							// New NxStorage for input (nxInput not in stack at this point, why ?)
							CString in(GetCurrentInput());
							CT2A inStr(in);
							NxStorage cur_nxInput(inStr);
							
							// New NxStorage for output
							NxStorage cur_nxOutput(outStr);

							// Dump input into output
							if (dumpStorage(&cur_nxInput, &cur_nxOutput, &bytesWritten, cur->name) >= 0) {
								bSuccess = TRUE;
								writeAmount += bytesWritten;
							}
						}
						num_part++;
						cur = cur->next;
					}		
				}
			}			
		} 

		// User selected raw dump
		if(isDumpAll || num_check == 0)
		{
			if (dumpStorage(&nxInput, &nxOutput, &bytesWritten) >= 0) 
			{
				bSuccess = TRUE;
				writeAmount = bytesWritten;
			}
		}

		// When every operation is over & success, format message
		if (bSuccess)
		{
			CString message, buf;
			if (num_check > 0) buf.Format(_T("%d partition%s dumped."), num_check, num_check > 1 ? _T("s") : _T(""));
			CString size(GetReadableSize(writeAmount).c_str());
			message.Format(_T("Finished. %s\n%s written."), num_check > 0 ? buf : _T(""), size);
			MessageBox(message, _T("Information"), MB_OK | MB_ICONINFORMATION);
		}
	}
}

