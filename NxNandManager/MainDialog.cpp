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

	CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_INPUT_COMBO);
	char* drives = ListPhysicalDrives();
	CString csDrives(*drives);
	for (int i = 0; i < csDrives.GetLength(); ++i)
	{
		CString driveName;
		driveName.Format(_T("\\\\.\\PHYSICALDRIVE%c"), csDrives.GetAt(i));
		pComboBox->AddString(driveName);
	}

	isDirOutput = FALSE;
	if (NULL != input)
	{
		CString Filename(input);
		GetDlgItem(IDC_INPUT_COMBO)->SetWindowTextW(Filename);
		GetDlgItem(IDC_INPUT)->SetWindowTextW(Filename);
	}
	if (NULL != output)
	{
		CString Filename(output);
		GetDlgItem(IDC_OUTPUT)->SetWindowTextW(Filename);
	}

	pComboBox->AddString(_T("Select file..."));

	//pComboBox->SetCurSel(1);
	return TRUE;
}

void MainDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(MainDialog, CDialog)
	ON_EN_CHANGE(IDC_INPUT, &MainDialog::OnEnChangeInput)
	ON_BN_CLICKED(IDC_DUMP_ALL, &MainDialog::OnBnClickedDumpAll)
	ON_EN_CHANGE(IDC_OUTPUT, &MainDialog::OnEnChangeOutput)
	ON_BN_CLICKED(IDOK, &MainDialog::OnBnClickedOk)
	ON_WM_TIMER()
	ON_MESSAGE(WM_INFORM_CLOSE, OnClosing)
	ON_LBN_SELCHANGE(IDC_PARTLIST, &MainDialog::OnLbnSelchangePartlist)
	ON_CBN_SELCHANGE(IDC_INPUT_COMBO, &MainDialog::OnCbnSelchangeInputCombo)
	ON_CBN_EDITCHANGE(IDC_INPUT_COMBO, &MainDialog::OnCbnEditchangeInputCombo)
END_MESSAGE_MAP()


// MainDialog message handlers


void MainDialog::OnEnChangeInput()
{
	CString file;
	GetDlgItem(IDC_INPUT)->GetWindowTextW(file);
	CT2A inputStr(file);
	input = inputStr;
	CListBox*pListBox = (CListBox*)GetDlgItem(IDC_PARTLIST);
	NxStorage nxInput(inputStr);
	pListBox->ResetContent();

	if (nxInput.type == RAWNAND && NULL != nxInput.firstPartion)
	{		
		GptPartition *cur = nxInput.firstPartion;
		while (NULL != cur)
		{
			char buff[128];
			u64 size = ((u64)cur->lba_end - (u64)cur->lba_start) * (int) NX_EMMC_BLOCKSIZE;
			sprintf_s(buff, 128, "%s (%s)", cur->name, GetReadableSize(size).c_str());
			CString name(buff);
			pListBox->AddString(name);
			cur = cur->next;
		}
	}

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


void MainDialog::OnEnChangeOutput()
{
	CString file;
	GetDlgItem(IDC_OUTPUT)->GetWindowTextW(file);
	CT2A outputStr(file);
	output = outputStr;
}


void MainDialog::OnTimer(UINT nIDEvent)
{
	/*
	// Down counting.
	if (m_pThread && m_pThread->IsRunning())
	{
		m_szMessage.Empty();
		m_szMessage.Format(TEXT("This is a threaded dialog box.\n\nThis message will be cleared in %d second(s) or when OK button is depressed."), --m_nDownCounter);
		m_pThread->SetString(m_szMessage);
	}


	// Killing the interface thread.
	if (m_pThread && nIDEvent == 1 && m_nDownCounter == 0)
	{
		if (m_pThread->IsRunning())
		{
			m_pThread->Kill();
			KillTimer(1);
		}
	}
	*/
CDialog::OnTimer(nIDEvent);
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
		CString in, out;
		GetDlgItem(IDC_INPUT)->GetWindowTextW(in);
		GetDlgItem(IDC_OUTPUT)->GetWindowTextW(out);
		if (in.GetLength() == 0 || out.GetLength() == 0)
		{
			MessageBox(_T("You have to specify both input and output."), _T("Error"), MB_OK | MB_ICONERROR);
			return;
		}

		CT2A inputStr(in);
		char buff[64];
		NxStorage nxInput(inputStr);
		if (nxInput.size <= 0)
		{
			sprintf_s(buff, 64, "Error while trying to read input stream\n");
		}
		CT2A outputStr(out);
		NxStorage nxOutput(outputStr);
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

		CButton *m_ctlCheck = (CButton*)GetDlgItem(IDC_DUMP_ALL);
		BOOL IsCheckChecked = (m_ctlCheck->GetCheck() == 1) ? true : false;
		CWnd* pListBox = GetDlgItem(IDC_PARTLIST);
		int num_check = 0;
		u64 bytesWritten = 0, writeAmount = 0;

		if (!IsCheckChecked && NULL != nxInput.firstPartion)
		{
			CListBox* pListBox = (CListBox*)GetDlgItem(IDC_PARTLIST);
			for (int i = 0; i <= (int)pListBox->GetCount() - 1; i++)
			{
				if (pListBox->GetSel(i))
				{
					num_check++;
					GptPartition *cur = nxInput.firstPartion;
					int num_part = 0;
					while (NULL != cur)
					{
						if (num_part == i)
						{
							CString nout, part(cur->name);
							nout.Format(_T("%s%s%s.bin"), out, out.GetAt((int)out.GetLength() - 1) == '\\' ? "" : "\\", part);
							CT2A outStr(nout);
						
							CString in;
							GetDlgItem(IDC_INPUT)->GetWindowTextW(in);
							CT2A inStr(in);
							NxStorage cur_nxInput(inStr);
							
							//NxStorage cur_nxOutput(outputStr);
							NxStorage cur_nxOutput(outStr);
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
		if(IsCheckChecked || num_check == 0)
		{
			if (dumpStorage(&nxInput, &nxOutput, &bytesWritten) >= 0) 
			{
				bSuccess = TRUE;
				writeAmount = bytesWritten;
			}
		}

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

int MainDialog::dumpStorage(NxStorage* nxInput, NxStorage* nxOutput, u64* bytesWritten, const char* partition)
{
	HANDLE hDisk, hDiskOut;
	u64 bytesToRead = nxInput->size, readAmount = 0, writeAmount = 0;
	BOOL bSuccess;
	int rc;

	// Get handle for input
	rc = nxInput->GetIOHandle(&hDisk, GENERIC_READ, partition, NULL != partition ? &bytesToRead : NULL);
	if (rc < -1)
	{
		MessageBox(_T("Failed to get handle to input file/disk"), _T("Error"), MB_OK | MB_ICONERROR);
		return -2;
	}
	// Get handle for output
	rc = nxOutput->GetIOHandle(&hDiskOut, GENERIC_WRITE, partition, NULL != partition ? &bytesToRead : NULL);
	if (rc < -1)
	{
		MessageBox(_T("Failed to get handle to output file/disk"), _T("Error"), MB_OK | MB_ICONERROR);
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
	message.Format(_T("Dumping %s... (%d%%)"), NULL != partition ? part  : type, percent);
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



void MainDialog::OnCbnSelchangeInputCombo()
{
	CComboBox *pComboBox = (CComboBox*)GetDlgItem(IDC_INPUT_COMBO);
	CString curText;
	pComboBox->GetLBText((int)pComboBox->GetCurSel(), curText);

	if (curText.Find(_T("Select file...")) != -1)
	{
		GetDlgItem(IDC_INPUT_COMBO)->SetWindowTextW(_T(""));
		CString szFilter;
		szFilter = "Bin files (*.bin)|*.bin|All files (*.*)|*.*||";

		CFileDialog FileOpenDialog(
			TRUE,
			NULL,
			NULL,
			OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST,
			szFilter,                       // filter 
			AfxGetMainWnd());               // the parent window  

		CString file;
		this->GetDlgItem(IDC_INPUT_COMBO)->GetWindowTextW(file);
		FileOpenDialog.m_ofn.lpstrInitialDir = file;

		if (FileOpenDialog.DoModal() == IDOK)
		{
			CFile File;
			VERIFY(File.Open(FileOpenDialog.GetPathName(), CFile::modeRead));
			CString Filename;
			Filename = File.GetFilePath();
			GetDlgItem(IDC_INPUT_COMBO)->SetWindowTextW(Filename);			
			//OnEnChangePath();
		}
	}
	GetDlgItem(IDC_INPUT_COMBO)->SetWindowTextW(_T(""));
	return;
	// TODO: Add your control notification handler code here
}


void MainDialog::OnCbnEditchangeInputCombo()
{
	int test = 1;
}
