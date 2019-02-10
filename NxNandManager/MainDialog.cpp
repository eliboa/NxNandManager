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
	
	if (NULL != input)
	{
		CString Filename(input);
		this->GetDlgItem(IDC_INPUT)->SetWindowTextW(Filename);
	}
	if (NULL != output)
	{
		CString Filename(output);
		this->GetDlgItem(IDC_OUTPUT)->SetWindowTextW(Filename);
	}

	return TRUE;
}

void MainDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(MainDialog, CDialog)
	ON_EN_CHANGE(IDC_INPUT, &MainDialog::OnEnChangeInput)
	ON_BN_CLICKED(IDC_DUMP_ALL, &MainDialog::OnBnClickedDumpAll)
	ON_LBN_SETFOCUS(IDC_PARTLIST, &MainDialog::OnLbnSetfocusPartlist)
	ON_EN_CHANGE(IDC_OUTPUT, &MainDialog::OnEnChangeOutput)
	ON_BN_CLICKED(IDOK, &MainDialog::OnBnClickedOk)
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
	} else {
		pListBox->EnableWindow(TRUE);
	}
}


void MainDialog::OnLbnSetfocusPartlist()
{	
	GetDlgItem(IDC_GROUP_OUTPUT)->SetWindowTextW(TEXT("Output directory : "));
	if (GetFileAttributesA(output) != FILE_ATTRIBUTE_DIRECTORY)
	{
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


void MainDialog::OnBnClickedOk()
{

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

	HANDLE hDisk, hDiskOut;
	u64 bytesToRead = nxInput.size, readAmount = 0, writeAmount = 0;
	BOOL bSuccess;
	int rc;

	// Get handle for input
	rc = nxInput.GetIOHandle(&hDisk, GENERIC_READ);
	if (rc < -1)
	{
		MessageBox(_T("Failed to get handle to input file/disk"), _T("Error"), MB_OK | MB_ICONERROR);
		return;
	} 
	// Get handle for output
	rc = nxOutput.GetIOHandle(&hDiskOut, GENERIC_WRITE);
	if (rc < -1)
	{
		MessageBox(_T("Failed to get handle to output file/disk"), _T("Error"), MB_OK | MB_ICONERROR);
		return;
	}

	CProgressCtrl* m_progCtrl = (CProgressCtrl*)GetDlgItem(IDC_PROGRESS1);
	int percent = 0;
	m_progCtrl->SetPos(percent);
	while (bSuccess = nxInput.dumpStorage(&hDisk, &hDiskOut, &readAmount, &writeAmount, bytesToRead))
	{
		int percent2 = (u64)writeAmount * 100 / (u64)bytesToRead;
		if (percent2 > percent)
		{
			percent = percent2;
			m_progCtrl->SetPos(percent);		
		}
	}
	CloseHandle(hDisk);
	CloseHandle(hDiskOut);

	if (writeAmount != bytesToRead)
	{
		char buff[256];
		sprintf_s(buff, 256, "ERROR : %I64d bytes to read but %I64d bytes written", bytesToRead, writeAmount);
		CString message(buff);
		MessageBox(message, _T("Error"), MB_OK | MB_ICONERROR);
		return;
	} else {
		char buff[256];
		sprintf_s(buff, 256, "Finished. %s written", GetReadableSize(writeAmount).c_str());
		CString message(buff);
		MessageBox(message, _T("Error"), MB_OK | MB_ICONINFORMATION);
	}
	//CDialog::OnOK();
}
