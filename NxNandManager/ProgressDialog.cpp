// ProgressDialog.cpp : implementation file
//

#include "stdafx.h"
#include "ProgressDialog.h"
#include "afxdialogex.h"


// ProgressDialog dialog

IMPLEMENT_DYNAMIC(ProgressDialog, CDialog)

ProgressDialog::ProgressDialog(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_PROGRESSDIALOG, pParent)
{
	m_szMessage = _T("");
	
}

ProgressDialog::~ProgressDialog()
{
}

void ProgressDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_STATIC_MESSAGE, m_szMessage);
}



BEGIN_MESSAGE_MAP(ProgressDialog, CDialog)
	ON_WM_SYSCOMMAND()
	ON_MESSAGE(WM_MY_MESSAGE, OnUpdateString)
	ON_MESSAGE(WM_MY_MESSAG2, OnUpdatePercent)
	ON_BN_CLICKED(IDCANCEL, &ProgressDialog::OnBnClickedCancel)
END_MESSAGE_MAP()

BOOL ProgressDialog::OnInitDialog()
{
	CDialog::OnInitDialog();
	GetDlgItem(IDC_PROGRESSCTL)->ShowWindow(SW_HIDE);

	return TRUE;
}

LRESULT ProgressDialog::OnUpdatePercent(WPARAM wpD, LPARAM lpD)
{
	CString *pwpD = (CString *)wpD;
	CT2A message(*pwpD);
	int percent = atoi(message);	
	CProgressCtrl* m_progCtrl = (CProgressCtrl*)GetDlgItem(IDC_PROGRESSCTL);
	m_progCtrl->ShowWindow(SW_SHOW);
	//this->UpdateWindow();
	m_progCtrl->SetPos(percent);
	UpdateData(FALSE);
	return LRESULT();
}

LRESULT ProgressDialog::OnUpdateString(WPARAM wpD, LPARAM lpD)
{
	CString *pwpD = (CString *)wpD;
	m_szMessage = *pwpD;
	UpdateData(FALSE);
	return LRESULT();
}

// ProgressDialog message handlers

void ProgressDialog::OnBnClickedCancel()
{
	// TODO: Add your control notification handler code here
	CDialog::OnCancel();
}
