#pragma once
#include "resource.h"
#include <stdlib.h>

#define WM_MY_MESSAGE (WM_APP+1000)
#define WM_MY_MESSAG2 (WM_APP+1001)

// ProgressDialog dialog

class ProgressDialog : public CDialog
{
	DECLARE_DYNAMIC(ProgressDialog)

public:
	ProgressDialog(CWnd* pParent = NULL);   // standard constructor
	virtual ~ProgressDialog();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_PROGRESSDIALOG };
#endif

	CString	m_szMessage;

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual LRESULT OnUpdateString(WPARAM wpD, LPARAM lpD);
	virtual LRESULT OnUpdatePercent(WPARAM wpD, LPARAM lpD);
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedCancel();
};
