#pragma once
#include "resource.h"
#include "NxStorage.h"
#include "utils.h"

// MainDialog dialog

class MainDialog : public CDialog
{
	DECLARE_DYNAMIC(MainDialog)

public:
	MainDialog(const char* arg_input = NULL, const char* arg_output = NULL, CWnd* pParent = NULL);   // standard constructor
	virtual ~MainDialog();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MAINDIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnEnChangeInput();

	char* input;
	char* output;
	afx_msg void OnBnClickedDumpAll();
	afx_msg void OnLbnSetfocusPartlist();
	afx_msg void OnEnChangeOutput();
	afx_msg void OnBnClickedOk();
};
