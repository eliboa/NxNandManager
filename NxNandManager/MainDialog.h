#pragma once
#include "resource.h"

// MainDialog dialog

class MainDialog : public CDialog
{
	DECLARE_DYNAMIC(MainDialog)

public:
	MainDialog(CWnd* pParent = NULL);   // standard constructor
	virtual ~MainDialog();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MAINDIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnEnChangeInput();
};
