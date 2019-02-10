#pragma once
#include "ProgressDialog.h"

/////////////////////////////////////////////////////////////////////////////
// CUIThread thread
#define WM_INFORM_CLOSE		WM_USER + 100

class CUIThread : public CWinThread
{
	DECLARE_DYNCREATE(CUIThread)

protected:
	

// Attributes
public:

// Operations
public:
	void SetParent(CWnd* pParent);
	CString m_szMessage;
	CUIThread();           // protected constructor used by dynamic creation
	virtual ~CUIThread();

	//	Setting the message to be displayed in the dialog box.
	void SetString(CString& szString);
	void SetString(LPCTSTR szString);
	void SetPercent(CString& szString);
	void SetPercent(LPCTSTR szString);
	//	Retrieve the status if the interface thread is still running.
	BOOL IsRunning();
	//	The main loop for running the interface thread. In this case, it displays a modal dialog box.
	int Run();
	//	Kill the interface thread by posting a message to the dialog box object.
	void Kill();

private:
	CWnd* m_pParent;
	// Indicates if we want to kill the thread.
	BOOL	m_bKill;
	BOOL	m_bRunning;
	// Object for the displaying the message dialog box.
	ProgressDialog m_Dlg;


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CUIThread)
	public:
	virtual BOOL InitInstance();
	virtual int ExitInstance();
	//}}AFX_VIRTUAL

// Implementation
protected:
	

	// Generated message map functions
	//{{AFX_MSG(CUIThread)
		// NOTE - the ClassWizard will add and remove member functions here.
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////