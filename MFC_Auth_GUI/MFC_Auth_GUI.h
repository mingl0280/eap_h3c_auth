
// MFC_Auth_GUI.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CMFC_Auth_GUIApp:
// �йش����ʵ�֣������ MFC_Auth_GUI.cpp
//

class CMFC_Auth_GUIApp : public CWinApp
{
public:
	CMFC_Auth_GUIApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CMFC_Auth_GUIApp theApp;