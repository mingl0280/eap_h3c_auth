
// MFC_Auth_GUIDlg.h : ͷ�ļ�
//

#pragma once


// CMFC_Auth_GUIDlg �Ի���
class CMFC_Auth_GUIDlg : public CDialogEx
{
// ����
public:
	CMFC_Auth_GUIDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_MFC_AUTH_GUI_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
};
