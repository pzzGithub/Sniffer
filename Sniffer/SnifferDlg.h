
// SnifferDlg.h: 头文件
//

#pragma once
#include"pcap.h"

// CSnifferDlg 对话框
class CSnifferDlg : public CDialogEx
{
// 构造
public:
	CSnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数
	int InitWinpcap();
// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnCbnSelchangeCombo1();
	CListCtrl m_listCtrl;
	CComboBox m_comboBoxDevice;
	CComboBox m_comboBoxRule;
	CTreeCtrl m_treeCtrl;
	CButton m_buttonStart;
	CButton m_buttonStop;

	pcap_if_t *alldevs;
	pcap_if_t *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	int devNum;
};
