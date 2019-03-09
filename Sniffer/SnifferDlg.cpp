
// SnifferDlg.cpp: 实现文件
//

#include "stdafx.h"
#include "Sniffer.h"
#include "SnifferDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

UINT WinpcapThreadFun(LPVOID lpParam);
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();
	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CSnifferDlg 对话框



CSnifferDlg::CSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

//初始化winpcap
int CSnifferDlg::InitWinpcap()
{
	devNum = 0;
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
		return -1;
	for (dev = alldevs; dev != NULL; dev = dev->next)
		devNum++;
	return 0;
}

int CSnifferDlg::StartWinpcap()
{
	int devIndex, filterIndex;
	u_long netmask;
	struct bpf_program fcode;

	InitWinpcap();
	devIndex = m_comboBoxDevice.GetCurSel();
	filterIndex = m_comboBoxRule.GetCurSel();
	if (devIndex == 0 || devIndex == CB_ERR)
	{
		MessageBox(_T("请选择一个网卡"));
		return -1;
	}
	if (filterIndex == CB_ERR)
	{
		MessageBox(_T("过滤器选择错误"));
		return -1;
	}
	dev = alldevs;
	for (int i = 0; i < devIndex - 1; i++)
		dev = dev->next;

	//打开网卡
	if ((adhandle = pcap_open(dev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		MessageBox(_T("无法打开接口：" + CString(dev->description)));
		pcap_freealldevs(alldevs);
		return -1;
	}

	//检查是否是以太网
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		MessageBox(_T("非以太网的网络!"));
		pcap_freealldevs(alldevs);
		return -1;
	}

	//获取网卡掩码
	if (dev->addresses != NULL)
		netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	//编译过滤器
	if (filterIndex == 0)
	{
		char filter[] = "";
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldevs);
			return -1;
		}
	}
	else
	{
		CString str;
		char* filter;
		int len;
		m_comboBoxRule.GetLBText(filterIndex, str);
		len = str.GetLength() + 1;
		filter = (char*)malloc(len);
		for (int i = 0; i < len; i++)
		{
			filter[i] = str.GetAt(i);
		}
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldevs);
			return -1;
		}
	}

	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		MessageBox(_T("设置过滤器错误"));
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置数据包存储路径
	CFileFind file;
	char thistime[30];
	struct tm *ltime;
	memset(filepath, 0, 512);
	memset(filename, 0, 64);

	if (!file.FindFile(_T("SavedData")))
	{
		CreateDirectory(_T("SavedData"), NULL);
	}

	time_t nowtime;
	time(&nowtime);
	ltime = localtime(&nowtime);
	strftime(thistime, sizeof(thistime), "%Y%m%d %H%M%S", ltime);
	strcpy(filepath, "SavedData\\");
	strcat(filename, thistime);
	strcat(filename, ".txt");

	strcat(filepath, filename);
	dumpfile = pcap_dump_open(adhandle, filepath);
	if (dumpfile == NULL)
	{
		MessageBox(_T("文件创建错误！"));
		return -1;
	}
	pcap_freealldevs(alldevs);

	//创建一个工作者线程
	winpcapThread = AfxBeginThread(WinpcapThreadFun, this);
	if (winpcapThread == NULL)
	{
		int code = GetLastError();
		CString str;
		str.Format(_T("创建线程错误，代码为%d."), code);
		MessageBox(str);
		return -1;
	}
	threadFlag = 1;
	return 1;
}

int CSnifferDlg::UpdateEdit(int index)
{
	POSITION localpos, netpos;
	localpos =m_pktdataList.FindIndex(index);
	netpos = m_netpktList.FindIndex(index);

	struct pktdata* local_data = (struct pktdata*)(m_pktdataList.GetAt(localpos));
	u_char * net_data = (u_char*)(m_netpktList.GetAt(netpos));

	CString buf;
	print_packet_hex(net_data, local_data->len, &buf);

	this->m_edit.SetWindowText(buf);
	return 1;
}

int CSnifferDlg::UpdateTree(int index)
{
	POSITION localpos;
	CString str;
	int i;

	this->m_treeCtrl.DeleteAllItems();

	localpos = m_pktdataList.FindIndex(index);
	struct pktdata* local_data = (struct pktdata*)(m_pktdataList.GetAt(localpos));

	HTREEITEM root = m_treeCtrl.GetRootItem();
	str.Format(_T("接收到的第%d个数据包"), index + 1);
	HTREEITEM data = m_treeCtrl.InsertItem(str, root);

	/*处理帧数据*/
	HTREEITEM frame = m_treeCtrl.InsertItem(_T("链路层数据"), data);
	//源MAC
	str.Format(_T("源MAC："));
	for (i = 0; i < 6; i++)
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), local_data->ethh->src[i]);
		else
			str.AppendFormat(_T("%02x"), local_data->ethh->src[i]);
	}
	this->m_treeCtrl.InsertItem(str, frame);
	//目的MAC
	str.Format(_T("目的MAC："));
	for (i = 0; i < 6; i++)
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), local_data->ethh->dest[i]);
		else
			str.AppendFormat(_T("%02x"), local_data->ethh->dest[i]);
	}
	m_treeCtrl.InsertItem(str, frame);
	//类型
	str.Format(_T("类型：0x%02x"), local_data->ethh->type);
	this->m_treeCtrl.InsertItem(str, frame);

	/*处理IP、ARP数据包*/
	if (0x0806 == local_data->ethh->type)//ARP
	{
		HTREEITEM arp = m_treeCtrl.InsertItem(_T("ARP协议头"), data);
		str.Format(_T("硬件类型：%d"), local_data->arph->ar_hrd);
		m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("协议类型：0x%02x"), local_data->arph->ar_pro);
		m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("硬件地址长度：%d"), local_data->arph->ar_hln);
		m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("协议地址长度：%d"), local_data->arph->ar_pln);
		m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("操作码：%d"), local_data->arph->ar_op);
		m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("发送方MAC："));
		for (i = 0; i < 6; i++)
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), local_data->arph->ar_srcmac[i]);
			else
				str.AppendFormat(_T("%02x"), local_data->arph->ar_srcmac[i]);
		}
		m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("发送方IP："), local_data->arph->ar_hln);
		for (i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), local_data->arph->ar_srcip[i]);
			else
				str.AppendFormat(_T("%d"), local_data->arph->ar_srcip[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("接收方MAC："), local_data->arph->ar_hln);
		for (i = 0; i < 6; i++)
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), local_data->arph->ar_destmac[i]);
			else
				str.AppendFormat(_T("%02x"), local_data->arph->ar_destmac[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("接收方IP："), local_data->arph->ar_hln);
		for (i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), local_data->arph->ar_destip[i]);
			else
				str.AppendFormat(_T("%d"), local_data->arph->ar_destip[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

	}
	else if (0x0800 == local_data->ethh->type) {//IP

		HTREEITEM ip = this->m_treeCtrl.InsertItem(_T("IP协议头"), data);

		str.Format(_T("版本：%d"), local_data->iph->version);
		m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("IP头长：%d"), local_data->iph->ihl);
		m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("服务类型：%d"), local_data->iph->tos);
		m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("总长度：%d"), local_data->iph->tlen);
		m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("标识：0x%02x"), local_data->iph->id);
		m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("段偏移：%d"), local_data->iph->frag_off);
		m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("生存期：%d"), local_data->iph->ttl);
		m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("协议：%d"), local_data->iph->proto);
		m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("头部校验和：0x%02x"), local_data->iph->check);
		m_treeCtrl.InsertItem(str, ip);

		str.Format(_T("源IP："));
		struct in_addr in;
		in.S_un.S_addr = local_data->iph->saddr;
		str.AppendFormat(CString(inet_ntoa(in)));
		m_treeCtrl.InsertItem(str, ip);

		str.Format(_T("目的IP："));
		in.S_un.S_addr = local_data->iph->daddr;
		str.AppendFormat(CString(inet_ntoa(in)));
		m_treeCtrl.InsertItem(str, ip);

		/*处理传输层ICMP、UDP、TCP*/
		if (1 == local_data->iph->proto)//ICMP
		{
			HTREEITEM icmp = m_treeCtrl.InsertItem(_T("ICMP协议头"), data);

			str.Format(_T("类型:%d"), local_data->icmph->type);
			m_treeCtrl.InsertItem(str, icmp);
			str.Format(_T("代码:%d"), local_data->icmph->code);
			m_treeCtrl.InsertItem(str, icmp);
			str.Format(_T("序号:%d"), local_data->icmph->seq);
			m_treeCtrl.InsertItem(str, icmp);
			str.Format(_T("校验和:%d"), local_data->icmph->chksum);
			m_treeCtrl.InsertItem(str, icmp);

		}
		else if (6 == local_data->iph->proto) {//TCP

			HTREEITEM tcp = m_treeCtrl.InsertItem(_T("TCP协议头"), data);

			str.Format(_T("  源端口:%d"), local_data->tcph->sport);
			m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), local_data->tcph->dport);
			m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%02x"), local_data->tcph->seq);
			m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  确认号:%d"), local_data->tcph->ack_seq);
			m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  头部长度:%d"), local_data->tcph->doff);

			HTREEITEM flag = m_treeCtrl.InsertItem(_T(" +标志位"), tcp);

			str.Format(_T("cwr %d"), local_data->tcph->cwr);
			m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ece %d"), local_data->tcph->ece);
			m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("urg %d"), local_data->tcph->urg);
			m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ack %d"), local_data->tcph->ack);
			m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("psh %d"), local_data->tcph->psh);
			m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("rst %d"), local_data->tcph->rst);
			m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("syn %d"), local_data->tcph->syn);
			m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("fin %d"), local_data->tcph->fin);
			m_treeCtrl.InsertItem(str, flag);

			str.Format(_T("  紧急指针:%d"), local_data->tcph->urg_ptr);
			m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  校验和:0x%02x"), local_data->tcph->check);
			m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  选项:%d"), local_data->tcph->opt);
			m_treeCtrl.InsertItem(str, tcp);
		}
		else if (17 == local_data->iph->proto) {				//UDP
			HTREEITEM udp = m_treeCtrl.InsertItem(_T("UDP协议头"), data);

			str.Format(_T("源端口:%d"), local_data->udph->sport);
			m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), local_data->udph->dport);
			m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), local_data->udph->len);
			m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), local_data->udph->check);
			m_treeCtrl.InsertItem(str, udp);
		}
	}
	
	return 1;
}

UINT WinpcapThreadFun(LPVOID lpParam)
{
	CSnifferDlg *dlg = (CSnifferDlg*)lpParam;

	int res, itemNum;
	struct tm *ltime;
	CString timestr, buf, srcMac, destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *header;//数据包头
	const u_char *pkt_data = NULL;//数据包body
	u_char *ppkt_data;

	if (dlg->winpcapThread == NULL)
	{
		return -1;
	}
	while ((res = pcap_next_ex(dlg->adhandle, &header, &pkt_data)) >= 0 && dlg->threadFlag == 1)
	{
		if (res == 0)
			continue;

		struct pktdata *data = (struct pktdata*)malloc(sizeof(struct pktdata));
		memset(data, 0, sizeof(struct pktdata));

		if (data == NULL)
		{
			MessageBox(NULL, _T("空间已满，无法接收新的数据包"), _T("Error"), MB_OK);
			return -1;
		}

		//判断是否是符合要求的数据包
		if (analyze_frame(pkt_data, data) < 0)
			continue;

		//数据包保存到文件中
		if (dlg->dumpfile != NULL)
		{
			pcap_dump((u_char*)dlg->dumpfile, header, pkt_data);
		}

		//将报文结构体放入一个链表
		dlg->m_pktdataList.AddTail(data);
		//将二进制报文存入链表
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data, pkt_data, header->len);
		dlg->m_netpktList.AddTail(ppkt_data);

		data->len = header->len;
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year + 1900;
		data->time[1] = ltime->tm_mon + 1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

		//在ListControl插入一行
		buf.Format(_T("%d"), dlg->packetNum);
		itemNum = dlg->m_listCtrl.InsertItem(dlg->packetNum, buf);

		//时间
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
			data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
		dlg->m_listCtrl.SetItemText(itemNum, 1, timestr);

		//报文长度
		buf.Empty();
		buf.Format(_T("%d"), data->len);
		dlg->m_listCtrl.SetItemText(itemNum, 2, buf);

		//源MAC
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
			data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
		dlg->m_listCtrl.SetItemText(itemNum, 3, buf);

		//目的MAC
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
			data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
		dlg->m_listCtrl.SetItemText(itemNum, 4, buf);

		//协议
		dlg->m_listCtrl.SetItemText(itemNum, 5, CString(data->pktType));

		//源IP
		buf.Empty();
		if (data->ethh->type == 0x0806)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_srcip[0],
				data->arph->ar_srcip[1], data->arph->ar_srcip[2], data->arph->ar_srcip[3]);
		}
		else if (data->ethh->type == 0x0800) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}
		dlg->m_listCtrl.SetItemText(itemNum, 6, buf);

		//目的IP
		buf.Empty();
		if (data->ethh->type == 0x0806)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_destip[0],
				data->arph->ar_destip[1], data->arph->ar_destip[2], data->arph->ar_destip[3]);
		}
		else if (data->ethh->type == 0x0800) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}
		dlg->m_listCtrl.SetItemText(itemNum, 7, buf);

		dlg->packetNum++;
	}
	return 0;
}

void CSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_listCtrl);
	DDX_Control(pDX, IDC_COMBO1, m_comboBoxDevice);
	DDX_Control(pDX, IDC_COMBO2, m_comboBoxRule);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrl);
	DDX_Control(pDX, IDC_BUTTON1, m_buttonStart);
	DDX_Control(pDX, IDC_BUTTON2, m_buttonStop);
	DDX_Control(pDX, IDC_BUTTON3, m_buttonSave);
	DDX_Control(pDX, IDC_EDIT1, m_edit);
}

BEGIN_MESSAGE_MAP(CSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CSnifferDlg::OnBnClickedButton1)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CSnifferDlg::OnLvnItemchangedList1)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &CSnifferDlg::OnNMCustomdrawList1)
	ON_BN_CLICKED(IDC_BUTTON2, &CSnifferDlg::OnBnClickedButton2)
END_MESSAGE_MAP()


// CSnifferDlg 消息处理程序

BOOL CSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	m_comboBoxDevice.AddString(_T("请选择网卡"));
	m_comboBoxRule.AddString(_T("请选择过滤规则"));
	if (InitWinpcap() < 0)
		return FALSE;

	//初始化网卡列表
	for (dev = alldevs; dev != NULL; dev = dev->next)
	{
		if (dev->description)
			m_comboBoxDevice.AddString(CString(dev->description));
	}

	//初始化过滤规则列表
	m_comboBoxRule.AddString(_T("tcp"));
	m_comboBoxRule.AddString(_T("udp"));
	m_comboBoxRule.AddString(_T("ip"));
	m_comboBoxRule.AddString(_T("icmp"));
	m_comboBoxRule.AddString(_T("arp"));

	m_comboBoxDevice.SetCurSel(0);
	m_comboBoxRule.SetCurSel(0);

	//初始化列表
	m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_listCtrl.InsertColumn(0, _T("编号"), 3, 50);
	m_listCtrl.InsertColumn(1, _T("时间"), 3, 130);
	m_listCtrl.InsertColumn(2, _T("长度"), 3, 80);
	m_listCtrl.InsertColumn(3, _T("源MAC地址"), 3, 140);
	m_listCtrl.InsertColumn(4, _T("目的MAC地址"), 3, 140);
	m_listCtrl.InsertColumn(5, _T("协议"), 3, 70);
	m_listCtrl.InsertColumn(6, _T("源IP地址"), 3, 150);
	m_listCtrl.InsertColumn(7, _T("目的IP地址"), 3, 150);

	m_buttonStop.EnableWindow(FALSE);
	m_buttonSave.EnableWindow(FALSE);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//开始按钮
void CSnifferDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
	packetNum = 1;

	if (StartWinpcap() < 0)
		return;
	m_listCtrl.DeleteAllItems();
	m_treeCtrl.DeleteAllItems();
	m_buttonStart.EnableWindow(FALSE);
	m_buttonStop.EnableWindow(TRUE);
	m_buttonSave.EnableWindow(FALSE);
}

//列表选中事件
void CSnifferDlg::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	int index;
	index = m_listCtrl.GetHotItem();
	if (index > m_pktdataList.GetCount() - 1)
		return;
	UpdateTree(index);
	UpdateEdit(index);
}

//修改ListControl背景颜色
void CSnifferDlg::OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = CDRF_DODEFAULT;

	if (pLVCD->nmcd.dwDrawStage == CDDS_PREPAINT)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (pLVCD->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
	{
		*pResult = CDRF_NOTIFYSUBITEMDRAW;
	}
	else if (pLVCD->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM))
	{
		COLORREF clrNewTextBk;
		char buf[10];
		memset(buf, 0, 10);

		POSITION pos = m_pktdataList.FindIndex(pLVCD->nmcd.dwItemSpec);

		struct pktdata * data = (struct pktdata *)m_pktdataList.GetAt(pos);
		strcpy(buf, data->pktType);

		if (strcmp(buf, "UDP") == 0)
			clrNewTextBk = RGB(194, 195, 252);
		else if (strcmp(buf, "TCP") == 0)
			clrNewTextBk = RGB(230, 230, 230);
		else if (strcmp(buf, "ARP") == 0)
			clrNewTextBk = RGB(226, 238, 227);
		else if (strcmp(buf, "ICMP") == 0)
			clrNewTextBk = RGB(49, 164, 238);
		else if (strcmp(buf, "HTTP") == 0)
			clrNewTextBk = RGB(238, 232, 180);
		else
			clrNewTextBk = RGB(255, 255, 255);
		pLVCD->clrTextBk = clrNewTextBk;

		*pResult = CDRF_DODEFAULT;
	}
}

//结束按钮
void CSnifferDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	if (winpcapThread == NULL)
		return;
	threadFlag = 0;
	m_buttonStart.EnableWindow(TRUE);
	m_buttonStop.EnableWindow(FALSE);
	m_buttonSave.EnableWindow(TRUE);
}
