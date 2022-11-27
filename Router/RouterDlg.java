/*
 * JTable Row에 data추가하는 방법
 * routerModel.addRow(new Object[]{"123.123.123.123","255.255.0.0","12.12.12.12","G","1","1"});
 */
import javax.swing.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.awt.BorderLayout;
import java.awt.Container;
import java.awt.Font;
import java.awt.List;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.Color;

import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.border.BevelBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.border.LineBorder;

public class RouterDlg extends JFrame implements BaseLayer{

    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    public ArrayList<PcapIf> m_pAdapterList;
    
    public DefaultTableModel StaticRouterModel, ARPCacheModel, ProxyARPModel;

    private static LayerManager m_LayerMgr = new LayerManager();
    public static RoutingTable routingTable;

    public static void main(String[] args) {
    	/*
    	 * TODO:
    	 * - Layer 생성
    	 * - Layer 연결
    	 */
    	routingTable = new RoutingTable();		// Routing Table 생성
    	// Layer 추가
    	m_LayerMgr.AddLayer(new NILayer("NI1"));
		m_LayerMgr.AddLayer(new EthernetLayer("ETHERNET1"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP1"));
		m_LayerMgr.AddLayer(new IPLayer("IP1"));
		
		// 이번 과제에서는 Network Card 2개 사용하므로
		m_LayerMgr.AddLayer(new NILayer("NI2"));
		m_LayerMgr.AddLayer(new EthernetLayer("ETHERNET2"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP2"));
		m_LayerMgr.AddLayer(new IPLayer("IP2"));
		
		// Router GUI(Dialog)
		m_LayerMgr.AddLayer(new RouterDlg("GUI"));
		
		m_LayerMgr.ConnectLayers("NI1 ( *ETHERNET1 ( *IP1 ( *GUI ) ) )");
		m_LayerMgr.ConnectLayers("ETHERNET1 ( *ARP1 ( +IP1 ) ) )");
		
		m_LayerMgr.ConnectLayers("NI2 ( *ETHERNET2 ( *IP2 ( *GUI ) ) )");
		m_LayerMgr.ConnectLayers("ETHERNET2 ( *ARP2 ( +IP2 ) ) )");
		byte[] MacAddr1 = new byte[6];
		byte[] MacAddr2 = new byte[6];
		
		//자동 Setting 과정
		// 자기 자신 MAC 주소 받아오기
		// 첫 번째 네트워크로 설정
		try {
			MacAddr1 = ((NILayer)m_LayerMgr.GetLayer("NI1")).GetAdapterObject(0).getHardwareAddress();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// 두 번째 네트워크로 설정
		try {
			MacAddr2 = ((NILayer)m_LayerMgr.GetLayer("NI2")).GetAdapterObject(1).getHardwareAddress();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		((EthernetLayer)m_LayerMgr.GetLayer("ETHERNET1")).set_srcaddr(MacAddr1);
		((EthernetLayer)m_LayerMgr.GetLayer("ETHERNET2")).set_srcaddr(MacAddr2);
		System.out.println("Ethernet Layer의 MacAddr 각각 추가");
		// Routing Table에 두 IP Layer를 추가함
		routingTable.setIPLayer(((IPLayer)m_LayerMgr.GetLayer("IP1")), ((IPLayer)m_LayerMgr.GetLayer("IP2")));
		System.out.println("Routing Table에 IPLayer 저장");
		// GUI를 ARP Layer로 할당
		((ARPLayer)m_LayerMgr.GetLayer("ARP1")).SetGUI((RouterDlg)m_LayerMgr.GetLayer("GUI"));
		((ARPLayer)m_LayerMgr.GetLayer("ARP2")).SetGUI((RouterDlg)m_LayerMgr.GetLayer("GUI"));
		// 각각의 ARP Layer에 InterfaceNumber 저장
		((ARPLayer)m_LayerMgr.GetLayer("ARP1")).setInterfaceNum(0);
		((ARPLayer)m_LayerMgr.GetLayer("ARP2")).setInterfaceNum(1);

		
		
		// TODO: ARPTable class 각 ARPLayer에 할당해줘야
    	
	}

	private JPanel contentPanel;				// 전체 화면 JPanel
    private JButton btnAllDelete;				// Basic ARP All ITem Delete Button
    private JTable StaticRouterTable;
    private JTable ARPCacheTable;
    private JTable ProxyARPTable;
    private JPanel StaticRouterPane;
    private JPanel ARPCachePane;
    private JPanel ProxyPane;
    private JLabel lblNewLabel;
    private JLabel lblArpCacheTable;
    private JLabel lblProxyArpTable;
    private JScrollPane RouterScrollPane;
    private JScrollPane ARPScrollPane;
    private JScrollPane ProxyScrollPane;
    private JButton btnRouterAdd;
    private JButton btnRouterDelete;
    private JButton btnARPDelete;
    private JButton btnProxyAdd;
    private JButton btnProxyDelete;
    private JDialog addRouterDlg;
    private JDialog proxyAddDlg;



    

    /* ARP Table Dlg*/
	public RouterDlg(String pName) {
		setTitle("Static Router");
		pLayerName = pName;

		setBounds(250, 250, 1141, 551);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		contentPanel = new JPanel();
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(null);
		
		/*
		 *	Static Routing Table 시작 
		 */
		
		StaticRouterPane = new JPanel();
		StaticRouterPane.setBounds(14, 12, 615, 480);
		contentPanel.add(StaticRouterPane);
		StaticRouterPane.setLayout(null);
		
		lblNewLabel = new JLabel("Static Routing Table");
		lblNewLabel.setFont(new Font("굴림", Font.BOLD, 24));
		lblNewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		lblNewLabel.setBounds(156, 12, 293, 29);
		StaticRouterPane.add(lblNewLabel);
		
		RouterScrollPane = new JScrollPane();
		RouterScrollPane.setBounds(14, 53, 587, 364);
		StaticRouterPane.add(RouterScrollPane);
		
		StaticRouterTable = new JTable();
		StaticRouterTable.setFont(new Font("Gulim", Font.PLAIN, 15));
		StaticRouterTable.setShowVerticalLines(false);
		StaticRouterTable.setShowGrid(false);
		StaticRouterModel = new DefaultTableModel(
				new Object[][] {
				},
				new String[] {
					"Destination", "Netmask", "Gateway", "Flag", "Interface", "Metric"
				}
			);
		StaticRouterTable.setModel(StaticRouterModel);
		StaticRouterTable.getColumnModel().getColumn(0).setPreferredWidth(139);
		StaticRouterTable.getColumnModel().getColumn(1).setPreferredWidth(133);
		StaticRouterTable.getColumnModel().getColumn(2).setPreferredWidth(126);
		RouterScrollPane.setViewportView(StaticRouterTable);
		
		btnRouterAdd = new JButton("Add");
		addRouterDlg = new AddRouterDlg(this, "Add Routing Entry");
		btnRouterAdd.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(e.getSource() == btnRouterAdd) {
					addRouterDlg.setVisible(true);
				}
			}
		});
		btnRouterAdd.setBounds(174, 441, 105, 27);
		StaticRouterPane.add(btnRouterAdd);
		
		btnRouterDelete = new JButton("Delete");
		btnRouterDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedIndex = StaticRouterTable.getSelectedRow();
				if(selectedIndex != -1){
					//remove selected row from the model
					StaticRouterModel.removeRow(selectedIndex);
					// TODO: Routing Table Class에서 해당 index 삭제하는 과정
					routingTable.deleteRoutingEntry(selectedIndex);
					System.out.println("현재 Routing Table의 개수 : "+routingTable.routingTable.size());
				}
			}
		});
		btnRouterDelete.setBounds(345, 441, 105, 27);
		StaticRouterPane.add(btnRouterDelete);
		
		/*
		 * Static Routing Table 끝
		 */
		
		ARPCachePane = new JPanel();
		ARPCachePane.setBounds(643, 12, 466, 252);
		contentPanel.add(ARPCachePane);
		ARPCachePane.setLayout(null);
		
		lblArpCacheTable = new JLabel("ARP Cache Table");
		lblArpCacheTable.setHorizontalAlignment(SwingConstants.CENTER);
		lblArpCacheTable.setFont(new Font("굴림", Font.BOLD, 24));
		lblArpCacheTable.setBounds(86, 12, 293, 29);
		ARPCachePane.add(lblArpCacheTable);
		
		ARPScrollPane = new JScrollPane();
		ARPScrollPane.setBounds(14, 52, 438, 157);
		ARPCachePane.add(ARPScrollPane);
		
		ARPCacheTable = new JTable();
		ARPCacheModel = new DefaultTableModel(
				new Object[][] {
				},
				new String[] {
					"IP Address", "Ethernet Address", "Interface", "Flag"
				}
			);
		ARPCacheTable.setModel(ARPCacheModel);
		ARPScrollPane.setViewportView(ARPCacheTable);
		
		btnARPDelete = new JButton("Delete");
		btnARPDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int index = ARPCacheTable.getSelectedRow();
				if(index >= 0) {
					DeleteARP(index);
				}
			}
		});
		btnARPDelete.setBounds(181, 221, 105, 27);
		ARPCachePane.add(btnARPDelete);
		
		ProxyPane = new JPanel();
		ProxyPane.setBounds(643, 273, 466, 219);
		contentPanel.add(ProxyPane);
		ProxyPane.setLayout(null);
		
		lblProxyArpTable = new JLabel("Proxy ARP Table");
		lblProxyArpTable.setHorizontalAlignment(SwingConstants.CENTER);
		lblProxyArpTable.setFont(new Font("굴림", Font.BOLD, 24));
		lblProxyArpTable.setBounds(98, 12, 293, 29);
		ProxyPane.add(lblProxyArpTable);
		
		ProxyScrollPane = new JScrollPane();
		ProxyScrollPane.setBounds(14, 48, 438, 122);
		ProxyPane.add(ProxyScrollPane);
		
		ProxyARPTable = new JTable();
		ProxyARPModel = new DefaultTableModel(
				new Object[][] {
				},
				new String[] {
					"IP Address", "Ethernet Address", "Interface"
				}
			);
		ProxyARPTable.setModel(ProxyARPModel);
		ProxyScrollPane.setViewportView(ProxyARPTable);
		
		btnProxyAdd = new JButton("Add");
		proxyAddDlg = new ProxyAddDlg();
		btnProxyAdd.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				proxyAddDlg.setVisible(true);
			}
		});
		btnProxyAdd.setBounds(103, 180, 105, 27);
		ProxyPane.add(btnProxyAdd);
		
		btnProxyDelete = new JButton("Delete");
		btnProxyDelete.setBounds(286, 182, 105, 27);
		ProxyPane.add(btnProxyDelete);
		
		setVisible(true);
		
	
	}
	
	
	class AddRouterDlg extends JDialog {
		
		private final JPanel AddRouterPane = new JPanel();
		private JTextField DestIP;
		private JTextField NetMaskIP;
		private JTextField GatewayIP;
		
		public AddRouterDlg(JFrame frame, String title) {
			super(frame, title);
			this.setLocationRelativeTo(frame);
			setTitle("Add Routing Table");
			setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
			setBounds(100, 100, 406, 366);
			getContentPane().setLayout(new BorderLayout());
			AddRouterPane.setBorder(new EmptyBorder(5, 5, 5, 5));
			getContentPane().add(AddRouterPane, BorderLayout.CENTER);
			AddRouterPane.setLayout(null);
			
			JLabel lblDest = new JLabel("Destination");
			lblDest.setBounds(14, 43, 98, 18);
			AddRouterPane.add(lblDest);
			
			JLabel lblNetmask = new JLabel("Netmask");
			lblNetmask.setBounds(14, 86, 98, 18);
			AddRouterPane.add(lblNetmask);
			
			JLabel lblGateway = new JLabel("Gateway");
			lblGateway.setBounds(14, 125, 98, 18);
			AddRouterPane.add(lblGateway);
			
			JLabel lblFlag = new JLabel("Flag");
			lblFlag.setBounds(14, 164, 98, 18);
			AddRouterPane.add(lblFlag);
			
			JLabel lblInterface = new JLabel("Interface");
			lblInterface.setBounds(14, 210, 98, 18);
			AddRouterPane.add(lblInterface);
			
			DestIP = new JTextField();
			DestIP.setBounds(126, 40, 230, 24);
			AddRouterPane.add(DestIP);
			DestIP.setColumns(10);
			
			NetMaskIP = new JTextField();
			NetMaskIP.setColumns(10);
			NetMaskIP.setBounds(126, 83, 230, 24);
			AddRouterPane.add(NetMaskIP);
			
			GatewayIP = new JTextField();
			GatewayIP.setColumns(10);
			GatewayIP.setBounds(126, 122, 230, 24);
			AddRouterPane.add(GatewayIP);
			
			JCheckBox chckbxUp = new JCheckBox("UP");
			chckbxUp.setBounds(122, 160, 66, 27);
			AddRouterPane.add(chckbxUp);
			
			JCheckBox chckbxGateway = new JCheckBox("Gateway");
			chckbxGateway.setBounds(194, 160, 98, 27);
			AddRouterPane.add(chckbxGateway);
			
			JCheckBox chckbxHost = new JCheckBox("Host");
			chckbxHost.setBounds(298, 160, 66, 27);
			AddRouterPane.add(chckbxHost);
			
			JComboBox NICList = new JComboBox();
			NICList.setBounds(126, 207, 109, 24);
			SetCombobox(NICList);
			AddRouterPane.add(NICList);
			
			JButton btnAdd = new JButton("Add");
			btnAdd.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					byte[] dstIP = StringToIP(DestIP.getText());
					
					byte[] netmask = StringToIP(NetMaskIP.getText());
					byte[] gateway = new byte[4];
					if(!GatewayIP.getText().isEmpty()){
						gateway = StringToIP(GatewayIP.getText());
					}
					String gate = "";
					if(GatewayIP.getText().isEmpty()) gate = "*";
					else gate = GatewayIP.getText();
					String flag = getFlag(chckbxUp.isSelected(),chckbxGateway.isSelected(), chckbxHost.isSelected());
					int index = NICList.getSelectedIndex();
					String inter = "Port "+index;
					int metric = getMetric();
					//routingTable 클래스에 Entry 추가
					routingTable.addRoutingEntry(dstIP, netmask, gateway, flag, inter, metric);
					//TODO: GUI의 라우팅 테이블에 업데이트
					StaticRouterModel.addRow(new Object[]{DestIP.getText(),NetMaskIP.getText(), gate, flag, inter, Integer.toString(metric)});
					System.out.println("현재 Routing Table의 개수 : "+routingTable.routingTable.size());

				}
			});
			btnAdd.setBounds(83, 271, 84, 27);
			AddRouterPane.add(btnAdd);
			
			JButton btnCancel = new JButton("Cancel");
			btnCancel.addActionListener(new ActionListener(){
				public void actionPerformed(ActionEvent e) {
					dispose();
				}
			});
			btnCancel.setBounds(208, 271, 84, 27);
			AddRouterPane.add(btnCancel);
		}
		
		
		private int getMetric(){
			int output = 1;
			//TODO : Metric....반환....<미완료>
			return output;
		}
		
		private String getFlag(boolean up, boolean gateway, boolean host){
			String output = "";
			// TODO : Flag 확인해서 String으로 변환해서 return<완료>
			if(up) {
				output += "U";
			}
			if(gateway){
				output += "G";
			}
			if(host){
				output += "H";
			}
			
			return output;
		}
		
		private byte[] StringToByte(String input){
			byte[] output = new byte[4];		//IP 주소는 4byte
			String[] tmp = input.split("\\.");
			for(int i = 0 ; i < tmp.length; i++){
				output[i] = Int2Byte(Integer.parseInt(tmp[i]));
			}
			return output;
		}
		
		private byte Int2Byte(int src){
			byte result = 0;
			// TODO : IP주소 숫자를 byte 배열에 넣기 위해서 바꾸는 과정이 필요함
			return result;
		}
		
		private void SetCombobox(JComboBox NICList) {
			java.util.List<PcapIf> m_pAdapterList = new ArrayList<PcapIf>();
			StringBuilder errbuf = new StringBuilder();

			int r = Pcap.findAllDevs(m_pAdapterList, errbuf);
			if (r == Pcap.NOT_OK || m_pAdapterList.isEmpty()) {
				System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
				return;
			}
			for (int i = 0; i < m_pAdapterList.size(); i++)
				NICList.addItem("Port "+i);
		}
		
		
	}
	
	public class ProxyAddDlg extends JDialog {

		private final JPanel ProxyAddPanel = new JPanel();
		private JTextField ProxyIPAddress;
		private JTextField ProxyEthernetAddress;


		/**
		 * Create the dialog.
		 */
		public ProxyAddDlg() {
			setTitle("Add Proxy ARP");
			setBounds(100, 100, 406, 300);
			setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
			getContentPane().setLayout(new BorderLayout());
			ProxyAddPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
			getContentPane().add(ProxyAddPanel, BorderLayout.CENTER);
			ProxyAddPanel.setLayout(null);
			{
				JLabel lblIpAddress = new JLabel("IP Address");
				lblIpAddress.setBounds(27, 31, 130, 18);
				ProxyAddPanel.add(lblIpAddress);
			}
			{
				JLabel lblEthernetAddress = new JLabel("Ethernet Address");
				lblEthernetAddress.setBounds(27, 89, 130, 18);
				ProxyAddPanel.add(lblEthernetAddress);
			}
			{
				JLabel lblInterface = new JLabel("Interface");
				lblInterface.setBounds(27, 147, 130, 18);
				ProxyAddPanel.add(lblInterface);
			}
			{
				JButton btnProxyAdd = new JButton("Add");
				btnProxyAdd.setBounds(76, 203, 105, 27);
				ProxyAddPanel.add(btnProxyAdd);
			}
			{
				JButton btnProxyCancel = new JButton("Cancel");
				btnProxyCancel.setBounds(208, 203, 105, 27);
				ProxyAddPanel.add(btnProxyCancel);
			}
			{
				ProxyIPAddress = new JTextField();
				ProxyIPAddress.setBounds(171, 28, 194, 24);
				ProxyAddPanel.add(ProxyIPAddress);
				ProxyIPAddress.setColumns(10);
			}
			{
				ProxyEthernetAddress = new JTextField();
				ProxyEthernetAddress.setColumns(10);
				ProxyEthernetAddress.setBounds(171, 86, 194, 24);
				ProxyAddPanel.add(ProxyEthernetAddress);
			}
			{
				JComboBox ProxyInterface = new JComboBox();
				ProxyInterface.setBounds(173, 144, 194, 24);
				ProxyAddPanel.add(ProxyInterface);
			}
		}

	}

	// GetArpTable : ARPLayer의 ARPCacheTable을 읽어오는 함수
	public boolean GetArpTable() {
		// RouterDlg의 ARPCacheTable 초기화
		for(int i = 0; i < ARPCacheModel.getRowCount(); i++) {
			ARPCacheModel.removeRow(i);
		}
		Iterator<ARPLayer._ARP_Cache> iter = ARPLayer.ArpCacheTable.iterator();
		while(iter.hasNext()) {
			ARPLayer._ARP_Cache arpCache = iter.next();
			byte[] ipAddr = arpCache.getIpAddr();
			byte[] macAddr = arpCache.getMacAddr();
			String status = arpCache.status == true ? "Complete" : "Incomplete";	//status에 따라 다르게 나타나도록
			// InterfaceName
			String interfaceName = "Port " +arpCache.getInterNum();
			String strMacAddr = "";
			String strIPAddr = ipToString(ipAddr);
			
			// MAC 주소 알면 MAC 주소로, 모르면 ????????로 나타냄
			strMacAddr = arpCache.status == true ? macToString(macAddr) : "?????????????";
			ARPCacheModel.addRow(new Object[]{strIPAddr,strMacAddr, interfaceName, status});
			System.out.println("Table 갯수 : " + ARPLayer.ArpCacheTable.size());
		}
		return true;
	}
	// DeleteARP
	public boolean DeleteARP(int index){
		// ARP Layer에서 해당 index의 ARP Cache를 제거
		ARPLayer.ArpCacheTable.remove(index);
		// GUI Update
		ARPCacheModel.removeRow(index);
		return true;
	}
	// byte[]의 IP주소를 String으로 반환(000.000.000.000)의 형태
	public String ipToString(byte[] ipAddr) {
		String ipStr = new String();
		for (int i = 0 ; i < 4; i++) {
			// 중간에는 .으로 구분함
			if(i != 3) {
				ipStr += ipAddr[i] & 0xFF;
				ipStr += ".";
			}
			else {
				ipStr += ipAddr[i] & 0xFF;
			}
		}
		return ipStr;
	}
	// String의 IP주소를 byte[]로 변환
	public byte[] StringToIP(String ipAddr){
		byte[] buf = new byte[4];
		String[] temp = ipAddr.split("\\.");
		for(int i = 0; i < 4; i++){
			buf[i] = (byte)Integer.parseInt(temp[i]);
		}
		
		return buf;
	}
	
	// byte[]의 MAC 주소를 String으로 변환(FF:FF:FF:FF:FF:FF)의 형태
	public String macToString(byte[] macAddr) {
		String macStr = "";
		for(int i = 0 ; i < 6; i++){
			macStr += String.format("%02X", macAddr[i] & 0xFF).toUpperCase();
			//macStr += Integer.toHexString(macAddr[i] & 0xFF).toUpperCase();
			if(i != 5) {
				macStr += ":";
			}

		}
		return macStr;
	}
	// String MAC 주소를 byte[]로 변환
	public byte[] StringToMAC(String macAddr){
		byte[] buf = new byte[6];
		String[] temp = macAddr.split(":");
		for(int i = 0 ; i < 6 ; i++){
			int hex = Integer.parseUnsignedInt(temp[i], 16);
			buf[i] = (byte)hex;
		}
		return buf;
	}

	
	// Layer 관련 함수
    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        // TODO Auto-generated method stub
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        // TODO Auto-generated method stub
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
        // nUpperLayerCount++;
    }

    @Override
    public String GetLayerName() {
        // TODO Auto-generated method stub
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer() {
        // TODO Auto-generated method stub
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        // TODO Auto-generated method stub
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);

    }
}


