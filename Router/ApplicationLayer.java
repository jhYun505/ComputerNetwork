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

public class ApplicationLayer extends JFrame implements BaseLayer{

    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    public ArrayList<PcapIf> m_pAdapterList;
    public byte[] MY_IP;
    public byte[] MY_MAC;

    String path;

    private static LayerManager m_LayerMgr = new LayerManager();
    int selected_index;
    
    public static void main(String[] args) {
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new EthernetLayer("ETHERNET"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP"));
		m_LayerMgr.AddLayer(new IPLayer("IP"));
		m_LayerMgr.AddLayer(new TCPLayer("TCP"));
		m_LayerMgr.AddLayer(new ApplicationLayer("GUI"));

		
		m_LayerMgr.ConnectLayers(" NI ( *ETHERNET ( +IP ( *TCP ( *GUI ) ) ) ) ");
		// ARP Layer - IP Layer 단방향 연결
		m_LayerMgr.GetLayer("IP").SetUnderLayer(m_LayerMgr.GetLayer("ARP"));
		// ARP Layer - Ethernet Layer 양방향 연결
		m_LayerMgr.GetLayer("ETHERNET").SetUpperUnderLayer(m_LayerMgr.GetLayer("ARP"));
		((ARPLayer)m_LayerMgr.GetLayer("ARP")).SetGUI(((ApplicationLayer)m_LayerMgr.GetLayer("GUI")));//Update를 위해 변수로 전달함.

	}

	private JPanel contentPanel;				// 전체 화면 JPanel
    
    private JPanel BasicPanel;					// Basic ARP용 JPanel
    private List ARPCacheList;					// ARP Cache Table Display
    private JButton btnItemDelete;				// Basic ARP Selected Item Delete Button
    private JButton btnAllDelete;				// Basic ARP All ITem Delete Button
    private JTextField IPAddrInput;				// Basic ARP IP Input Field
    private JButton btnBasicSend;				// Basic ARP IP Send Button
    
    private JPanel ProxyPane;					// Proxy ARP용 Panel
    private List ProxyEntryList;				// Proxy Entry Display
    private JButton btnProxyAdd;				// Proxy Entry Add Button
    private JButton btnProxyDelete;				// Proxy Entry Delete Button
    
    private JPanel GratuitousPane;				// Gratuitous ARP용 Panel
    private JTextField GARPAddrInput;			// Gratuitous ARP MAC Address Input Field
    private JButton btnGratSend;				// Gratuitous ARP Mac Address Send Button
    private JLabel lblDevice;
    private JLabel lblIpAddress;
    private JLabel lblMacAddress;
    private JTextField DeviceName;
    private JTextField ProxyIPAddr;
    private JTextField ProxyMACAddr;
    private JTextField srcMacAddress;
    private JTextField srcIPAddress;
    
    private JComboBox NICList;

    

    /* ARP Table Dlg*/
	public ApplicationLayer(String pName) {
		setTitle("TestARP");
		pLayerName = pName;

		setBounds(250, 250, 1115, 525);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		contentPanel = new JPanel();
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(null);
		
		BasicPanel = new JPanel();
		BasicPanel.setBorder(new TitledBorder(null, "ARP Cache", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		BasicPanel.setBounds(14, 29, 351, 429);
		contentPanel.add(BasicPanel);
		BasicPanel.setLayout(null);
		
		ARPCacheList = new List();
		//ARPCacheList.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		ARPCacheList.setBounds(13, 23, 324, 269);
		BasicPanel.add(ARPCacheList);
		GetArpTable();
		
		btnItemDelete = new JButton("Item Delete");
		btnItemDelete.setBounds(32, 298, 127, 42);
		BasicPanel.add(btnItemDelete);
		// ARP Cache Entry 삭제 버튼(선택한 것만 지운다)
		btnItemDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int index = ARPCacheList.getSelectedIndex();
				if(index >= 0) {
					DeleteARP(index);
				}
			}
		});
		
		btnAllDelete = new JButton("All Detete");
		btnAllDelete.setBounds(196, 298, 127, 42);
		btnAllDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(e.getSource() == btnAllDelete){
					ARPLayer.ArpCacheTable.clear();
					GetArpTable();
				}
			}
		});
		BasicPanel.add(btnAllDelete);
		
		JLabel IPAddrLabel = new JLabel("IP Address");
		IPAddrLabel.setBounds(13, 352, 134, 18);
		BasicPanel.add(IPAddrLabel);
		
		
		// ARP Send 버튼
		btnBasicSend = new JButton("Send");
		btnBasicSend.setBounds(262, 382, 75, 35);
		btnBasicSend.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				if (e.getSource() == btnBasicSend) { //BasicPanel의 Send버튼 : BasicARPSend 동작하는 함수
					// Step1. IPAddrInput의 값을 읽어와서 byte[]로 변경
					// Step2. ARPLayer의 Send함수 호출
					// Step3. Application Layer의 ArpCacheList 업데이트
					
					//Step1
					String[] dstIP = IPAddrInput.getText().split("\\.");
					byte[] dstIPAddr = new byte[4];
					for (int i = 0; i < 4; i++) {
						dstIPAddr[i] = (byte) Integer.parseInt(dstIP[i]);
					}
					IPAddrInput.setText("");

					// Step2
					String msg = "";	// 상위 Layer에서 내려가는 data
					byte[] input = msg.getBytes();
					
					// ARP Layer의 dstIP 주소를 dstIPAddr로 설정한다.
					((ARPLayer)m_LayerMgr.GetLayer("ARP")).arp_header.setDstIPAddr(dstIPAddr);
					// IP Layer의 dstIP주소를 dstIPAddr로 설정한다.
					((IPLayer)m_LayerMgr.GetLayer("IP")).m_sHeader.setIp_dst(dstIPAddr);
					
					// TCP Layer로 내려보낸다.
					((TCPLayer)m_LayerMgr.GetLayer("TCP")).Send(input, 0);
					//Step3
					GetArpTable();
				}
			}
		});
		BasicPanel.add(btnBasicSend);
		
		IPAddrInput = new JTextField();
		IPAddrInput.setBounds(13, 382, 235, 35);
		BasicPanel.add(IPAddrInput);
		IPAddrInput.setColumns(10);
		
		ProxyPane = new JPanel();
		ProxyPane.setBorder(new TitledBorder(null, "Proxy ARP Entry", TitledBorder.LEADING, TitledBorder.TOP, null, null));
		ProxyPane.setBounds(371, 29, 349, 429);
		contentPanel.add(ProxyPane);
		ProxyPane.setLayout(null);
		
		ProxyEntryList = new List();
		//ProxyEntryList.setBorder(new BevelBorder(BevelBorder.LOWERED, null, null, null, null));
		ProxyEntryList.setBounds(14, 24, 321, 200);
		ProxyPane.add(ProxyEntryList);
		
		btnProxyAdd = new JButton("Add");
		btnProxyAdd.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				AddProxyEntry(DeviceName.getText(), ProxyIPAddr.getText(), ProxyMACAddr.getText());
				GetProxyTable();
				DeviceName.setText("");
				ProxyIPAddr.setText("");
				ProxyMACAddr.setText("");
			}
		});
	
		btnProxyAdd.setBounds(51, 384, 105, 33);
		 
		ProxyPane.add(btnProxyAdd);
		
		btnProxyDelete = new JButton("Delete");
		btnProxyDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int index = ProxyEntryList.getSelectedIndex();
				if(index >= 0) {
					DeleteProxy(index);
				}
				GetProxyTable();//Proxy Table 갱신
			}
		});
		btnProxyDelete.setBounds(195, 384, 105, 33);
		ProxyPane.add(btnProxyDelete);
		
		lblDevice = new JLabel("Device");
		lblDevice.setHorizontalAlignment(SwingConstants.RIGHT);
		lblDevice.setBounds(27, 253, 89, 18);
		ProxyPane.add(lblDevice);
		
		lblIpAddress = new JLabel("IP Address");
		lblIpAddress.setHorizontalAlignment(SwingConstants.RIGHT);
		lblIpAddress.setBounds(27, 295, 89, 18);
		ProxyPane.add(lblIpAddress);
		
		lblMacAddress = new JLabel("MAC Address");
		lblMacAddress.setHorizontalAlignment(SwingConstants.RIGHT);
		lblMacAddress.setBounds(27, 338, 89, 18);
		ProxyPane.add(lblMacAddress);
		
		DeviceName = new JTextField();
		DeviceName.setBounds(130, 250, 182, 24);
		ProxyPane.add(DeviceName);
		DeviceName.setColumns(10);
		
		ProxyIPAddr = new JTextField();
		ProxyIPAddr.setColumns(10);
		ProxyIPAddr.setBounds(130, 292, 182, 24);
		ProxyPane.add(ProxyIPAddr);
		
		ProxyMACAddr = new JTextField();
		ProxyMACAddr.setColumns(10);
		ProxyMACAddr.setBounds(130, 335, 182, 24);
		ProxyPane.add(ProxyMACAddr);
		
		GratuitousPane = new JPanel();
		GratuitousPane.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Gratuitous ARP", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		GratuitousPane.setBounds(734, 39, 349, 191);
		contentPanel.add(GratuitousPane);
		GratuitousPane.setLayout(null);
		
		JLabel lblHwA = new JLabel("H/W Address");
		lblHwA.setHorizontalAlignment(SwingConstants.LEFT);
		lblHwA.setBounds(14, 42, 135, 34);
		GratuitousPane.add(lblHwA);
		
		
		GARPAddrInput = new JTextField();
		GARPAddrInput.setBounds(14, 75, 321, 34);
		GratuitousPane.add(GARPAddrInput);
		GARPAddrInput.setColumns(10);

		// Gratuitous ARP의 Send 버튼
		btnGratSend = new JButton("Send");
		btnGratSend.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (e.getSource() == btnGratSend) {
					System.out.println("==== GARP 전송입니다.====");
					String newMacAddr = GARPAddrInput.getText();
					byte[] newAddr = StringToMAC(newMacAddr);		// 입력된 MAC 주소(변경된 내 MAC 주소)
					
//					// ARP Layer의 src Mac 주소는 newAddr로, dstIP주소는 MY_IP로 설정한다.
					((ARPLayer)m_LayerMgr.GetLayer("ARP")).arp_header.setSrcMacAddr(newAddr);	// Sender 주소
					((ARPLayer)m_LayerMgr.GetLayer("ARP")).arp_header.setDstIPAddr(MY_IP);
//					((ARPLayer)m_LayerMgr.GetLayer("ARP")).arp_header.setDstMacAddr(newAddr);	// Target 주소
					
					// IPLayer의 dst,src ip주소를 나의 ip 주소로 설정한다.
					((IPLayer)m_LayerMgr.GetLayer("IP")).m_sHeader.setIp_dst(MY_IP);
					((IPLayer)m_LayerMgr.GetLayer("IP")).m_sHeader.setIp_src(MY_IP);
					byte[] bc = new byte[6];
			    	for(int i = 0 ; i < 6 ; i++) {
			    		bc[i] = (byte)0xff;
			    	}
					
					//((EthernetLayer)m_LayerMgr.GetLayer("ETHERNET")).set_srcaddr(newAddr);		// Ethernet Layer의 src mac 주소를 addr로 설정한다.
					((EthernetLayer)m_LayerMgr.GetLayer("ETHERNET")).set_dstaddr(bc);		// broadcast 설정
					
					// TCP Layer로 내려보낸다.
					String msg = "";	// 상위 Layer에서 내려가는 data
					byte[] input = msg.getBytes();
					((TCPLayer)m_LayerMgr.GetLayer("TCP")).Send(input, input.length);
				}
			}
		});
		btnGratSend.setBounds(144, 132, 75, 39);
		GratuitousPane.add(btnGratSend);
		

		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Address", TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		panel.setBounds(734, 252, 349, 206);
		contentPanel.add(panel);
		panel.setLayout(null);
		
		NICList = new JComboBox();
		NICList.setBounds(120, 43, 188, 24);
		panel.add(NICList);
		
		JLabel lblNewLabel = new JLabel("NIC List");
		lblNewLabel.setBounds(14, 46, 92, 18);
		panel.add(lblNewLabel);
		
		JLabel lblMacAddress = new JLabel("MAC Address");
		lblMacAddress.setBounds(14, 82, 92, 18);
		panel.add(lblMacAddress);
		
		JLabel lblIpAddress = new JLabel("IP Address");
		lblIpAddress.setBounds(14, 118, 92, 18);
		panel.add(lblIpAddress);
		
		srcMacAddress = new JTextField();
		srcMacAddress.setBounds(120, 79, 188, 24);
		panel.add(srcMacAddress);
		srcMacAddress.setColumns(10);
		
		srcIPAddress = new JTextField();
		srcIPAddress.setColumns(10);
		srcIPAddress.setBounds(120, 115, 188, 24);
		panel.add(srcIPAddress);
		
		// Network Interface Card 설정하는 부분
		JButton btnSetting = new JButton("Setting");
		btnSetting.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				String selected = NICList.getSelectedItem().toString();
				selected_index = NICList.getSelectedIndex();
				// Network Layer에서 Adapter Number 저장
				((NILayer) m_LayerMgr.GetLayer("NI")).SetAdapterNumber(selected_index);
				
				srcMacAddress.setText("");
				String MacAddr = "";
				byte[] MacAddress = new byte[6];
				
				// 해당 Network Interface에서 Ethernet 주소를 가져오는 함수
				try {
					MacAddress = ((NILayer) m_LayerMgr.GetLayer("NI")).GetAdapterObject(selected_index)
																	  .getHardwareAddress();
					MacAddr = macToString(MacAddress).toUpperCase();
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				srcMacAddress.setText(MacAddr);
				MY_MAC = MacAddress;		// 나의 MAC 주소를 Application Layer에 저장함
				((ARPLayer)m_LayerMgr.GetLayer("ARP")).arp_header.setSrcMacAddr(MY_MAC);
				((EthernetLayer)m_LayerMgr.GetLayer("ETHERNET")).set_srcaddr(MY_MAC);
				
				// IP주소 저장하는 과정.
				srcIPAddress.setText("");
				String IPAddress = "";
				
				// 현재 내 IP 주소 가져오기 : String Type
				try {
					IPAddress = InetAddress.getLocalHost().getHostAddress();
				} catch (UnknownHostException e2) {
					// TODO Auto-generated catch block
					e2.printStackTrace();
				}
				srcIPAddress.setText(IPAddress);
				MY_IP = StringToIP(IPAddress);
				((ARPLayer)m_LayerMgr.GetLayer("ARP")).arp_header.setSrcIPAddr(MY_IP);
				((IPLayer)m_LayerMgr.GetLayer("IP")).m_sHeader.setIp_src(MY_IP);	//IP Layer에 나의 IP 저장
				
				// 여기까지 기본 설정(NI Adapter 설정, 나의 MAC 주소 설정, 나의 IP 주소 저장)

			}
		});
		btnSetting.setBounds(230, 151, 105, 38);
		panel.add(btnSetting);
		
		setVisible(true);
		SetCombobox();
		

	}
	
	// Network Interface 목록을 가져옴
	private void SetCombobox() {
		java.util.List<PcapIf> m_pAdapterList = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder();

		int r = Pcap.findAllDevs(m_pAdapterList, errbuf);
		if (r == Pcap.NOT_OK || m_pAdapterList.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
		}
		for (int i = 0; i < m_pAdapterList.size(); i++)
			this.NICList.addItem(m_pAdapterList.get(i).getDescription());
	}

	
	// GetArpTable : ARPLayer의 ARPCacheTable을 읽어오는 함수
	public boolean GetArpTable() {
		// AppLayer의 ARPCacheList 초기화
		ARPCacheList.removeAll();
		Iterator<ARPLayer._ARP_Cache> iter = ARPLayer.ArpCacheTable.iterator();
		while(iter.hasNext()) {
			ARPLayer._ARP_Cache arpCache = iter.next();
			byte[] ipAddr = arpCache.ipAddr;
			byte[] macAddr = arpCache.macAddr;
			String status = arpCache.status == true ? "Complete" : "Incomplete";	//status에 따라 다르게 나타나도록
			String strMacAddr = "";
			String strIPAddr = ipToString(ipAddr);
			
			// MAC 주소 알면 MAC 주소로, 모르면 ????????로 나타냄
			strMacAddr = arpCache.status == true ? macToString(macAddr) : "?????????????";
			ARPCacheList.add(String.format("%15s", strIPAddr) + "          " + strMacAddr + "          " + status);
			System.out.println("Table 갯수 : " + ARPLayer.ArpCacheTable.size());
		}
		return true;
	}
	// DeleteARP
	public boolean DeleteARP(int index){
		// ARP Layer에서 해당 index의 ARP Cache를 제거
		ARPLayer.ArpCacheTable.remove(index);
		// GUI Update
		GetArpTable();
		return true;
	}
	
	// Add Proxy Entry
	public boolean AddProxyEntry(String DeviceName, String IpAddr, String MacAddr) {
		byte[] ipAddr = StringToIP(IpAddr);
		byte[] macAddr = StringToMAC(MacAddr);
		ARPLayer._Proxy_Entry newProxy = new ARPLayer._Proxy_Entry(DeviceName, ipAddr, macAddr);
		ARPLayer.ProxyEntryTable.add(newProxy);
		return true;
	}
	
	// Proxy Table Get
	public boolean GetProxyTable() {
		// AppLayer의 Proxy Table 초기화
		ProxyEntryList.removeAll();
		// iterator 순회하면서  table의 값들을 읽어온다.
		Iterator<ARPLayer._Proxy_Entry> iter = ARPLayer.ProxyEntryTable.iterator();
		while(iter.hasNext()) {
			ARPLayer._Proxy_Entry proxyEntry = iter.next();
			// AppLayer의 List에 나타내기 위해 String으로 모두 변경
			String DeviceName = proxyEntry.hostName;
			String ipAddr = ipToString(proxyEntry.ipAddr);
			String macAddr = macToString(proxyEntry.macAddr);
			ProxyEntryList.add(DeviceName + "       " + ipAddr + "       " + macAddr);
		}
		return true;
	}
	
	// Delete Proxy Entry
	public boolean DeleteProxy(int index) {
		((ARPLayer)m_LayerMgr.GetLayer("ARP")).ProxyEntryTable.remove(index);
		System.out.println("ProxyTableSize : " + ((ARPLayer)m_LayerMgr.GetLayer("ARP")).ProxyEntryTable.size());
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


