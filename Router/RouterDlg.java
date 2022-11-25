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

    private static LayerManager m_LayerMgr = new LayerManager();

    public static void main(String[] args) {
    	/*
    	 * TODO:
    	 * - Layer 생성
    	 * - Layer 연결
    	 */
    	RouterDlg layer = new RouterDlg("GUI");

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
    private DefaultTableModel StaticRouterModel, ARPCacheModel, ProxyARPModel;

    

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
		StaticRouterModel = new DefaultTableModel(
				new Object[][] {
						{"123.123.123,123","123.123.123,123","123.123.123.123","UP","1","Host1"}
				},
				new String[] {
					"Destination", "Netmask", "Gateway", "Flag", "Interface", "Metric"
				}
			);
		StaticRouterTable.setModel(StaticRouterModel);
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
				}
			}
		});
		btnRouterDelete.setBounds(345, 441, 105, 27);
		StaticRouterPane.add(btnRouterDelete);
		
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

		
		btnAllDelete = new JButton("All Detete");
		btnAllDelete.setBounds(196, 298, 127, 42);
		
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
			btnAdd.setBounds(83, 271, 84, 27);
			AddRouterPane.add(btnAdd);
			
			JButton btnCancel = new JButton("Cancel");
			btnCancel.setBounds(208, 271, 84, 27);
			AddRouterPane.add(btnCancel);
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
				NICList.addItem(m_pAdapterList.get(i).getDescription());
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
				ProxyInterface.setBounds(173, 144, 130, 24);
				ProxyAddPanel.add(ProxyInterface);
			}
		}

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


