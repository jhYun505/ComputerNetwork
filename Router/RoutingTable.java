import java.util.ArrayList;
import java.util.Arrays;


public class RoutingTable {
	
	public ArrayList<_ROUTING_ENTRY_> routingTable = new ArrayList<>();
	
	public IPLayer[] ipArr = new IPLayer[2];
	public RouterDlg GUI;
	
	class _ROUTING_ENTRY_{
		
		private byte[] RT_DEST_IP;		// Routing Table destination IP Address
		private byte[] RT_NETMASK;		// Routing Table Masking
		private byte[] RT_GATEWAY;		// Routing Table Gateway Address
		private String RT_FLAG;			// Routing Table FLAG : U, G, H 조합
		private String RT_INTERFACE;	// Routing Table Interface information
		private int RT_METRIC;			// Routing Table Metric information
		
		/* 생성자 */
		public _ROUTING_ENTRY_(){
			RT_DEST_IP = new byte[4];
			RT_NETMASK = new byte[4];
			RT_GATEWAY = new byte[4];
			RT_FLAG = "";
			RT_INTERFACE = "";
			RT_METRIC = 0;
		}
		
		public void setRoutingEntry(byte[] dstIP, byte[] netmask, byte[] gateway, String flag, String inter, int metric) {
			
			this.RT_DEST_IP = dstIP;
			this.RT_NETMASK = netmask;
			this.RT_GATEWAY = gateway;
			this.RT_FLAG = flag;
			this.RT_INTERFACE = inter;
			this.RT_METRIC = metric;
			
		}

		public byte[] getRT_DEST_IP() {
			return RT_DEST_IP;
		}

		public byte[] getRT_NETMASK() {
			return RT_NETMASK;
		}

		public byte[] getRT_GATEWAY() {
			return RT_GATEWAY;
		}

		public String getRT_FLAG() {
			return RT_FLAG;
		}

		public String getRT_INTERFACE() {
			return RT_INTERFACE;
		}

		public int getRT_METRIC() {
			return RT_METRIC;
		}
	}
	
	public void setGUI(RouterDlg DlgLayer){
		this.GUI = DlgLayer;
	}
	
	public void setIPLayer(IPLayer layer1, IPLayer layer2) {
		this.ipArr[0] = layer1;
		this.ipArr[1] = layer2;
	}
	
	// Routing Table에 Entry를 추가하는 함수
	public void addRoutingEntry(byte[] dstIP, byte[] netmask, byte[] gateway, String flag, String inter, int metric){
		_ROUTING_ENTRY_ entry = new _ROUTING_ENTRY_();		//Entry 생성
		entry.setRoutingEntry(dstIP, netmask, gateway, flag, inter, metric);	//Entry Setting
		routingTable.add(entry);		//Table에 Add
	}
	
	// index를 이용하여 Table에서 Entry찾아서 삭제
	public boolean deleteRoutingEntry(int index){
		// Table 범위 안에 들어가는 경우
		if(index >= 0 && index < routingTable.size()){
			routingTable.remove(index);
			return true;
		}
		return false;
	}
	
	// TODO: Routing Table에 있는지 확인하는 함수
	public _ROUTING_ENTRY_ findMatchingEntry(byte[] dstIP) {
		for (int i = 0; i < routingTable.size(); i++) {
			// current entry object
			_ROUTING_ENTRY_ currentEntry = routingTable.get(i);

			byte[] subnetMask = currentEntry.getRT_NETMASK();
			byte[] maskingResult = maskingDstIP(dstIP, subnetMask);

			// matching success
			if (Arrays.equals(currentEntry.getRT_DEST_IP(), maskingResult)){
				return currentEntry;
			}
		}
		return null;
	}

	// masking dstIP for subnetMask
	public byte[] maskingDstIP(byte[] dstIP, byte[] subnetMask) {
		byte[] maskingResult = new byte[4];
		for (int i = 0; i < dstIP.length; i++) {
			maskingResult[i] = (byte) (dstIP[i] & subnetMask[i]);
		}
		
		return maskingResult;
	}
	
	// Routing 과정 : input -> 올라온 메세지
	public _ROUTING_ENTRY_ routing(byte[] dstIP){
		// 원래의 목적지 IP 주소
		byte[] originDstIP = dstIP;
		// 지금 보내야 하는 IP 주소
		byte[] nowDstIP = Arrays.copyOf(originDstIP, 4);		// ARP Cache Table에서 찾아야 하는 주소
		// Matching 되는 IP 주소 보냄
		return findMatchingEntry(originDstIP);
		
		// IPLayer에서 받아서 ip가지고 RouterLayer로 내려보낸다.
		
	}

	

}
