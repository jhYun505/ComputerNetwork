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
			
			System.arraycopy(dstIP, 0, RT_DEST_IP, 0, 4);
			System.arraycopy(netmask, 0, RT_NETMASK, 0, 4);
			System.arraycopy(gateway, 0, RT_GATEWAY, 0, 4);
			RT_FLAG = flag;
			RT_INTERFACE = inter;
			RT_METRIC = metric;
			
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
			if (Arrays.equals(currentEntry.getRT_DEST_IP(), maskingResult))
				return currentEntry;
		}

		return null;
	}

	// masking dstIP for subnetMask
	public byte[] maskingDstIP(byte[] dstIP, byte[] subnetMask) {
		byte[] maskingResult = new byte[4];
		for (int i = 0; i < 4; i++) {
			maskingResult[i] = (byte) (dstIP[i] & subnetMask[i]);
		}
		
		return maskingResult;
	}
	
	// Routing 과정 : input -> 올라온 메세지
	public boolean routing(byte[] input){
		// 원래의 목적지 IP 주소
		byte[] originDstIP = Arrays.copyOfRange(input, 16, 20);
		// 지금 보내야 하는 IP 주소
		byte[] nowDstIP = Arrays.copyOf(originDstIP, 4);		// ARP Cache Table에서 찾아야 하는 주소
		// Router Table에서 IP 검색해서 어디로 갈지 정함
		_ROUTING_ENTRY_ matched = findMatchingEntry(originDstIP);
		
		// Matching 되는게 없으면? -> 근데 Default Gateway(Masking 0.0.0.0)통해서 갈 것 같기는 합니다
		if (matched == null) return false;
		
		// U(Up) -> 라우터의 동작 여부(U이면 동작함)
		if(matched.getRT_FLAG().equals("U")){
			System.out.println("===== Router 동작 중 =====");
		}else if (matched.getRT_FLAG().equals("UG")) {
			// Gate MAC 주소로 전송해야함
			// 검색해야 하는 IP 주소는 Gateway의 IP 주소
			nowDstIP = Arrays.copyOf(matched.getRT_GATEWAY(), 4);
			
		} else if (matched.getRT_FLAG().equals("UH")) {
			// 직접 연결된 Host인경우
			nowDstIP = Arrays.copyOf(originDstIP, 4);
		}
		// GUI의 PortNumber번의 네트워크쪽으로 input 패킷을 전달함.
		// 타겟 주소는 nowDstIP의 MAC 주소여야함.
		int portNumber = Integer.parseInt(matched.getRT_INTERFACE().split(" ")[1]);
		// IPLayer Send 함수에 추가?
		return ipArr[portNumber].Send(input, input.length, nowDstIP);
		
	}

	

}
