import java.util.ArrayList;


public class RoutingTable {
	
	public ArrayList<_ROUTING_ENTRY_> routingTable = new ArrayList<>();
	
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
	
	// Routing Table에 Entry를 추가하는 함수
	public void addRoutingEntry(byte[] dstIP, byte[] netmask, byte[] gateway, String flag, String inter, int metric){
		_ROUTING_ENTRY_ entry = new _ROUTING_ENTRY_();		//Entry 생성
		entry.setRoutingEntry(dstIP, netmask, gateway, flag, inter, metric);	//Entry Setting
		routingTable.add(entry);		//Table에 Add
	}
	
	// index를 이용하여 Table에서 Entry찾아서 삭제
	public boolean deleteRoutingEntry(int index){
		// Table 범위 안에 들어가는 경우
		if(index >= 0 && index < routingTable.size()-1){
			routingTable.remove(index);
			return true;
		}
		return false;
	}
	
	// TODO: Routing Table에서 Masking하는 함수
	
	// TODO: Routing Table에 있는지 확인하는 함수
	

	
	

}
