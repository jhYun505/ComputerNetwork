
public class RoutingTable {
	private int RT_INDEX;			// Routing Table index
	private byte[] RT_DEST_IP;		// Routing Table destination IP Address
	private byte[] RT_NETMASK;		// Routing Table Masking
	private byte[] RT_GATEWAY;		// Routing Table Gateway Address
	private String RT_FLAG;			// Routing Table FLAG : U, G, H 조합
	private String RT_INTERFACE;	// Routing Table Interface information
	private int RT_METRIC;			// Routing Table Metric information
	
	/* 생성자 */
	public RoutingTable(){
		
		RT_INDEX = 0;
		RT_DEST_IP = new byte[4];
		RT_NETMASK = new byte[4];
		RT_GATEWAY = new byte[4];
		RT_FLAG = "";
		RT_INTERFACE = "";
		RT_METRIC = 0;
		
	}
	
	public void setRoutingTable(byte[] dstIP, byte[] netmask, byte[] gateway, String flag, String inter, int metric) {
		int maskingResult = 0;
		System.arraycopy(dstIP, 0, RT_DEST_IP, 0, 4);
		System.arraycopy(netmask, 0, RT_NETMASK, 0, 4);
		System.arraycopy(gateway, 0, RT_GATEWAY, 0, 4);
		RT_FLAG = flag;
		RT_INTERFACE = inter;
		RT_METRIC = metric;
		
	}

	public int getRT_INDEX() {
		return RT_INDEX;
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
