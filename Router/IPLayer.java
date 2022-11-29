import java.util.ArrayList;
import java.util.Arrays;

public class IPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	public IPLayer otherIP;
	public RoutingTable RT_Table;
	
	public void setRT_Table(RoutingTable RT_Table) {
		this.RT_Table = RT_Table;
	}

	public void setOtherIP(IPLayer ip) {
		this.otherIP = ip;
	}

	class _IP_HEADER {
		byte ip_verlen; // ip version ->IPv4 : 4 (1byte)
		byte ip_tos; // type of service (1byte)
		byte[] ip_len; // total packet length (2byte)
		byte[] ip_id; // datagram id (2byte)
		byte[] ip_fragoff; // fragment offset (2byte)
		byte ip_ttl; // time to live in gateway hops (1byte)
		byte ip_proto; // IP protocol (1byte)
		byte[] ip_cksum; // header checksum (2byte)
		byte[] ip_src; // IP address of source (4byte)
		byte[] ip_dst; // IP address of destination (4byte)
		byte[] ip_data; // variable length data


		public _IP_HEADER() {
			this.ip_src = new byte[4];
			this.ip_dst = new byte[4];
			this.ip_verlen = (byte)4;
			this.ip_tos = (byte)0;
			this.ip_len = new byte[2];
			this.ip_id = new byte[2];
			this.ip_fragoff = new byte[2];
			this.ip_ttl = (byte)64;
			this.ip_proto = (byte)0;
			this.ip_cksum = new byte[2];

		}

		public byte[] getIp_src() {
			return ip_src;
		}

		public void setIp_src(byte[] ip_src) {
			this.ip_src = ip_src;
		}

		public byte[] getIp_dst() {
			return ip_dst;
		}

		public void setIp_dst(byte[] ip_dst) {
			this.ip_dst = ip_dst;
		}
	}

	_IP_HEADER m_sHeader = new _IP_HEADER();
	
	public void set_srcIP(byte[] src){
		this.m_sHeader.setIp_src(src);
	}
	
	public void set_dstIP(byte[] dst){
		this.m_sHeader.setIp_dst(dst);
	}
	
	public byte[] get_srcIP(){
		return this.m_sHeader.getIp_src();
	}
	public byte[] get_dstIP(){
		return this.m_sHeader.getIp_dst();
	}
	
	public void setLength(int length){
        m_sHeader.ip_len[0] = (byte) (length >> 8);
        m_sHeader.ip_len[1] = (byte) (length);
    }

	public IPLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		
	}



	// 이번 과제에서는 무조건 IP -> ARP로 갑니다.
	public boolean Send(byte[] input, int length) {
		byte[] output = ObjToByte(m_sHeader, input, length);
		return ((ARPLayer)this.GetUnderLayer()).Send(output, output.length);
	}
	
	public boolean Send(byte[] input, int length, byte[] dstIPAddr){
		((ARPLayer)this.GetUnderLayer()).setDstIP(dstIPAddr);
		return((ARPLayer)this.GetUnderLayer()).Send(input, input.length, dstIPAddr);
		
	}
	
	

	public boolean Receive(byte[] input) {
		
		byte[] msgSrcIP = Arrays.copyOfRange(input, 12, 16);
		byte[] msgDstIP = Arrays.copyOfRange(input, 16, 20);
		//라우터가 목적지인 경우
		if(Arrays.equals(msgDstIP, m_sHeader.getIp_src())) {
            m_sHeader.setIp_dst(msgSrcIP);
            byte[] reply = RemoveIPHeader(input, input.length);
            if(reply[0] == (byte)0x08){
            	reply[0] = (byte)0x00;		//reply는 0 request는 8
            	reply = ObjToByte(m_sHeader, reply, reply.length);
            	return ((ARPLayer)this.GetUnderLayer()).Send(reply, reply.length, msgSrcIP);
            }
		}
		
		RoutingTable._ROUTING_ENTRY_ entry = RT_Table.routing(msgDstIP);
		if (entry == null)
			return false;
		
		// 라우터 엔트리의 정보
		int interNum = Integer.parseInt(entry.getRT_INTERFACE().split(" ")[1]);
		String flag = entry.getRT_FLAG();
		byte[] gateway = entry.getRT_GATEWAY();
		
		
		// 현재 인터페이스 정보
		int thisInter = (int)this.m_sHeader.getIp_src()[2];
		// 현재 네트워크 인터페이스 내의 전송
		if(thisInter == interNum){
			if(flag.equals("U")) {
				// 연결되어있으니까 거기로 보낸다
				((ARPLayer)this.GetUnderLayer()).Send(input, input.length, msgDstIP);
			}else if(flag.equals("UG")){
				//Gateway주소로의 전송
				((ARPLayer)this.GetUnderLayer()).GetUnderLayer().Send(input, input.length);
			}
		}
		// 다른 네트워크로의 전송
		else {			
			if(flag.equals("U")) {
				otherIP.Send(input, input.length, msgDstIP);
			}else if(flag.equals("UG")){
				//Gateway주소로의 전송
				otherIP.Send(input, input.length, gateway);
			}
		}
		return true;
		
	}
	public byte[] RemoveIPHeader(byte[] input, int length) {
		byte[] data = new byte[length - 20];
		System.arraycopy(input, 20, data, 0, data.length);
		return data;
	}
	
	public byte[] ObjToByte(_IP_HEADER header, byte[] input, int length) {
		byte[] buf = new byte[length + 20];
		// length setting
		setLength(input.length + 20);
		buf[0] = header.ip_verlen;
		buf[1] = header.ip_tos;
		buf[2] = header.ip_len[0];
		buf[3] = header.ip_len[1];
		buf[4] = header.ip_id[0];
		buf[5] = header.ip_id[1];
		buf[6] = header.ip_fragoff[0];
		buf[7] = header.ip_fragoff[1];
		buf[8] = header.ip_ttl;
		buf[9] = header.ip_proto;
		buf[10] = header.ip_cksum[0];
		buf[11] = header.ip_cksum[1];
		System.arraycopy(header.ip_src, 0, buf, 12, 4);
		System.arraycopy(header.ip_dst, 0, buf, 16, 4);
		for(int i = 0; i < length ; i++) {
			buf[i + 19] = input[i];
		}
		
		return buf;
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
		if (pUnderLayer == null)
			return;
		this.p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
		if (pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
	}

	@Override
	public String GetLayerName() {
		// TODO Auto-generated method stub
		return pLayerName;
	}

	@Override
	public BaseLayer GetUnderLayer() {
		if (p_UnderLayer == null)
			return null;
		return p_UnderLayer;
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
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
