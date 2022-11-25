import java.util.ArrayList;

public class IPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	private class _IP_ADDR {
		private byte[] addr = new byte[4];

		public _IP_ADDR() {
			this.addr[0] = (byte) 0x00;
			this.addr[1] = (byte) 0x00;
			this.addr[2] = (byte) 0x00;
			this.addr[3] = (byte) 0x00;
		}
		
		public _IP_ADDR(byte[] ipAddress) {
			this.addr[0] = ipAddress[0];
			this.addr[1] = ipAddress[1];
			this.addr[2] = ipAddress[2];
			this.addr[3] = ipAddress[3];
		}
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
		_IP_ADDR ip_src; // IP address of source (4byte)
		_IP_ADDR ip_dst; // IP address of destination (4byte)
		byte[] ip_data; // variable length data


		public _IP_HEADER() {
			this.ip_src = new _IP_ADDR();
			this.ip_dst = new _IP_ADDR();
			this.ip_verlen = (byte) 4;
			this.ip_tos = (byte)0x00;
			this.ip_len = new byte[2];
			this.ip_id = new byte[2];
			this.ip_fragoff = new byte[2];
			this.ip_ttl = (byte)0x00;
			this.ip_proto = (byte)0x00;
			this.ip_cksum = new byte[2];

		}


		public _IP_ADDR getIp_src() {
			return ip_src;
		}


		public void setIp_src(byte[] ip_src) {
			this.ip_src = new _IP_ADDR(ip_src);
		}


		public _IP_ADDR getIp_dst() {
			return ip_dst;
		}


		public void setIp_dst(byte[] ip_dst) {
			this.ip_dst = new _IP_ADDR(ip_dst);
		}
	}

	_IP_HEADER m_sHeader = new _IP_HEADER();

	public IPLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		
	}

	// IP Layer는 ARP와는 단방향 연결이고  ETHERNET과는 양방향 연결입니다.
	public boolean Send(byte[] input, int length) {
		// Header 부분에서 설정할 것이 있지만 일단은 생략하는 것으로 하겠습니다.
		byte[] output = ObjToByte(m_sHeader, input, length);
		
		// 연결 여부 확인을 위한 UnderLayer의 이름 출력
		System.out.println(this.GetUnderLayer().GetLayerName());
		((ARPLayer)this.GetUnderLayer()).Send(input, length);
		

		return false;
	}

	

	public boolean Receive(byte[] input) {
		
		return true;
	}
	
	public byte[] ObjToByte(_IP_HEADER header, byte[] input, int length) {
		byte[] buf = new byte[length + 20];
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
		System.arraycopy(header.ip_src.addr, 0, buf, 12, 4);
		System.arraycopy(header.ip_dst.addr, 0, buf, 16, 4);
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
