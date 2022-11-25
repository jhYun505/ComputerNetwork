import java.util.ArrayList;

public class TCPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
/*
typedef struct _TCPLayer_HEADER {
unsigned short tcp_sport; // source port (2byte)
unsigned short tcp_dport;// destination port (2byte)
unsigned int tcp_seq; // sequence number (4byte)
unsigned int tcp_ack; // acknowledged sequence (4byte)
unsigned char tcp_offset; // no use (1byte)
unsigned char tcp_flag; // control flag (1byte)
unsigned short tcp_window; // no use (2byte)
unsigned short tcp_cksum; // check sum (2byte)
unsigned short tcp_urgptr; // no use (2byte)
unsigned char Padding[4]; //(4byte)
unsigned char tcp_data[ TCP_DATA_SIZE ]; // data part
}TCPLayer_HEADER, *LPTCPLayer_HEADER ;
*/
	private class _TCP_ADDR {
		private byte[] addr = new byte[2];

		public _TCP_ADDR () {
			this.addr[0] = (byte) 0x00;
			this.addr[1] = (byte) 0x00;
		}
	}

	private class _TCP_HEADER {
		_TCP_ADDR tcp_sport; // source port (2byte)
		_TCP_ADDR tcp_dport;// destination port (2byte)
		byte[] tcp_seq; // sequence number (4byte)
		byte[] tcp_ack; // acknowledged sequence (4byte)
		byte tcp_offset; // no use (1byte)
		byte tcp_flag; // control flag (1byte)
		byte[] tcp_window; // no use (2byte)
		byte[] tcp_cksum; // check sum (2byte)
		byte[] tcp_urgptr; // no use (2byte)
		byte[] Padding; //(4byte)
		byte[] tcp_data; // data part

		public _TCP_HEADER() {
			this.tcp_dport = new _TCP_ADDR();
			this.tcp_sport = new _TCP_ADDR();
			this.tcp_seq = new byte[4];
			this.tcp_ack = new byte[4];
			this.tcp_offset = (byte) 0x00;
			this.tcp_flag = (byte) 0x00;
			this.tcp_window = new byte[2];
			this.tcp_cksum = new byte[2];
			this.tcp_urgptr = new byte[2];
			this.Padding = new byte[4];

		}
	}

	_TCP_HEADER m_sHeader = new _TCP_HEADER();

	public TCPLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		
	}

	// Header를 Byte화 해서 하위 Layer로 전달한다(IP Layer)
	public boolean Send(byte[] input, int length) {
		// TCP Layer의 경우 지나가기만 하지 정해진 규칙(port 번호 등)이 없으므로 그냥 default 0으 값이 채워진 HEADER전달합니다.
		// 현재는 ARP만 구현되어 있으므로 tcp_flag도 따로 설정하지 않겠습니다.
		byte[] output = ObjToByte(m_sHeader, input, length);
		// 하위 Layer인 IP Layer로 전달함.
		((IPLayer)this.GetUnderLayer()).Send(output, output.length);
	

		return false;
	}

	

	public boolean Receive(byte[] input) {
		// ARP만 구현해서 이 부분은 구현하지 않았습니다.
		return true;
	}
	
	public byte[] ObjToByte(_TCP_HEADER header, byte[] input, int length) {
		byte[] buf = new byte[24 + length];
		//TO-DO : 객체 -> byte 바꾸는 배열 필요
		buf[0] = header.tcp_sport.addr[0];
		buf[1] = header.tcp_sport.addr[1];
		buf[2] = header.tcp_dport.addr[0];
		buf[3] = header.tcp_dport.addr[1];
		System.arraycopy(header.tcp_seq, 0, buf, 4, 4);
		System.arraycopy(header.tcp_ack, 0, buf, 8, 4);
		buf[12] = header.tcp_offset;
		buf[13] = header.tcp_flag;
		buf[14] = header.tcp_window[0];
		buf[15] = header.tcp_window[1];
		buf[16] = header.tcp_cksum[0];
		buf[17] = header.tcp_cksum[1];
		buf[18] = header.tcp_urgptr[0];
		buf[19] = header.tcp_urgptr[1];
		System.arraycopy(header.Padding, 0, buf, 20, 4);
		for(int i = 0; i < length ; i++) {
			buf[23 + i] = input[i];
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
