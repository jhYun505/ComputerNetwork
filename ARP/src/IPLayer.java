import java.util.ArrayList;

import FileAppLayer._FAPP_HEADER;

public class IPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
/*
typedef struct _IPLayer_HEADER {
unsigned char ip_verlen; // ip version ->IPv4 : 4 (1byte)
unsigned char ip_tos; // type of service (1byte)
unsigned short ip_len; // total packet length (2byte)
unsigned short ip_id; // datagram id (2byte)
unsigned short ip_fragoff; // fragment offset (2byte)
unsigned char ip_ttl; // time to live in gateway hops (1byte)
unsigned char ip_proto; // IP protocol (1byte)
unsigned short ip_cksum; // header checksum (2byte)
unsigned char ip_src[4]; // IP address of source (4byte)
unsigned char ip_dst[4]; // IP address of destination (4byte)
unsigned char ip_data[IP_DATA_SIZE]; // variable length data
} IPLayer_HEADER, *LPIPLayer_HEADER ;
*/
	private class _IP_ADDR {
		private byte[] addr = new byte[4];

		public _IP_ADDR() {
			this.addr[0] = (byte) 0x00;
			this.addr[1] = (byte) 0x00;
			this.addr[2] = (byte) 0x00;
			this.addr[3] = (byte) 0x00;
		}
	}

	private class _IP_HEADER {
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
	}

	_IP_HEADER m_sHeader = new _IP_HEADER();

	public IPLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		
	}
	
	public void setSrcAddress(byte[] addr) {
		
		m_sHeader.ip_src.addr[0] = addr[0];
		m_sHeader.ip_src.addr[1] = addr[1];
		m_sHeader.ip_src.addr[2] = addr[2];
		m_sHeader.ip_src.addr[3] = addr[3];
		
	}
	
	public void setDstAddress(byte[] addr) {
				
		m_sHeader.ip_dst.addr[0] = addr[0];
		m_sHeader.ip_dst.addr[1] = addr[1];
		m_sHeader.ip_dst.addr[2] = addr[2];
		m_sHeader.ip_dst.addr[3] = addr[3];
	}


	public boolean Send(byte[] input, int length) {
		
		if((input[2]==(byte)0x20 && input[3]==(byte)0x80) || (input[2]==(byte)0x20 && input[3]==(byte)0x90) ) {
			
			byte[] bytes = ObjToByte(m_sHeader,input,length);
			this.GetUnderLayer().Send(bytes, length + 20);
			return true;
			
		}
		else if(input[2]==(byte)0x20 && input[3]==(byte)0x70){
			byte[] opcode = new byte[2];
			opcode[0] = (byte)0x00;
			opcode[1] = (byte)0x04;
			
			byte[] macAdd = new byte[6];
			System.arraycopy(input, 24, macAdd, 0, 6); 
			byte[] bytes = ObjToByte(m_sHeader, input, length);

						
			((ARPLayer)this.GetUnderLayer()).Send(m_sHeader.ip_src.addr,m_sHeader.ip_src.addr, macAdd, new byte[6], opcode); //arp 레이어 구현 필요

			return true;
			
		}
		
		else {
			byte[] opcode = new byte[2];
			opcode[0] = (byte)0x00;
			opcode[1] = (byte)0x01;
			byte[] bytes = ObjToByte(m_sHeader, input, length);

			((ARPLayer)this.GetUnderLayer()).Send(m_sHeader.ip_src.addr,m_sHeader.ip_dst.addr, new byte[6], new byte[6], opcode); //arp 레이어 구현 필요

			return true;
		}
	}

	

	public synchronized boolean Receive(byte[] input, int length) {
		
		System.out.println("IP receive : "+ length);
		byte[] data = removeIPHeader(input, length);
	
		if(srcChk(input)) {
			return false;
		}
		
		if(dstChk(input)) {
			this.GetUpperLayer(0).Receive(data);
			return true;
		}
		
		return false;
	}
	
	public byte[] toBytes(int input) {
		
		byte[] temp = new byte[2];
		
		temp[0] |= (byte)((input & 0xFF00)>>8);
		temp[1] |= (byte)(input & 0xFF);
		
		return temp;
	}
	
	private int toInt(byte value1, byte value2) {
        return (int)(((value1 & 0xff) << 8) | (value2 & 0xff)); // NegativeArraySizeException 발생
    }
	
	private boolean srcChk(byte[] addr) {
		for(int i = 0; i < m_sHeader.ip_src.addr.length; i++) {
			if(addr[i + 12] != m_sHeader.ip_src.addr[i])
				
				return false;
			
		}
		
		return true;
		
	}
	
	private boolean dstChk(byte[] addr) {
		for(int i = 0; i < m_sHeader.ip_dst.addr.length; i++) {
			if(addr[i + 12] != m_sHeader.ip_dst.addr[i])
				
				return false;
			
		}
		
		return true;
	}
	
	private byte[] ObjToByte(_IP_HEADER m_sHeader, byte[] input, int length) {
        
		byte[] buf = new byte[length + 20];
       
        buf[0] = m_sHeader.ip_verlen;
        buf[1] = m_sHeader.ip_tos;
        buf[2] = m_sHeader.ip_len[0];
        buf[3] = m_sHeader.ip_len[1];
        buf[4] = m_sHeader.ip_id[0];
        buf[5] = m_sHeader.ip_id[1];
        buf[6] = m_sHeader.ip_fragoff[0];
        buf[7] = m_sHeader.ip_fragoff[1];
        buf[8] = m_sHeader.ip_ttl;
        buf[9] = m_sHeader.ip_proto;
        buf[10] = m_sHeader.ip_cksum[0];
        buf[11] = m_sHeader.ip_cksum[1];

        for(int i = 0; i < 4; i++) {
        	buf[12 + i] = m_sHeader.ip_src.addr[i];
        	buf[16 + i] = m_sHeader.ip_dst.addr[i];
        }
        
        for(int i = 0; i < length; i++) {
        	buf[20 + i] = input[i];
        }

        return buf;
    }
	
	private byte[] removeIPHeader(byte[] input, int length) {
	    byte[] cpyInput = new byte[length - 20];
	    System.arraycopy(input, 20, cpyInput, 0, length - 20);
		return cpyInput;
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
