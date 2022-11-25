import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;

public class EthernetLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	private class _ETHERNET_ADDR {
		private byte[] addr = new byte[6];

		public _ETHERNET_ADDR() {
			this.addr[0] = (byte) 0x00;
			this.addr[1] = (byte) 0x00;
			this.addr[2] = (byte) 0x00;
			this.addr[3] = (byte) 0x00;
			this.addr[4] = (byte) 0x00;
			this.addr[5] = (byte) 0x00;
		}
	}

	private class _ETHERNET_HEADER {
		_ETHERNET_ADDR enet_dstaddr;
		_ETHERNET_ADDR enet_srcaddr;
		byte[] enet_type;
		byte[] enet_data;

		public _ETHERNET_HEADER() {
			this.enet_dstaddr = new _ETHERNET_ADDR();
			this.enet_srcaddr = new _ETHERNET_ADDR();
			this.enet_type = new byte[2];
			this.enet_type[0] = (byte) 0x08; // 0x08??
			this.enet_type[1] = (byte) 0x06;	// 0x0806
			this.enet_data = null;
		}
	}

	_ETHERNET_HEADER m_sHeader = new _ETHERNET_HEADER();

	public void set_type(byte type){ // 타입저장
		m_sHeader.enet_data[1] = (byte)type;
	}
	public void set_dstaddr(byte[] dst){  // 목적지 저장
		//m_sHeader.enet_dstaddr.addr =  dst;
		for(int i = 0 ; i < 6 ; i++){
			m_sHeader.enet_dstaddr.addr[i] =  dst[i];
		}
	}
	public void set_srcaddr(byte[] src){  // 주소 저장
		for(int i = 0; i < 6 ; i++) {
			m_sHeader.enet_srcaddr.addr[i] =  src[i];
		}
		//m_sHeader.enet_srcaddr.addr =  src;
	}
	public  byte[] get_dst(){  //dst return
		return m_sHeader.enet_dstaddr.addr;
	}
	public  byte[] get_src(){  //src return
		return m_sHeader.enet_srcaddr.addr;
	}
	
	public EthernetLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		
	}
	public byte[] ObjToByte(_ETHERNET_HEADER Header, byte[] input, int length) {
		byte[] buf = new byte[length + 14];
		for (int i = 0; i < 6; i++) {
			buf[i] = Header.enet_dstaddr.addr[i];
			buf[i + 6] = Header.enet_srcaddr.addr[i];
		}
		buf[12] = Header.enet_type[0];
		buf[13] = Header.enet_type[1];
		for (int i = 0; i < length; i++)
			buf[14 + i] = input[i];

		return buf;
	}

	public boolean Send(byte[] input, int length) {
		byte[] sender = m_sHeader.enet_srcaddr.addr;
		System.out.println("Sender 주소 : ");
		for(int i = 0; i <sender.length ; i++) {
			System.out.print(Integer.toHexString(sender[i]) + ":");
		}
		System.out.println();
		
		byte[] target = m_sHeader.enet_dstaddr.addr;
		System.out.println("Receiver 주소 : ");
		for(int i = 0; i <target.length ; i++) {
			System.out.print(Integer.toHexString(target[i]) + " ");
		}
		System.out.println("");		
		//상위 계층의 종류에 따라 헤더에 상위 프로토콜 형태 저장 후 물리적 계층으로 전달 
		m_sHeader.enet_type[0] = (byte) 0x08;
		m_sHeader.enet_type[1] = (byte) 0x06;
		byte[] bytes = ObjToByte(m_sHeader, input, length);
		((NILayer)this.GetUnderLayer()).Send(bytes, length + 14);
		return false;

	}

	

	public byte[] RemoveEtherHeader(byte[] input, int length) {
		byte[] data = new byte[length - 14];
		System.arraycopy(input, 14, data, 0, data.length);
		return data;
	}

	public boolean Receive(byte[] input) {

		if(!IsItMyPacket(input) && (IsItMine(input)|| IsItBroadcast(input)) ){// broadcast이거나,  목적지가 나일시 
			byte[] datas = RemoveEtherHeader(input, input.length);
			if(input[12] == (byte)0x08 && input[13] == (byte) 0x06){ // ARP 0x08 [06]
				System.out.println(this.GetUpperLayer(1).GetLayerName());
				((ARPLayer)this.GetUpperLayer(1)).Receive(datas);
			}
			else return false;
		}else{ // 
			return false;
		}
		
		return true;
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

	public boolean IsItMyPacket(byte[] input) {
		for (int i = 0; i < 6; i++) {
			if (m_sHeader.enet_srcaddr.addr[i] == input[6 + i])
				continue;
			else
				return false;
		}
		return true;
	}

	public boolean IsItMine(byte[] input) {
		for (int i = 0; i < 6; i++) {
			if (m_sHeader.enet_srcaddr.addr[i] == input[i])
				continue;
			else {
				return false;
			}
		}
		return true;
	}

	public boolean IsItBroadcast(byte[] input) {
		for (int i = 0; i < 6; i++) {
			if (input[i] == -1) {
				continue;
			} else
				return false;
		}
		return true;
	}
	

}
