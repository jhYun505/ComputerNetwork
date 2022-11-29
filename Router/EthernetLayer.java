import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;

public class EthernetLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	// UpperLayer 0번 : IP Layer 1번 : ARPLayer
	private class _ETHERNET_HEADER {
		byte[] enet_dstaddr;
		byte[] enet_srcaddr;
		byte[] enet_type = new byte[2];
		byte[] enet_data;

		public _ETHERNET_HEADER() {
			this.enet_dstaddr = new byte[6];
			this.enet_srcaddr = new byte[6];
			this.enet_type[0] = (byte) 0x08; // 0x08??
			this.enet_type[1] = (byte) 0x00; //일단은 IP
			this.enet_data = null;
		}
		public void set_type(byte type) {
			this.enet_type = new byte[]{0x08, type};
		}
		public void set_dst(byte[] dstMac) {
			for(int i = 0 ; i < 6 ; i++){
				this.enet_dstaddr[i] = dstMac[i];
			}
		}
		
		public void set_src(byte[] srcMac) {
			for(int i = 0 ; i < 6 ; i++){
				this.enet_srcaddr[i] = srcMac[i];
			}
		}
		public byte[] get_dst(){
			return this.enet_dstaddr;
		}
		public byte[] get_src(){
			return this.enet_srcaddr;
		}
		
	}

	_ETHERNET_HEADER m_sHeader = new _ETHERNET_HEADER();
	


	public void set_type(byte type){ // 타입저장
		this.m_sHeader.set_type(type);
	}
	public void set_dstaddr(byte[] dst){  // 목적지 저장
		//m_sHeader.enet_dstaddr.addr =  dst;
		this.m_sHeader.set_dst(dst);
	}
	public void set_srcaddr(byte[] src){  // 주소 저장
		this.m_sHeader.set_src(src);
		//m_sHeader.enet_srcaddr.addr =  src;
	}
	public  byte[] get_dst(){  //dst return
		return this.m_sHeader.get_dst();
	}
	public  byte[] get_src(){  //src return
		return this.m_sHeader.get_src();
	}
	
	
	public EthernetLayer(String pName) {
		// super(pName);
		// TODO Auto-generated constructor stub
		pLayerName = pName;
	}
	public byte[] ObjToByte(_ETHERNET_HEADER Header, byte[] input, int length) {
		byte[] buf = new byte[length + 14];
		for (int i = 0; i < 6; i++) {
			buf[i] = Header.enet_dstaddr[i];
			buf[i + 6] = Header.enet_srcaddr[i];
		}
		buf[12] = Header.enet_type[0];
		buf[13] = Header.enet_type[1];
		for (int i = 0; i < length; i++)
			buf[14 + i] = input[i];

		return buf;
	}

	public boolean Send(byte[] input, int length) {
		byte[] srcMac = this.m_sHeader.get_src();
		byte[] msg = ObjToByte(m_sHeader, input, length);
		return ((NILayer)this.GetUnderLayer()).Send(msg, msg.length);
	}
	
	

	public byte[] RemoveEtherHeader(byte[] input, int length) {
		byte[] data = new byte[length - 14];
		System.arraycopy(input, 14, data, 0, data.length);
		return data;
	}

	public synchronized boolean Receive(byte[] input) {
		if(!IsItMyPacket(input) && (IsItMine(input)|| IsItBroadcast(input)) ){// broadcast이거나,  목적지가 나일시 
			byte[] datas = RemoveEtherHeader(input, input.length);
			if(input[12] == (byte)0x08){
				if(input[13] == (byte)6){ // ARP 0x08 [06]
					//ARPLayer로 전송함
					return ((ARPLayer)this.GetUpperLayer(1)).Receive(datas);
				}
				else if(input[13] == (byte)0x00){
					return ((IPLayer)this.GetUpperLayer(0)).Receive(datas);
				}
				
			}
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
		byte[] myAddr = m_sHeader.get_src();
		for (int i = 0; i < 6; i++) {
			if (myAddr[i] == input[6 + i])
				continue;
			else
				return false;
		}
		return true;
	}

	public boolean IsItMine(byte[] input) {
		byte[] myAddr = m_sHeader.get_src();
		for (int i = 0; i < 6; i++) {
			if (myAddr[i] == input[i])
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
