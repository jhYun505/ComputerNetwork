import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Timer;
import java.util.TimerTask;



public class ARPLayer implements BaseLayer{

    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    public Hashtable<String,Timer> timerList = new Hashtable<>();
    public RouterDlg GUI_Layer;
    public ARPTable arpTable;
    public int interfaceNum;
    
    
    public void setARPTable(ARPTable arpTable) {
    	this.arpTable = arpTable;
    }
    
    public void setInterfaceNum(int num){
    	this.interfaceNum = num;
    }
    
    byte[] BROADCAST = broadcast();
    //Proxy Entry Table
    public static ArrayList<_Proxy_Entry> ProxyEntryTable = new ArrayList<>();

    class _ARP_MSG {
        byte[] hardType = new byte[2];                // 2bytes. Type of Hardware Address
        byte[] protType = new byte[2];                // 2bytes. Type of Protocol Address
        byte hardSize = (byte) 0x00;                  // 1byte. (Ethernet - 6bytes)
        byte protSize = (byte) 0x00;                  // 1byte. (IP - 4bytes)
        byte[] opCode = new byte[2];                  // 2bytes. [1 : ARP Request / 2 : ARP Reply]
        byte[] srcMacAddr = new byte[6];      //Sender's Ethernet Address(MAC주소 : 6bytes)
        byte[] srcIPAddr = new byte[4];             //Sender's IP Address(IP주소 : 4bytes)
        byte[] dstMacAddr = new byte[6];      // Target's Ethernet Address;(MAC주소 : 6bytes)
        byte[] dstIPAddr = new byte[6];             //Target's IP Address;(IP주소 : 4bytes)


        public _ARP_MSG() {
            this.hardType = new byte[2];
            this.protType = new byte[2];
            this.hardSize = (byte) 0x00;
            this.protSize = (byte) 0x00;
            this.opCode = new byte[2];
            this.srcMacAddr = new byte[6];
            this.srcIPAddr = new byte[4];
            this.dstMacAddr = new byte[6];
            this.dstIPAddr = new byte[4];
        }


		public byte[] getOpCode() {
			return opCode;
		}


		public void setOpCode(byte[] opCode) {
			this.opCode = opCode;
		}


		public byte[] getSrcMacAddr() {
			return srcMacAddr;
		}


		public void setSrcMacAddr(byte[] srcMacAddr) {
			this.srcMacAddr = srcMacAddr;
		}


		public byte[] getSrcIPAddr() {
			return srcIPAddr;
		}


		public void setSrcIPAddr(byte[] srcIPAddr) {
			this.srcIPAddr = srcIPAddr;
		}


		public byte[] getDstMacAddr() {
			return dstMacAddr;
		}


		public void setDstMacAddr(byte[] dstMacAddr) {
			this.dstMacAddr = dstMacAddr;
		}


		public byte[] getDstIPAddr() {
			return dstIPAddr;
		}


		public void setDstIPAddr(byte[] dstIPAddr) {
			this.dstIPAddr = dstIPAddr;
		}
		
		public void setDstBroadcast() {
			byte[] buf = {-1, -1, -1, -1, -1, -1};
			this.dstMacAddr = buf;
		}
        
        
    }
    _ARP_MSG arp_header = new _ARP_MSG();
    // ARP MSG Reset 함수
    private void ResetMSG() {
    	arp_header.hardType[0] = (byte)0x00;
    	arp_header.hardType[1] = (byte)0x01;		// hardware Type은 0x01 고정(Ethernet이므로)
    	arp_header.protType[0] = (byte)0x08;
    	arp_header.protType[1] = (byte)0x00;		// protocol type은 IPv4이므로 0x0800
    	arp_header.hardSize = (byte)0x06;			// Ethernet은 6bytes
    	arp_header.protSize = (byte)0x04;			// IPv4 사용하므로 4bytes
    	arp_header.opCode[0] = (byte)0x00;
    	arp_header.opCode[1] = (byte)0x01;			//Request를 기본으로
    }
    
    
    // ARP Layer 생성자
    public ARPLayer(String pName) {
    	pLayerName = pName;
    	ResetMSG();		// Layer 생성할 때 Reset 한다
    }
    
    
    
    public static class _Proxy_Entry {
    	String hostName;
    	byte[] ipAddr;
    	byte[] macAddr;
    	
    	public _Proxy_Entry (String hostName, byte[] ipAddr, byte[] macAddr) {
    		this.hostName = hostName;
    		this.ipAddr = ipAddr;
    		this.macAddr = macAddr;
    	}
    }


    /*public boolean Send(byte[] input, int length) {
    	byte[] dstIPAddress = arp_header.getDstIPAddr();
    	byte[] srcIPAddress = arp_header.getSrcIPAddr();
    	int index = -1;
    	((EthernetLayer)this.GetUnderLayer()).set_type((byte)0x06);
    	
    	// Sender == Target : GARP MSG
    	if(IsIPEquals(dstIPAddress, srcIPAddress)) {
    		((EthernetLayer)this.GetUnderLayer()).set_dstaddr(BROADCAST);
    	}else {
    		index = arpTable.IsInArpCacheTable(dstIPAddress);
	    	if(index >= 0) {
	    		System.out.println("ARP Cache Table에 있는 IP주소로 전송 시작");
	    		byte[] TargetMac = arpTable.ArpCacheTable.get(index).getMacAddr();
	    		((EthernetLayer)this.GetUnderLayer()).set_dstaddr(TargetMac);
	    		this.arp_header.setDstMacAddr(TargetMac);
	    		
	    	} else {
	    		System.out.println("ARP Cache Table에 없는 IP주소로 전송 시작");
	    		((EthernetLayer)this.GetUnderLayer()).set_dstaddr(BROADCAST);	//Broadcast로 목적지 설정
	    		byte[] TargetMac = new byte[6];
	    		arpTable.AddARPCache(dstIPAddress, TargetMac, false, this.interfaceNum);
	    		// 모르는 주소이므로 3분으로 타이머 설정
	    		//Timer timer = this.setTimeOut(dstIPAddress, 3 * 60 * 1000);
	        	//timerList.put(IpToString(dstIPAddress), timer);
	        	
	    	}
    	}
    	byte[] arpMsg = ObjToByte(arp_header, input, length);
    	((EthernetLayer)this.GetUnderLayer()).Send(arpMsg, arpMsg.length);
    	

		return true;
    }*/
    
    public void setSrcIP(byte[] srcIP){
    	this.arp_header.setSrcIPAddr(srcIP);
    }
    
    public void setDstIP(byte[] dstIP){
    	this.arp_header.setDstIPAddr(dstIP);
    }
    
    public void setSrcMac(byte[] srcMac){
    	this.arp_header.setSrcMacAddr(srcMac);
    }
    
    public void setDstMac(byte[] dstMac){
    	this.arp_header.setDstMacAddr(dstMac);
    }
    
    public boolean Send(byte[] input, int length, byte[] dstIP){
    	this.arp_header.setDstIPAddr(dstIP);
    	int index =  arpTable.IsInArpCacheTable(dstIP);
    	if(index < 0) {
    		return arpSend(input, length, dstIP);
    	}
    	boolean state = false;
    	while(!state){
    		try {
				Thread.sleep(100); //기다린다
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
    		state = arpTable.getARPCache(index).status;
    	}
    	return dataSend(input, input.length, arpTable.getARPCache(index).getMacAddr());
    	
    	
    }
    
    // arp 전송 함수
    public boolean arpSend(byte[] input, int length, byte[] targetIP){
    	byte[] msg = new byte[1];
		((EthernetLayer)this.GetUnderLayer()).set_dstaddr(BROADCAST);
		((EthernetLayer)this.GetUnderLayer()).set_type((byte)0x06);
		byte[] TargetMac = new byte[6];
		int interfaceNum = (int)targetIP[2];
		arpTable.UpdateARPCache(targetIP, TargetMac, false, interfaceNum);
		GUI_Layer.ARPTableUpdate(targetIP, TargetMac, false, interfaceNum);
		byte[] packet = ObjToByte(arp_header, msg, msg.length);
    	return ((EthernetLayer)this.GetUnderLayer()).Send(packet, packet.length);
    }
    
    //  data 전송함수
    public boolean dataSend(byte[] input, int length, byte[] TargetMac){
		((EthernetLayer)this.GetUnderLayer()).set_type((byte)0x00);
		((EthernetLayer)this.GetUnderLayer()).set_dstaddr(TargetMac);
		this.arp_header.setDstMacAddr(TargetMac);
		// 그냥 그대로 전달 -> 아는 주소니까
		return ((EthernetLayer)this.GetUnderLayer()).Send(input, input.length);
    	
    }
   
    

    // GARP
    public boolean GARPSend(byte[] input){
    	this.arp_header.setDstIPAddr(this.arp_header.srcIPAddr);
    	((EthernetLayer)this.GetUnderLayer()).set_type((byte)0x06);
    	byte[] garp = new byte[28];
        
    	garp[0] = arp_header.hardType[0];
    	garp[1] = arp_header.hardType[1];
        garp[2] = arp_header.protType[0];
        garp[3] = arp_header.protType[1];
        garp[4] = arp_header.hardSize;
        garp[5] = arp_header.protSize;
        garp[6] = arp_header.opCode[0];
        garp[7] = arp_header.opCode[1];
        
        System.arraycopy(arp_header.getSrcMacAddr(), 0, garp, 8, 6);
        System.arraycopy(arp_header.getSrcIPAddr(), 0, garp, 14, 4);
        System.arraycopy(arp_header.getDstMacAddr(), 0, garp, 18, 6);
        System.arraycopy(arp_header.getDstIPAddr(), 0, garp, 24, 4);
    	((EthernetLayer)this.GetUnderLayer()).set_dstaddr(broadcast());
    	return ((EthernetLayer)this.GetUnderLayer()).Send(garp, garp.length);
    }

    // Reply Send할 때 쓸 함수
    public boolean ReplySend(byte[] request) {
    	// 받은 ARP RequstMsg에서의 주소
    	byte[] rplMsg = new byte[request.length];
    	System.arraycopy(request, 0, rplMsg, 0, request.length);
    	rplMsg[7] = (byte)0x02;	//opcode 변경
    	System.arraycopy(arp_header.getSrcMacAddr(), 0, rplMsg, 8, 6);	//MyMac(Target MAC) -> SenderMac
    	System.arraycopy(request, 24, rplMsg, 14, 4);	// TargetIP -> Sender IP
    	System.arraycopy(request, 8, rplMsg, 18, 6);		// Sender Mac -> TargetMac
    	System.arraycopy(request, 14, rplMsg, 24, 4); 	// Sender IP -> TargetIP
    	
    	byte[] targetMac = new byte[6];
    	System.arraycopy(rplMsg, 18, targetMac, 0, 6);
    	((EthernetLayer)this.GetUnderLayer()).set_type((byte)0x06);
    	((EthernetLayer)this.GetUnderLayer()).set_dstaddr(targetMac);
    	((EthernetLayer)this.GetUnderLayer()).Send(rplMsg, rplMsg.length);
    	return true;
    }
    

    // Receive 함수
    public synchronized boolean Receive(byte[] input) {
    	byte[] opCode = Arrays.copyOfRange(input, 6, 8);
    	byte[] SenderMac = Arrays.copyOfRange(input, 8, 14);
    	byte[] SenderIP = Arrays.copyOfRange(input, 14,18);
    	byte[] TargetIP = Arrays.copyOfRange(input, 24,28);
    	
    	/*
    	// 이미 존재하는 IP 주소라면( timer Reset함 )
		if(timerList.containsKey(IpToString(SenderIP))){
			System.out.println("Timer를 취소합니다  - IP 주소 : " + IpToString(SenderIP));
			timerList.get(IpToString(SenderIP)).cancel();
		}q
		*/

		//System.out.println("== 새 Timer 설정(MAC 주소를 알고 있으므로 20분으로 설정합니다) ==");
    	//Timer timer = this.setTimeOut(SenderIP, 20 * 60 * 1000);
    	//timerList.put(IpToString(SenderIP), timer);
    	
    	if(opCode[1] == (byte) 0x01){
    		// 나한테 온 것 -> Reply보내야함
    		if(IsMyIP(TargetIP) || IsInProxyTable(TargetIP)) {
	    		ReplySend(input);
	    	}
    	}
    	int interfaceNum = SenderIP[2];
    	arpTable.UpdateARPCache(SenderIP, SenderMac, true, interfaceNum);
    	GUI_Layer.ARPTableUpdate(SenderIP, SenderMac, true, interfaceNum);	// ARP Table 업데이트

		return true;
    }
    

    // _ARP_MSG Object를 byte[]로 바꿔주는 함수
    public byte[] ObjToByte(_ARP_MSG arpMsg, byte[] input, int length) {
        byte[] buf = new byte[28 + length];
        
        buf[0] = arpMsg.hardType[0];
        buf[1] = arpMsg.hardType[1];
        buf[2] = arpMsg.protType[0];
        buf[3] = arpMsg.protType[1];
        buf[4] = arpMsg.hardSize;
        buf[5] = arpMsg.protSize;
        buf[6] = arpMsg.opCode[0];
        buf[7] = arpMsg.opCode[1];
        
        System.arraycopy(arpMsg.getSrcMacAddr(), 0, buf, 8, 6);
        System.arraycopy(arpMsg.getSrcIPAddr(), 0, buf, 14, 4);
        System.arraycopy(arpMsg.getDstMacAddr(), 0, buf, 18, 6);
        System.arraycopy(arpMsg.getDstIPAddr(), 0, buf, 24, 4);
        System.arraycopy(input, 0, buf, 28, length);
        
        return buf;
    }
    
    // ip 배열 주소를 String으로 변환하는 함수
    public String IpToString(byte[] ipAddr) {
    	String buf = "";
    	for(int i = 0 ; i < 4 ; i++) {
    		buf += (int) ipAddr[i] & 0xff;
    		if (i != 3) buf += ".";
    	}
    	return buf;
    	
    }
 // String의 IP주소를 byte[]로 변환
 	public byte[] StringToIP(String ipAddr){
 		byte[] buf = new byte[4];
 		String[] temp = ipAddr.split("\\.");
 		for(int i = 0; i < 4; i++){
 			buf[i] = (byte)Integer.parseInt(temp[i]);
 		}
 		
 		return buf;
 	}


    
    
    // Proxy Table에 있는지 확인하는 함수
    public boolean IsInProxyTable(byte[] targetIP) {
    	// iterator로 ArrayList를 순회
    	Iterator <_Proxy_Entry> iter = ProxyEntryTable.iterator();
    	while(iter.hasNext()) {
    		// targetIP와 Entry의 IP주소가 같은지 확인
    		_Proxy_Entry entry = iter.next();
    		byte[] addr = entry.ipAddr;
    		if (IsIPEquals(targetIP, addr)){
    			return true;
    		}
    	}
    	return false;	//Proxy Table에 존재하지 않는 경우
    }

    // ARP Msg의 Target IP와 나의 IP 주소와 비교
    public boolean IsMyIP (byte[] targetIP) {
    	byte[] myIP = arp_header.getSrcIPAddr();
    	for(int i = 0; i < 4 ; i++) {
    		// 일치하지 않는 경우
    		if (myIP[i] != targetIP[i]) {
    			return false;
    		}
    	}
    	return true;
    }
    
    public boolean IsIPEquals(byte[] ip1, byte[] ip2) {
    	return Arrays.equals(ip1, ip2);
    }


    // Proxy Table에 Entry 추가하는 함수
    public boolean AddPoxyEntry(String hostName, byte[] ipAddr, byte[] macAddr) {
        _Proxy_Entry newProxyEntry = new _Proxy_Entry(hostName, ipAddr, macAddr);
        ProxyEntryTable.add(newProxyEntry);
        return true;
    }
    // Proxy Table에 Entry 삭제하는 함수
    public boolean RemoveProxyEntry(byte[] ipAddr) {
        for(int i = 0; i < ProxyEntryTable.size() ; i++) {
            // 순회하면서 지우려고 하는 IP주소가 있는지 확인.
            if(Arrays.equals(ProxyEntryTable.get(i).ipAddr, ipAddr)) {
                ProxyEntryTable.remove(i);    // ArrayList에서 index이용해 제거한다.
                return true;
            }
        }
        return false;
    }
    
    public byte[] broadcast() {
    	byte[] bc = new byte[6];
    	for(int i = 0 ; i < 6 ; i++) {
    		bc[i] = (byte)0xFF;
    	}
    	return bc;
    }
    
    // GUI Layer 설정하는 함수
    public void SetGUI(RouterDlg GUI) {
    	this.GUI_Layer = GUI;
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
    
    
/* Timer 부분은 일단 제거   
 *  Timer 관련 함수 생성 
    private Timer setTimeOut(byte[] srcIPAddr, long time) {
    	Timer timer = new Timer(IpToString(srcIPAddr));		// Timer 생성
    	TimerTask task = new TimerTask() {
			@Override
			public void run() {
				// TODO Auto-generated method stub
				ARPTable.RemoveARPCache(StringToIP(Thread.currentThread().getName())); // 삭제한다.
				GUI_LAYER.GetArpTable();		// Update
				System.out.println("!!TimeOut!! - IP주소: " +Thread.currentThread().getName()+"가 "+ time /  1000 + "초가 지나서 삭제되었습니다.");
			}
    	};
    	timer.schedule(task, time);		// timer
    	return timer;
    }*/
    


}
