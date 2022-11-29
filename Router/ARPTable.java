import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;


public class ARPTable {
	
	// ARP Cache Table
    public static ArrayList<_ARP_Cache> ArpCacheTable = new ArrayList<>();
   
    
 // ARP Cache
    public static class _ARP_Cache {
    	public byte[] getIpAddr() {
			return ipAddr;
		}

		public void setIpAddr(byte[] ipAddr) {
			this.ipAddr = ipAddr;
		}

		public byte[] getMacAddr() {
			return macAddr;
		}

		public void setMacAddr(byte[] macAddr) {
			this.macAddr = macAddr;
		}

		public boolean isStatus() {
			return status;
		}

		public void setStatus(boolean status) {
			this.status = status;
		}
		
		public int getInterNum(){
			return this.interfaceNum;
		}
		
		byte[] ipAddr;
    	byte[] macAddr;
    	boolean status;				// complete == true, incomplete == false
    	int interfaceNum;
    	
    	public _ARP_Cache(byte[] ipAddr, byte[] macAddr, boolean status, int interfaceNum) {
    		this.ipAddr = ipAddr;
    		this.macAddr = macAddr;
    		this.status = status;
    		this.interfaceNum = interfaceNum;
    	}
    }
    

    
 // Arp Cache Table에 있는지 확인하는 함수
    public static int IsInArpCacheTable(byte[] targetIP) {
    	// iterator로 ArrayList를 순회
    	int index = 0;
    	for(int i = 0; i < ArpCacheTable.size(); i++) {
    		// targetIP와 Entry의 IP주소가 같은지 확인
    		_ARP_Cache target = ArpCacheTable.get(i);
    		if(IsIPEquals(targetIP, target.ipAddr)){
    			index = i;
    			return index;
    		}
    	}
    	return -1;	//ARP Table에 존재하지 않는 경우
    }
    
 // ARP Cache Table 추가하는 함수
    public boolean AddARPCache(byte[] IPAddr, byte[] MACAddr, boolean status, int interfaceNum) {
        _ARP_Cache newArpCache = new _ARP_Cache(IPAddr, MACAddr, status, interfaceNum);
        ArpCacheTable.add(newArpCache);
        return true;
    }

    // ARP Cache Table 삭제하는 함수
    public boolean RemoveARPCache(byte[] IPAddr) {
        for(int i = 0; i < ArpCacheTable.size() ; i++) {
            // 순회하면서 지우려고 하는 IP주소가 있는지 확인.
            if(Arrays.equals(ArpCacheTable.get(i).ipAddr, IPAddr)) {
                ArpCacheTable.remove(i);    // ArrayList에서 index이용해 제거한다.
                return true;
            }
        }
        return false;
    }
    // ARP Cache Table 업데이트 하는 함수
    public static boolean UpdateARPCache(byte[] IPAddr, byte[] MACAddr, boolean status, int interfaceNum) {
        // iterator로 ArrayList를 순회
        int index = IsInArpCacheTable(IPAddr);
        if(index >= 0){
		    ArpCacheTable.get(index).setIpAddr(IPAddr);
		    ArpCacheTable.get(index).setMacAddr(MACAddr);
		    ArpCacheTable.get(index).setStatus(status);
        } else {
        	ArpCacheTable.add(new _ARP_Cache(IPAddr, MACAddr, status, interfaceNum));
        }
        return true;
    }
    
    public static _ARP_Cache getARPCache(int index){
    	return ArpCacheTable.get(index);
    }
    
    public static boolean IsIPEquals(byte[] ip1, byte[] ip2) {
    	return Arrays.equals(ip1, ip2);
    }


}
