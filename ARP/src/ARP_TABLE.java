import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Timer;
import java.util.TimerTask;

public class ARP_TABLE {
    public static HashMap<String, byte[]> arptable = new Hashtable<>();

    public static void arp_table_remove_all() {
        arptable = new Hashtable();
        // 제거 후 업데이트
    }

    public static void arp_table_remove() {

        // remove 구현
    }

    public void checkingput(string src, byte[] value) {

        if (arptable.containsKey(src)) {
            byte[] macadd = arptable.get(src);
            if (macadd != -1) {
                set<string> str = arptable.keySet();
                for (string key : str) {
                    if (Arrays.equals(arptable.get(key), macadd)) {
                        arptable.replace(key, value);
                    }
                }
            }
            arptable.replace(src, value);
            // 키 값이 있다면? 새롭게 업데이트
        } else {
            arptable.put(src, value);
            // 키 값이 없다면? 새롭게 추가
        }

    }

}