import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;

public class scannerfinder {

    public static void main(String[] args) {
        final StringBuilder errbuf = new StringBuilder();
        final Pcap pcap = Pcap.openOffline(args[0], errbuf);
        HashMap<String, int[]> hashmap = new HashMap<String, int[]>();
        if (pcap == null) {
            System.err.println(errbuf);
            return;
        }

        final Tcp tcp = new Tcp();
        final PcapPacket packet = new PcapPacket(JMemory.POINTER);
        final Ip4 ip = new Ip4();

        while (pcap.nextEx(packet) == Pcap.NEXT_EX_OK) {
            if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
                //System.out.println(FormatUtils.ip(ip.source()));
                if (tcp.flags_SYN() && !tcp.flags_ACK()) {
                    if (hashmap.containsKey(FormatUtils.ip(ip.source()))) {
                        hashmap.get(FormatUtils.ip(ip.source()))[0]++;
                    } else {
                        hashmap.put(FormatUtils.ip(ip.source()), new int[2]);
                        hashmap.get(FormatUtils.ip(ip.source()))[0]++;
                    }
                } else if (tcp.flags_SYN() && tcp.flags_ACK()) {
                    //int[] arr = hashmap.get(FormatUtils.ip(ip.source()));
                    //arr[0]++;
                    if (hashmap.containsKey(FormatUtils.ip(ip.destination()))) {
                        hashmap.get(FormatUtils.ip(ip.destination()))[1]++;
                    } else {
                        hashmap.put(FormatUtils.ip(ip.destination()), new int[2]);
                        hashmap.get(FormatUtils.ip(ip.destination()))[1]++;
                    }
                }
            }
        }


        for (String ipAddr : hashmap.keySet()) {
            //System.out.printf("IP Address: %s, SYN Packets: %d, SYN + ACK Packets: %d%n", ipAddr, hashmap.get(ipAddr)[0], hashmap.get(ipAddr)[1]);
            if(hashmap.get(ipAddr)[0] > (3 * hashmap.get(ipAddr)[1])){
                System.out.printf("%s%n", ipAddr);
            }
        }

    }
}
