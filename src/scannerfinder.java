/*
Bradley White and Isaac Sotelo
CSCI 476: Lab 4
March 20, 2017
 */

import java.util.HashMap;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;

public class scannerfinder {

    public static void main(String[] args) {
        // Used by the PCAP library to process the packet capture
        final StringBuilder errbuf = new StringBuilder();

        // Open the packet capture which is passed as the first command line parameter
        final Pcap pcap = Pcap.openOffline(args[0], errbuf);

        // Create a hashmap which maps IP addresses (Strings) to an array with length two.
        // Index 0 will contain the amount of SYN packets which were sent from this IP
        // Index 1 will contain the amount of SYN + ACK packets which this IP received
        HashMap<String, int[]> hashmap = new HashMap<>();

        // Exit if no packet capture was passed in the command line
        if (pcap == null) {
            System.err.println(errbuf);
            return;
        }

        // We are only interested in packets with TCP and IP headers
        final Tcp tcp = new Tcp();
        final PcapPacket packet = new PcapPacket(JMemory.POINTER);
        final Ip4 ip = new Ip4();

        // Iterate through all packets in the capture
        while (pcap.nextEx(packet) == Pcap.NEXT_EX_OK) {
            // Check the packet headers
            if (packet.hasHeader(ip) && packet.hasHeader(tcp)) {
                // If the packet has the SYN flag set and not the ACK flag, we keep track of the source IP and the amount of packets sent
                if (tcp.flags_SYN() && !tcp.flags_ACK()) {
                    // Check if the IP is already in the HashMap, if not add it and increment the SYN sent count by 1
                    if (hashmap.containsKey(FormatUtils.ip(ip.source()))) {
                        hashmap.get(FormatUtils.ip(ip.source()))[0]++;
                    } else {
                        hashmap.put(FormatUtils.ip(ip.source()), new int[2]);
                        hashmap.get(FormatUtils.ip(ip.source()))[0]++;
                    }
                    // If the SYN and ACK flags are set, this is a reply to a SYN packet and we keep track of the destination IP and the amount of packets received
                } else if (tcp.flags_SYN() && tcp.flags_ACK()) {
                    // Check if the IP is already in the HashMap, if not add it and increment the SYN/ACK received count by 1
                    if (hashmap.containsKey(FormatUtils.ip(ip.destination()))) {
                        hashmap.get(FormatUtils.ip(ip.destination()))[1]++;
                    } else {
                        hashmap.put(FormatUtils.ip(ip.destination()), new int[2]);
                        hashmap.get(FormatUtils.ip(ip.destination()))[1]++;
                    }
                }
            }
        }

        System.out.printf("Possible IP addresses which are performing a SYN scan attack:%n");
        // Iterate through all IP address in the HashMap
        for (String ipAddr : hashmap.keySet()) {
            // If an IP address sent three times as many SYN packet than SYN/ACKs than it received, print it because it is potentially malicious
            if (hashmap.get(ipAddr)[0] > (3 * hashmap.get(ipAddr)[1])) {
                System.out.printf("%s%n", ipAddr);
            }
        }
    }
}
