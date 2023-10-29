
import java.io.*;

public class PcapReader {

    public PcapReader() {
    }

    public void readPcapFile(String[] args, String filePath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(filePath);
             DataInputStream dataInputStream = new DataInputStream(fileInputStream)) {

            // En-tête du fichier pcap (24 octets)
            byte[] fileHeader = new byte[24];
            dataInputStream.readFully(fileHeader);

            int packetNumber = 1;
            int reading_limit = -1;
            if(args.length == 2 && args[1]!=null){
                reading_limit = Integer.parseInt(args[1]);
            }
            
            while (dataInputStream.available() >= 1 && (reading_limit<0 || packetNumber<=reading_limit)) {//Tant qu'il y a au moins un byte à lire ou que la limite n'est pas atteinte
                // En-tête du fichier pcap (16 octets)
                byte[] packetHeader = new byte[16];
                dataInputStream.readFully(packetHeader);

                int packetSize = (packetHeader[12] & 0xFF) |
                    ((packetHeader[13] & 0xFF) << 8) |
                    ((packetHeader[14] & 0xFF) << 16) |
                    ((packetHeader[15] & 0xFF) << 24);

                System.out.println("Frame " + packetNumber + ": Size =  " + packetSize + " bytes");

                // Données du paquet
                byte[] packetData = new byte[packetSize];
                if (dataInputStream.read(packetData) != packetSize) {
                    throw new IOException("Unable to read packet data");
                }
                Parser parser = new Parser();
                String packetType = parser.ethernet(packetData);
                switch (packetType) {
                    case "ARP":
                        parser.arp(packetData);
                        break;
                    case "IPv4":
                        String protocol = parser.ipv4(packetData);
                        switch (protocol) {
                            case "TCP":
                                String[] ports_flags = parser.tcp(packetData);
                                boolean isresponse = false;
                                if (ports_flags[2].equals("0018")) {
                                    if (ports_flags[0].equals("0050")) { //source port == 80
                                        isresponse = true;
                                        parser.http(packetData, isresponse);
                                    }
                                    else if (ports_flags[1].equals("0050")){
                                        parser.http(packetData, isresponse);
                                    } 
                                }
                                break;
                            case "ICMP":
                                parser.icmp(packetData);
                                break;
                            case "UDP":
                                String [] udpPorts = parser.udp(packetData);
                                if(udpPorts[1].equals("53") || udpPorts[0].equals("53")){
                                    parser.dns(packetData);
                                } else if(udpPorts[1].equals("443") || udpPorts[0].equals("443")){
                                    parser.quic(packetData);
                                }
                                break;
                            default:
                                break;
                        }
                        break;
                    case "IPv6":
                        String protocol6 = parser.ipv6(packetData);
                        switch(protocol6){
                            case "UDP":
                                String [] udpPorts = parser.udp(packetData);
                                if(udpPorts[1].equals("53") || udpPorts[0].equals("53")){
                                    parser.dns(packetData);
                                } else if(udpPorts[1].equals("443") || udpPorts[0].equals("443")){
                                    parser.quic(packetData);
                                }
                                break;
                            case "TCP":
                                parser.tcp(packetData);
                                break;
                        }
                        break;
                    default:
                        break;
                }
                System.out.println();
                packetNumber++;
                parser.start_index = 0;
            }
        }
    }
}
