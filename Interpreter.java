import java.net.*;
public class Interpreter {
    public Interpreter() {
    }

    public String getProtocol(byte protocol) {
        switch (protocol) {
                case 1:
                    return "ICMP";
                case 2:
                    return "IGMP";
                case 6:
                    return "TCP";
                case 17:
                    return "UDP";
                default:
                    return "Unknown";
            }
    }

    public String getPacketType(byte[] packetType) {
        String s = "";
        for (byte b : packetType) {
            s+=(String.format("%02X", b));
        }
        switch (s) {
            case "0800":
                return "IPv4";
            case "0806":
                return "ARP";
            case "86DD":
                return "IPv6";
            default:
                return "Unknown";
        }
    }

    public String getIpv4(byte[] ip) {
            try {
                if (ip.length == 4) {
                    InetAddress address = Inet4Address.getByAddress(ip);
                    return address.getHostAddress();
                } else if (ip.length == 16) {
                    InetAddress address = Inet6Address.getByAddress(null, ip, -1);
                    return address.getHostAddress();
                } else {
                    return "Invalid IP address length";
                }
            } catch (UnknownHostException e) {
                e.printStackTrace();
                return "Unknown Host";
            }
        }
    
    public String getHardwareType(byte[] hardwareType) {
            String s = "";
            for (byte b : hardwareType) {
                s+=(String.format("%02X", b));
            }
            switch (s) {
                case "0001":
                    return "Ethernet";
                case "01":
                    return "Ethernet";
                default:
                    return "Unknown";
            }
        }
    
    public String getIpv6(byte[] ip) {
            try {
                InetAddress address = Inet6Address.getByAddress(null, ip, -1);
                return address.getHostAddress();
            } catch (UnknownHostException e) {
                e.printStackTrace();
                return null;
            }
        }

    public String getMac(byte[] mac) {
            String s = "";
            for (byte b : mac) {
                s+=(String.format("%02X", b)) + ":";
            }
            return s.substring(0, s.length() - 1);
        }
    
    public String getOpcode(byte[] opcode) {
            String s = "";
            for (byte b : opcode) {
                s+=(String.format("%02X", b));
            }
            switch (s) {
                case "0001":
                    return "Request";
                case "0002":
                    return "Reply";
                default:
                    return "Unknown";
            }
        }
    
    public String getICMPType(byte type){
        switch (type) {
            case 0:
                return "Echo Reply";
            case 3:
                return "Destination Unreachable";
            case 4:
                return "Source Quench";
            case 5:
                return "Redirect";
            case 8:
                return "Echo Request";
            case 9:
                return "Router Advertisement";
            case 10:
                return "Router Solicitation";
            case 11:
                return "Time Exceeded";
            case 12:
                return "Parameter Problem";
            case 13:
                return "Timestamp";
            case 14:
                return "Timestamp Reply";
            case 15:
                return "Information Request";
            case 16:
                return "Information Reply";
            case 17:
                return "Address Mask Request";
            case 18:
                return "Address Mask Reply";
            default:
                return "Unknown";
        }
    }

    public String getTCPFlags(String flags){
        switch (flags) {
            case "0000":
                return "No flags";
            case "0001":
                return "FIN";
            case "0002":
                return "SYN";
            case "0004":
                return "RST";
            case "0008":
                return "PSH";
            case "0010":
                return "ACK";
            case "0018":
                return "PSH, ACK";
            case "0012":
                return "SYN, ACK";
            case "0011":
                return "FIN, ACK";
            case "0014":
                return "RST, ACK";
            default:
                return "Unknown";
        }
    }

    public String[] getDNSName(byte[] packetData, int start_index){
        String s = "";
        int i = start_index+12;
        while(i<packetData.length){
            int length = packetData[i];
            if(length==0) break;
            for(int j=1; j<=length; j++){
                s+=(char)packetData[i+j];
            }
            s+=".";
            i+=length+1;
        }
        String[] result = {s, Integer.toString(i)};
        return result;
    }

    public String[] getHTTP(byte[] packetData, int start_index){
        String s = "";
        int i = start_index;
        while(i<packetData.length){
            if(packetData[i]==0x0D && packetData[i+1]==0x0A){
                break;
            }
            if(packetData[i]!=0x20) s+=(char)packetData[i];
            else s+=" ";
            i++;
        }
        s+=" ";
        start_index=i+2;
        String[] result = {s, Integer.toString(start_index)};
        return result;
    }
   
    public String getDHCPMethodName(String name){
        switch (name) {
            case "01":
                return "Boot Request";
            case "02":
                return "Boot request";
            
            default:
                return "Unknown";
        }
    }
}
