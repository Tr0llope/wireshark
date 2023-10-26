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
                return "Unknown Host"; // Handle the exception appropriately in your code
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
                return null; // Handle the exception appropriately in your code
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
}