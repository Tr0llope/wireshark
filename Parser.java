public class Parser {
    Interpreter interpreter;
    int start_index;
    
    public Parser() {
        this.interpreter = new Interpreter();
        this.start_index = 0;
    }

    public String ipv4(byte[] packetData){
        byte version = (byte) ((packetData[14] & 0xF0) >> 4);
        byte headerLength = (byte) (packetData[14] & 0x0F);
        byte[] totalLength = {packetData[16], packetData[17]};
        int totalLengthInt = ((totalLength[0] & 0xFF)<<8) | ((totalLength[1] & 0xFF));
        String totalLengthString = String.format("%d", totalLengthInt);
        byte flags = (byte) ((packetData[20] & 0xE0) >> 5);
        int timeToLive = (packetData[22] & 0xFF);
        byte protocol = packetData[23];
        byte[] sourceIp = {packetData[26], packetData[27], packetData[28], packetData[29]};
        byte[] destinationIp = {packetData[30], packetData[31], packetData[32], packetData[33]};
        
        start_index = 34;

        System.out.print("\u001B[1mIPv4:\u001B[0m");
        System.out.print(" Version: " + version);
        System.out.print(" Header length: " + headerLength);
        System.out.print(" Total length: " + totalLengthString);
        System.out.print(" Flags: " + flags);
        System.out.print(" Time to live: " + timeToLive);
        System.out.print(" Protocol: " + interpreter.getProtocol(protocol));
        System.out.print(" Source IP: " + interpreter.getIpv4(sourceIp));
        System.out.println(" Destination IP: " + interpreter.getIpv4(destinationIp));
        return interpreter.getProtocol(protocol);
    }

    public void arp(byte[] packetData){
        Interpreter interpreter = new Interpreter();
        byte[] hardwareType = {packetData[14], packetData[15]};
        byte[] protocolType = {packetData[16], packetData[17]};
        byte hardwareSize = packetData[18];
        

        byte protocolSize = packetData[19];
        

        byte[] opcode = {packetData[20], packetData[21]};
        byte[] senderMac = {packetData[22], packetData[23], packetData[24], packetData[25], packetData[26], packetData[27]};
        byte[] senderIp = {packetData[28], packetData[29], packetData[30], packetData[31]};
        byte[] targetMac = {packetData[32], packetData[33], packetData[34], packetData[35], packetData[36], packetData[37]};
        byte[] targetIp = {packetData[38], packetData[39], packetData[40], packetData[41]};

        System.out.print("\u001B[1mARP:\u001B[0m");
        System.out.print(" Hardware type: " + interpreter.getHardwareType(hardwareType));
        System.out.print(" Protocol type: " + interpreter.getPacketType(protocolType));
        System.out.print(" Hardware size: " + hardwareSize);
        System.out.print(" Protocol size: " + protocolSize);
        System.out.print(" Opcode: " + interpreter.getOpcode(opcode));
        System.out.print(" Sender MAC: " + interpreter.getMac(senderMac));
        System.out.print(" Sender IP: " + interpreter.getIpv4(senderIp));
        System.out.print(" Target MAC: " + interpreter.getMac(targetMac));
        System.out.println(" Target IP: " + interpreter.getIpv4(targetIp));
    }

    public String ethernet(byte[] packetData){
        Interpreter interpreter = new Interpreter();
        byte[] destinationMac = {packetData[0], packetData[1], packetData[2], packetData[3], packetData[4], packetData[5]};
        byte[] sourceMac = {packetData[6], packetData[7], packetData[8], packetData[9], packetData[10], packetData[11]};
        byte[] packetType = {packetData[12], packetData[13]};

        System.out.print("\u001B[1mEthernet:\u001B[0m");
        System.out.print(" Destination MAC: " + interpreter.getMac(destinationMac));
        System.out.print(" Source MAC: " + interpreter.getMac(sourceMac));
        System.out.println(" Type: " + interpreter.getPacketType(packetType));
        return interpreter.getPacketType(packetType);
    }

    public String ipv6(byte[] packetData){
        Interpreter interpreter = new Interpreter();
        byte protocol = packetData[20];
        byte[] srcIpv6 = new byte[16];
        for(int i = 22, j = 0; i < 38 && j < srcIpv6.length; i++, j++){
            srcIpv6[j] = packetData[i];
        }
        byte[] destIpv6 = new byte[16];
        for(int i = 38, j = 0; i < 54 && j < destIpv6.length; i++, j++){
            destIpv6[j] = packetData[i];
        }
        
        start_index = 54;

        System.out.print("\u001B[1mIPv6:\u001B[0m");
        System.out.print(" Next header: " + interpreter.getProtocol(protocol));
        System.out.print(" Source IP: " + interpreter.getIpv6(srcIpv6));
        System.out.println(" Destination IP: " + interpreter.getIpv6(destIpv6));

        return interpreter.getProtocol(protocol);
    }

    public String[] tcp(byte[] packetData){
        byte[] sourcePort = {packetData[start_index], packetData[start_index+1]};
        int sourcePortInt = ((sourcePort[0] & 0xFF)<<8) | ((sourcePort[1] & 0xFF));
        String sourcePortString = String.format("%04X", ((sourcePort[0] & 0xFF)<<8) | ((sourcePort[1] & 0xFF)));
        byte[] destinationPort = {packetData[start_index+2], packetData[start_index+3]};
        int destinationPortInt = ((destinationPort[0] & 0xFF)<<8) | ((destinationPort[1] & 0xFF));
        String destinationPortString = String.format("%04X", ((destinationPort[0] & 0xFF)<<8) | ((destinationPort[1] & 0xFF)));
        byte[] sequenceNumber = {packetData[start_index+4], packetData[start_index+5], packetData[start_index+6], packetData[start_index+7]};
        int sequenceNumberInt = ((sequenceNumber[0] & 0xFF)<<24) | ((sequenceNumber[1] & 0xFF)<<16) | ((sequenceNumber[2] & 0xFF)<<8) | ((sequenceNumber[3] & 0xFF));
        byte[] acknowledgementNumber = {packetData[start_index+8], packetData[start_index+9], packetData[start_index+10], packetData[start_index+11]};
        int acknowledgementNumberInt = ((acknowledgementNumber[0] & 0xFF)<<24) | ((acknowledgementNumber[1] & 0xFF)<<16) | ((acknowledgementNumber[2] & 0xFF)<<8) | ((acknowledgementNumber[3] & 0xFF));
        byte headerLength = (byte) ((packetData[start_index+12] & 0xF0) >> 4);
        byte[] flags = {packetData[start_index+13], packetData[start_index+14]};
        String flagsString = String.format("%04X", flags[0], flags[1]);
        start_index = start_index+20;

        System.out.print("\u001B[1mTCP:\u001B[0m");
        System.out.print(" Source port: " + String.format("%d",sourcePortInt));
        System.out.print(" Destination port: " + String.format("%d",destinationPortInt));
        System.out.print(" Sequence number: " + String.format("%d",sequenceNumberInt));
        System.out.print(" Acknowledgement number: " + String.format("%d",acknowledgementNumberInt));
        System.out.print(" Header length: " + headerLength);
        System.out.println(" Flags: " + interpreter.getTCPFlags(flagsString));
        String [] tab = {sourcePortString, destinationPortString, flagsString};
        return tab;
    }

    public void http(byte[] packetData, boolean isreponse){
        String type;
        System.out.print("\u001B[1mHTTP:\u001B[0m");
        if(isreponse){
            type = " (Response)";
            String[] data = interpreter.getHTTP(packetData, start_index);
            start_index = Integer.parseInt(data[1]);
            byte[] date = new byte[37];
            for(int i = start_index, j = 0; i < start_index+37 && j < date.length; i++, j++){
                date[j] = packetData[i];
            }

            String s = "";
            int i = start_index;
            while(i<packetData.length){
                if(packetData[i]==0x0D && packetData[i+1]==0x0A && packetData[i+2]==0x0D && packetData[i+3]==0x0A){
                    break;
                } else if(packetData[i]==0x0D && packetData[i+1]==0x0A) s+=" ";
                else s+=(char)packetData[i];
                i++;
            }

            System.out.print(type + " " + data[0]);
            System.out.println(s);

        } else {
            type = " (Request)";
            String[] data = interpreter.getHTTP(packetData, start_index);
            start_index = Integer.parseInt(data[1]);

            String s = "";
            int i = start_index;
            while(i<packetData.length){
                if(packetData[i]==0x0D && packetData[i+1]==0x0A && packetData[i+2]==0x0D && packetData[i+3]==0x0A){
                    break;
                } else if(packetData[i]==0x0D && packetData[i+1]==0x0A) s+=" ";
                else s+=(char)packetData[i];
                i++;
            }

            System.out.print(type + " " + data[0]);
            System.out.println(s);
        }

    }

    public String[] udp(byte[] packetData){
        byte[] sourcePort = {packetData[start_index], packetData[start_index+1]};
        int sourcePortInt = ((sourcePort[0] & 0xFF)<<8) | ((sourcePort[1] & 0xFF));
        String sourcePortString = String.format("%d",sourcePortInt);

        byte[] destinationPort = {packetData[start_index+2], packetData[start_index+3]};
        int destinationPortInt = ((destinationPort[0] & 0xFF)<<8) | ((destinationPort[1] & 0xFF));
        String destinationPortString = String.format("%d",destinationPortInt);

        byte[] length = {packetData[start_index+4], packetData[start_index+5]};
        int lengthInt = ((length[0] & 0xFF)<<8) | ((length[1] & 0xFF));
        
        start_index = start_index+8;
        
        System.out.print("\u001B[1mUDP:\u001B[0m");
        System.out.print(" Source port: " + sourcePortString);
        System.out.print(" Destination port: " + destinationPortString);
        System.out.println(" Length: " + String.format("%d",lengthInt));
        String [] tab = {sourcePortString, destinationPortString};
        return tab;
    }

    public void icmp(byte[] packetData){
        byte type = packetData[start_index];
        byte code = packetData[start_index+1];
        byte[] checksum = {packetData[start_index+2], packetData[start_index+3]};
        String checksumString = String.format("%04X", ((checksum[0] & 0xFF)<<8) | ((checksum[1] & 0xFF)));
        byte[] identifier = {packetData[start_index+4], packetData[start_index+5]};
        int identifierInt = ((identifier[0] & 0xFF)<<8) | ((identifier[1] & 0xFF));
        byte[] sequenceNumber = {packetData[start_index+6], packetData[start_index+7]};
        int sequenceNumberInt = ((sequenceNumber[0] & 0xFF)<<8) | ((sequenceNumber[1] & 0xFF));

        System.out.print("\u001B[1mICMP:\u001B[0m");
        System.out.print(" Type: " + interpreter.getICMPType(type));
        System.out.print(" Code: " + code);
        System.out.print(" Checksum: " + checksumString);
        System.out.print(" Identifier: " + identifierInt);
        System.out.println(" Sequence number: " + sequenceNumberInt);
    }

    public void dns(byte[] packetData){
        byte[] transactionID = {packetData[start_index], packetData[start_index+1]};
        String transactionIDString = String.format("%04X", ((transactionID[0] & 0xFF)<<8) | ((transactionID[1] & 0xFF)));
        byte[] flags = {packetData[start_index+2], packetData[start_index+3]};
        String flagsString = String.format("%04X", ((flags[0] & 0xFF)<<8) | ((flags[1] & 0xFF)));
        byte[] questions = {packetData[start_index+4], packetData[start_index+5]};
        String questionsString = String.format("%04X", ((questions[0] & 0xFF)<<8) | ((questions[1] & 0xFF)));
        byte[] answerRRs = {packetData[start_index+6], packetData[start_index+7]};
        String answerRRsString = String.format("%04X", ((answerRRs[0] & 0xFF)<<8) | ((answerRRs[1] & 0xFF)));
        byte[] authorityRRs = {packetData[start_index+8], packetData[start_index+9]};
        String authorityRRsString = String.format("%04X", ((authorityRRs[0] & 0xFF)<<8) | ((authorityRRs[1] & 0xFF)));
        byte[] additionalRRs = {packetData[start_index+10], packetData[start_index+11]};
        String additionalRRsString = String.format("%04X", ((additionalRRs[0] & 0xFF)<<8) | ((additionalRRs[1] & 0xFF)));

        System.out.print("\u001B[1mDNS:\u001B[0m");
        System.out.print(" Transaction ID: " + transactionIDString);
        System.out.print(" Flags: " + flagsString);
        System.out.print(" Questions: " + questionsString);
        System.out.print(" Answer RRs: " + answerRRsString);
        System.out.print(" Authority RRs: " + authorityRRsString);
        System.out.println(" Additional RRs: " + additionalRRsString);

        if(questionsString.equals("0001")){
            byte[] queryName = new byte[64];
            String[] name_index = interpreter.getDNSName(packetData, start_index);
            start_index = Integer.parseInt(name_index[1]);
            byte[] queryType = {packetData[start_index+1], packetData[start_index+2]};
            String queryTypeString = String.format("%04X", ((queryType[0] & 0xFF)<<8) | ((queryType[1] & 0xFF)));
            if(queryTypeString.equals("0001")){
                queryTypeString = "A (Ipv4 Address)";
            } else if(queryTypeString.equals("001C")){
                queryTypeString = "AAAA (Ipv6 Address)";
            }
            byte[] queryClass = {packetData[start_index+3], packetData[start_index+4]};//92
            String queryClassString = String.format("%04X", ((queryClass[0] & 0xFF)<<8) | ((queryClass[1] & 0xFF)));
            if(queryClassString.equals("0001")){
                queryClassString = "IN (Internet Address)";
            }

            System.out.print(" (Query) name: " + name_index[0]);
            System.out.print(" type: " + queryTypeString);
            System.out.println(" class: " + queryClassString); 
        }
        
        if(answerRRsString.equals("0001")){
            start_index +=6;
            byte[] answerType = {packetData[start_index+1], packetData[start_index+2]};
            String answerTypeString = String.format("%04X", ((answerType[0] & 0xFF)<<8) | ((answerType[1] & 0xFF)));
            if(answerTypeString.equals("0001")){
                answerTypeString = "A (Ipv4 Address)";
            } else if(answerTypeString.equals("001C")){
                answerTypeString = "AAAA (Ipv6 Address)";
            }
            byte[] answerClass = {packetData[start_index+3], packetData[start_index+4]};
            String answerClassString = String.format("%04X", ((answerClass[0] & 0xFF)<<8) | ((answerClass[1] & 0xFF)));
            if(answerClassString.equals("0001")){
                answerClassString = "IN (Internet Address)";
            }
            byte[] answerTTL = {packetData[start_index+5], packetData[start_index+6], packetData[start_index+7], packetData[start_index+8]};//102
            int answerTTLInt = ((answerTTL[0] & 0xFF)<<24) | ((answerTTL[1] & 0xFF)<<16) | ((answerTTL[2] & 0xFF)<<8) | ((answerTTL[3] & 0xFF));
           
            System.out.print("(Answer) type: " + answerTypeString);
            System.out.print(" class: " + answerClassString);
            System.out.print(" TTL: " + String.format("%d",answerTTLInt));
            if(answerTypeString.equals("A (Ipv4 Address)")){
                byte[] answerAddressv4 = new byte[4];
                for(int i = start_index+11, j = 0; i < start_index+15 && j < answerAddressv4.length; i++, j++){
                    answerAddressv4[j] = packetData[i];
                }
                System.out.println(" Address: " + interpreter.getIpv4(answerAddressv4));
            }else {
                byte[] answerAddressv6 = new byte[16];
                for(int i = start_index+11, j = 0; i < start_index+27 && j < answerAddressv6.length; i++, j++){
                    answerAddressv6[j] = packetData[i];
                }
                System.out.println(" Address: " + interpreter.getIpv6(answerAddressv6));
            }
            
        }
    }

    public void quic(byte[] packetData){
        byte[] version = {packetData[start_index], packetData[start_index+1], packetData[start_index+2], packetData[start_index+3]};
        String versionString = String.format("%04X", ((version[0] & 0xFF)<<24) | ((version[1] & 0xFF)<<16) | ((version[2] & 0xFF)<<8) | ((version[3] & 0xFF)));
        byte[] destinationConnectionID = new byte[8];
        String destinationConnectionIDString = "";
        for(int i = start_index+5, j = 0; i < start_index+13 && j < destinationConnectionID.length; i++, j++){
            destinationConnectionID[j] = packetData[i];
            destinationConnectionIDString += String.format("%02X", destinationConnectionID[j]);
        }
        
        byte sourceConnectionID = packetData[start_index+13];
        String sourceConnectionIDString = String.format("%02X", sourceConnectionID);
        
        start_index = start_index+13;

        System.out.print("\u001B[1mQUIC:\u001B[0m");
        System.out.print(" Version: " + versionString);
        System.out.print(" Destination connection ID: " + destinationConnectionIDString);
        System.out.println(" Source connection ID: " + sourceConnectionIDString);
    }

    public void dhcp(byte[] packetData){
        byte[] op = {packetData[start_index]};
        String opString = interpreter.getDHCPMethodName(String.format("%02X", op[0]));
        byte[] hwtype = {packetData[start_index+1]};
        String hwtypeString = interpreter.getHardwareType(hwtype);
        byte[] hwlen = {packetData[start_index+2]};
        String hwlenString = String.format("%02X", hwlen[0]);
        byte[] hops = {packetData[start_index+3]};
        String hopsString = String.format("%02X", hops[0]);
        byte[] transacID = {packetData[start_index+4], packetData[start_index+5], packetData[start_index+6], packetData[start_index+7]};
        String transacIDString = String.format("%02X", transacID[0]) + String.format("%02X", transacID[1]) + String.format("%02X", transacID[2]) + String.format("%02X", transacID[3]);
        byte[] secs = {packetData[start_index+8], packetData[start_index+9]};
        String secsString = String.format("%02X", secs[0]) + String.format("%02X", secs[1]);
        byte[] flags = {packetData[start_index+10], packetData[start_index+11]};
        String flagsString = String.format("%02X", flags[0]) + String.format("%02X", flags[1]);
        
        byte[] clientIP = {packetData[start_index+12], packetData[start_index+13], packetData[start_index+14], packetData[start_index+15]};
        String clientIPString = interpreter.getIpv4(clientIP);
        byte[] serverIP = {packetData[start_index+20], packetData[start_index+21], packetData[start_index+22], packetData[start_index+23]};
        String serverIPString = interpreter.getIpv4(serverIP);
        byte[] gatewayIP = {packetData[start_index+24], packetData[start_index+25], packetData[start_index+26], packetData[start_index+27]};
        String gatewayIPString = interpreter.getIpv4(gatewayIP);
        byte[] clientMAC = new byte[6];
        for(int i = start_index+28, j = 0; i < start_index+34 && j < clientMAC.length; i++, j++){
            clientMAC[j] = packetData[i];
        }
        String clientMACString = interpreter.getMac(clientMAC);
        start_index = start_index+44;
        byte[] serverHostname = new byte[64];
        byte[] bootFilename = new byte[128];
        start_index = start_index+192;
        byte[] magicCookie = {packetData[start_index], packetData[start_index+1], packetData[start_index+2], packetData[start_index+3]};
        String magicCookieString = String.format("%02X", magicCookie[0]) + String.format("%02X", magicCookie[1]) + String.format("%02X", magicCookie[2]) + String.format("%02X", magicCookie[3]);

        System.out.print("\u001B[1mDHCP:\u001B[0m");
        System.out.print(" Operation: " + opString);
        System.out.print(" Hardware type: " + hwtypeString);
        System.out.print(" Hardware length: " + hwlenString);
        System.out.print(" Hops: " + hopsString);
        System.out.print(" Transaction ID: " + transacIDString);
        System.out.print(" Seconds: " + secsString);
        System.out.print(" Flags: " + flagsString);
        System.out.print(" Client IP address: " + clientIPString);
        System.out.print(" Server IP address: " + serverIPString);
        System.out.print(" Gateway IP address: " + gatewayIPString);
        System.out.print(" Client hardware address: " + clientMACString);
        System.out.println(" Magic cookie: " + magicCookieString);

    }

    public void followtcpstream(byte[] packetData, String[] ports_flags){
        String sourcePort = ports_flags[0];
        String destinationPort = ports_flags[1];
        String flags = ports_flags[2];
        String data = "";
        int i = start_index;
        while(i<packetData.length){
            if(packetData[i]==0x0D && packetData[i+1]==0x0A && packetData[i+2]==0x0D && packetData[i+3]==0x0A){
                break;
            } else if(packetData[i]==0x0D && packetData[i+1]==0x0A) data+=" ";
            else data+=(char)packetData[i];
            i++;
        }
        System.out.println(data);
    }
}
