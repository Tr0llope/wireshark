public class Parser {
    Interpreter interpreter;
    public Parser() {
        this.interpreter = new Interpreter();
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

        System.out.print("\u001B[1mIPv6:\u001B[0m");
        System.out.print(" Next header: " + interpreter.getProtocol(protocol));
        System.out.print(" Source IP: " + interpreter.getIpv6(srcIpv6));
        System.out.println(" Destination IP: " + interpreter.getIpv6(destIpv6));

        return interpreter.getProtocol(protocol);
    }

    public String[] tcp(byte[] packetData){
        byte[] sourcePort = {packetData[34], packetData[35]};
        int sourcePortInt = ((sourcePort[0] & 0xFF)<<8) | ((sourcePort[1] & 0xFF));
        String sourcePortString = String.format("%04X", ((sourcePort[0] & 0xFF)<<8) | ((sourcePort[1] & 0xFF)));
        byte[] destinationPort = {packetData[36], packetData[37]};
        int destinationPortInt = ((destinationPort[0] & 0xFF)<<8) | ((destinationPort[1] & 0xFF));
        String destinationPortString = String.format("%04X", ((destinationPort[0] & 0xFF)<<8) | ((destinationPort[1] & 0xFF)));
        byte[] sequenceNumber = {packetData[38], packetData[39], packetData[40], packetData[41]};
        int sequenceNumberInt = ((sequenceNumber[0] & 0xFF)<<24) | ((sequenceNumber[1] & 0xFF)<<16) | ((sequenceNumber[2] & 0xFF)<<8) | ((sequenceNumber[3] & 0xFF));
        byte[] acknowledgementNumber = {packetData[42], packetData[43], packetData[44], packetData[45]};
        int acknowledgementNumberInt = ((acknowledgementNumber[0] & 0xFF)<<24) | ((acknowledgementNumber[1] & 0xFF)<<16) | ((acknowledgementNumber[2] & 0xFF)<<8) | ((acknowledgementNumber[3] & 0xFF));
        byte headerLength = (byte) ((packetData[46] & 0xF0) >> 4);
        byte[] flags = {packetData[47], packetData[48]};
        String flagsString = String.format("%04X", flags[0], flags[1]);

        System.out.print("\u001B[1mTCP:\u001B[0m");
        System.out.print(" Source port: " + String.format("%d",sourcePortInt));
        System.out.print(" Destination port: " + String.format("%d",destinationPortInt));
        System.out.print(" Sequence number: " + String.format("%d",sequenceNumberInt));
        System.out.print(" Acknowledgement number: " + String.format("%d",acknowledgementNumberInt));
        System.out.print(" Header length: " + headerLength);
        System.out.println(" Flags: " + flagsString);
        String [] tab = {sourcePortString, destinationPortString, flagsString};
        return tab;
    }

    public void http(byte[] packetData, boolean isreponse){
        String type;
        System.out.print("\u001B[1mHTTP:\u001B[0m");
        byte[] requestmethod = {packetData[54], packetData[55], packetData[56], packetData[57], packetData[58], packetData[59], packetData[60], packetData[61], packetData[62]};
        String requestmethodString = new String(requestmethod);
        if(isreponse){
            type = "(Response)";
            byte[] statusCode = {packetData[63], packetData[64], packetData[65]};
            String statusCodeString = new String(statusCode);
            byte[] responsePhrase = {packetData[67], packetData[68]};
            String responsePhraseString = new String(responsePhrase);

            System.out.print(" " + type );
            System.out.print(" Status code: " + statusCodeString);
            System.out.println(" Response phrase: " + responsePhraseString);

        } else {
            type = "(Request)";
            requestmethod = new byte[]{packetData[54], packetData[55], packetData[56]};//54/61
            requestmethodString = new String(requestmethod);
            //byte[] requestURI = {packetData[58], packetData[59], packetData[60], packetData[61], packetData[62], packetData[63], packetData[64], packetData[65], packetData[66], packetData[67], packetData[68], packetData[69], packetData[70], packetData[71], packetData[72], packetData[73], packetData[74]};//58 to 73
            byte[] requestURI = new byte[16];
            for (int i = 58, j = 0; i < 74 && j < requestURI.length; i++, j++) {
                requestURI[j] = packetData[i];
            }
            String requestURIString = new String(requestURI);
            byte[] userAgent = new byte[28];
            for(int i = 104, j = 0; i < 132 && j < userAgent.length; i++, j++){
                userAgent[j] = packetData[i];
            }
            String userAgentString = new String(userAgent);
            byte[] host = new byte[31];
            for(int i = 132, j = 0; i < 163 && j < host.length; i++, j++){
                host[j] = packetData[i];
            }
            String hostString = new String(host);

            System.out.print(" " + type );
            System.out.print(" Method: " + requestmethodString);
            System.out.print(" URI: " + requestURIString);
            System.out.print(" " + userAgentString);
            System.out.print(" " + hostString);
        }

    }

    public String[] udp(byte[] packetData){
        byte[] sourcePort = {packetData[54], packetData[55]};
        int sourcePortInt = ((sourcePort[0] & 0xFF)<<8) | ((sourcePort[1] & 0xFF));
        String sourcePortString = String.format("%d",sourcePortInt);

        byte[] destinationPort = {packetData[56], packetData[57]};
        int destinationPortInt = ((destinationPort[0] & 0xFF)<<8) | ((destinationPort[1] & 0xFF));
        String destinationPortString = String.format("%d",destinationPortInt);

        byte[] length = {packetData[58], packetData[59]};
        int lengthInt = ((length[0] & 0xFF)<<8) | ((length[1] & 0xFF));
        
        System.out.print("\u001B[1mUDP:\u001B[0m");
        System.out.print(" Source port: " + sourcePortString);
        System.out.print(" Destination port: " + destinationPortString);
        System.out.println(" Length: " + String.format("%d",lengthInt));
        String [] tab = {sourcePortString, destinationPortString};
        return tab;
    }

    public void icmp(byte[] packetData){
        byte type = packetData[34];
        byte code = packetData[35];
        byte[] checksum = {packetData[36], packetData[37]};
        String checksumString = String.format("%04X", ((checksum[0] & 0xFF)<<8) | ((checksum[1] & 0xFF)));

        System.out.print("\u001B[1mICMP:\u001B[0m");
        System.out.print(" Type: " + type);
        System.out.print(" Code: " + code);
        System.out.println(" Checksum: " + checksumString);
    }

    public void dns(byte[] packetData){
        Interpreter interpreter = new Interpreter();
        byte[] transactionID = {packetData[62], packetData[63]};
        String transactionIDString = String.format("%04X", ((transactionID[0] & 0xFF)<<8) | ((transactionID[1] & 0xFF)));
        byte[] flags = {packetData[64], packetData[65]};
        String flagsString = String.format("%04X", ((flags[0] & 0xFF)<<8) | ((flags[1] & 0xFF)));
        byte[] questions = {packetData[66], packetData[67]};
        String questionsString = String.format("%04X", ((questions[0] & 0xFF)<<8) | ((questions[1] & 0xFF)));
        byte[] answerRRs = {packetData[68], packetData[69]};
        String answerRRsString = String.format("%04X", ((answerRRs[0] & 0xFF)<<8) | ((answerRRs[1] & 0xFF)));
        byte[] authorityRRs = {packetData[70], packetData[71]};
        String authorityRRsString = String.format("%04X", ((authorityRRs[0] & 0xFF)<<8) | ((authorityRRs[1] & 0xFF)));
        byte[] additionalRRs = {packetData[72], packetData[73]};
        String additionalRRsString = String.format("%04X", ((additionalRRs[0] & 0xFF)<<8) | ((additionalRRs[1] & 0xFF)));

        System.out.print("\u001B[1mDNS:\u001B[0m");
        System.out.print(" Transaction ID: " + transactionIDString);
        System.out.print(" Flags: " + flagsString);
        System.out.print(" Questions: " + questionsString);
        System.out.print(" Answer RRs: " + answerRRsString);
        System.out.print(" Authority RRs: " + authorityRRsString);
        System.out.print(" Additional RRs: " + additionalRRsString);

        if(questionsString.equals("0001")){
            byte[] queryName = new byte[14];
            for(int i = 75, j = 0; i < 89 && j < queryName.length; i++, j++){
                queryName[j] = packetData[i];
            }
            String queryNameString = new String(queryName);
            byte[] queryType = {packetData[89], packetData[90]};
            String queryTypeString = String.format("%04X", ((queryType[0] & 0xFF)<<8) | ((queryType[1] & 0xFF)));
            byte[] queryClass = {packetData[91], packetData[92]};
            String queryClassString = String.format("%04X", ((queryClass[0] & 0xFF)<<8) | ((queryClass[1] & 0xFF)));

            System.out.print(" (Query) name: " + queryNameString);
            System.out.print(" type: " + queryTypeString);
            System.out.println(" class: " + queryClassString); 
        }
        

        if(answerRRsString.equals("0001")){
            byte[] answerType = {packetData[95], packetData[96]};
            String answerTypeString = String.format("%04X", ((answerType[0] & 0xFF)<<8) | ((answerType[1] & 0xFF)));
            byte[] answerClass = {packetData[97], packetData[98]};
            String answerClassString = String.format("%04X", ((answerClass[0] & 0xFF)<<8) | ((answerClass[1] & 0xFF)));
            byte[] answerTTL = {packetData[99], packetData[100], packetData[101], packetData[102]};
            int answerTTLInt = ((answerTTL[0] & 0xFF)<<24) | ((answerTTL[1] & 0xFF)<<16) | ((answerTTL[2] & 0xFF)<<8) | ((answerTTL[3] & 0xFF));
            
            System.out.print("(Answer) type: " + answerTypeString);
            System.out.print(" class: " + answerClassString);
            System.out.print(" TTL: " + String.format("%d",answerTTLInt));
            if(answerTypeString.equals("0001")){
                byte[] answerAddressv4 = {packetData[105], packetData[106], packetData[107], packetData[108]};
                System.out.println(" Address: " + interpreter.getIpv4(answerAddressv4));
            }else {
                byte[] answerAddressv6 = new byte[16];
                for(int i = 105, j = 0; i < 121 && j < answerAddressv6.length; i++, j++){
                    answerAddressv6[j] = packetData[i];
                }
                System.out.println(" Address: " + interpreter.getIpv6(answerAddressv6));
            }
            
        }
    }

    public void quic(byte[] packetData){
        byte[] version = {packetData[63], packetData[64], packetData[65], packetData[66]};
        String versionString = String.format("%04X", ((version[0] & 0xFF)<<24) | ((version[1] & 0xFF)<<16) | ((version[2] & 0xFF)<<8) | ((version[3] & 0xFF)));
        byte[] destinationConnectionID = new byte[8];
        String destinationConnectionIDString = "";
        for(int i = 68, j = 0; i < 76 && j < destinationConnectionID.length; i++, j++){
            destinationConnectionID[j] = packetData[i];
            destinationConnectionIDString += String.format("%02X", destinationConnectionID[j]);
        }
        
        byte sourceConnectionID = packetData[76];
        String sourceConnectionIDString = String.format("%02X", sourceConnectionID);

        System.out.print("\u001B[1mQUIC:\u001B[0m");
        System.out.print(" Version: " + versionString);
        System.out.print(" Destination connection ID: " + destinationConnectionIDString);
        System.out.println(" Source connection ID: " + sourceConnectionIDString);
    }


}
