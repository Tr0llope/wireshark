
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class PcapReader {

    public static void main(String[] args) {
        // Spécifiez le chemin complet du fichier pcap
        String filePath = args[0];

        try {
            readPcapFile(filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String mapPacketType(byte[] packetType) {
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

    private static void readPcapFile(String filePath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(filePath);
             DataInputStream dataInputStream = new DataInputStream(fileInputStream)) {

            // En-tête du fichier pcap (24 octets)
            byte[] fileHeader = new byte[24];
            dataInputStream.readFully(fileHeader);

            // Affichage de l'en-tête en hexadécimal
            System.out.println("File Header (Hex):");
            printHex(fileHeader);

            // Lecture des paquets pcap
            int packetNumber = 1;

            int bytesRead;
            while (dataInputStream.available() >= 16) {
                // En-tête du paquet pcap (16 octets)
                byte[] packetHeader = new byte[16];
                dataInputStream.readFully(packetHeader);

                int packetSize = (packetHeader[12] & 0xFF) |
                    ((packetHeader[13] & 0xFF) << 8) |
                    ((packetHeader[14] & 0xFF) << 16) |
                    ((packetHeader[15] & 0xFF) << 24);

                System.out.println("Taille: " + packetSize + " octets");

                // Données du paquet
                byte[] packetData = new byte[packetSize];
                if (dataInputStream.read(packetData) != packetSize) {
                    throw new IOException("Unable to read packet data");
                }


                byte [] packetType = {packetData[12], packetData[13]};

                // Affichage des informations du paquet en hexadécimal
                System.out.println("Packet " + packetNumber + " - Type: " + mapPacketType(packetType));
                //printHex(packetHeader);
                //printHex(packetData);

                packetNumber++;
            }
        }
    }

    private static void printHex(byte[] bytes) {
        for (byte b : bytes) {
            System.out.print(String.format("%02X ", b));
        }
        System.out.println();
    }
}
