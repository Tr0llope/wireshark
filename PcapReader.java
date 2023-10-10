package wireshark;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class PcapReader {

    public static void main(String[] args) {
        // Spécifiez le chemin complet du fichier pcap
        String filePath = "chemin/vers/le/fichier.pcap";

        try {
            readPcapFile(filePath);
        } catch (IOException e) {
            e.printStackTrace();
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
            while (dataInputStream.available() > 0) {
                // En-tête du paquet pcap (16 octets)
                byte[] packetHeader = new byte[16];
                dataInputStream.readFully(packetHeader);

                // Taille du paquet (en octets)
                int packetSize = ((packetHeader[12] & 0xFF) << 24) | ((packetHeader[13] & 0xFF) << 16)
                        | ((packetHeader[14] & 0xFF) << 8) | (packetHeader[15] & 0xFF);

                // Données du paquet
                byte[] packetData = new byte[packetSize];
                dataInputStream.readFully(packetData);

                // Affichage des informations du paquet en hexadécimal
                System.out.println("Packet " + packetNumber + " (Hex):");
                printHex(packetHeader);
                printHex(packetData);

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
