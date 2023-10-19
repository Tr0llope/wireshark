import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

// print the content of a pcap file on the console

public class HexaScanner {
    public static void main(String[] args) {
        String filePath = "../arp2.pcap";
        try (DataInputStream inputStream = new DataInputStream(new FileInputStream(filePath))) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                for (int i = 0; i < bytesRead; i++) {
                    System.out.printf("%02X ", buffer[i]);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.print('\n');
    }
}
