package wireshark;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class HexaScanner {
    public static void main(String[] args) {
        String filePath = "path/to/pcap/file.pcap";
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
    }
}
