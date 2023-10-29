import java.io.IOException;

public class Wireshark {
    public static void main(String[] args) {
        String filePath = args[0];

        try {
            PcapReader pcapReader = new PcapReader();
            pcapReader.readPcapFile(args, filePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
