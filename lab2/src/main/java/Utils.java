import java.util.List;
import java.util.stream.Collectors;

public class Utils {
    public  String listToString(List<Integer> list) {
        return list.stream()
                .map(String::valueOf)
                .collect(Collectors.joining());
    }

    public static String hexToBin(String hexString) {
        StringBuilder binaryString = new StringBuilder();
        for (char hexChar : hexString.toCharArray()) {
            String binary = String.format("%4s", Integer.toBinaryString(Integer.parseInt(String.valueOf(hexChar), 16)))
                    .replace(' ', '0');
            binaryString.append(binary);
        }
        return binaryString.toString();
    }

    public static String charToBinary(char c) {
        return String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0');
    }
}