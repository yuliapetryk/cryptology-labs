import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DES {
    private static Parametrs param;
    static Utils utils;

    public DES(){
        param = new Parametrs();
        utils = new Utils();
    }

    public static List<Integer> generateSubkeys(String originalKey) {
        List<Integer> subkeys = new ArrayList<>();
        StringBuilder permutedKey = new StringBuilder();
        for (int i = 0; i < 56; i++) {
            permutedKey.append(originalKey.charAt(param.PC1[i]));
        }

        String leftPart = permutedKey.substring(0, 28);
        String rightPart = permutedKey.substring(28, 56);

        for (int round = 0; round < 16; round++) {
            for (int rotation = 0; rotation < param.LEFT_ROTATIONS[round]; rotation++) {
                leftPart = leftPart.substring(1) + leftPart.charAt(0);
                rightPart = rightPart.substring(1) + rightPart.charAt(0);
            }
            String combinedParts = leftPart + rightPart;

            StringBuilder roundKey = new StringBuilder();
            for (int i = 0; i < 48; i++) {
                roundKey.append(combinedParts.charAt(param.PC2[i]));
            }

            for (int i = 0; i < 48; i++) {
                subkeys.add(Character.getNumericValue(roundKey.charAt(i)));
            }
        }

        return subkeys;
    }

    public static List<Integer> encrypt(List<Integer> initializationVector, String plaintext, String keyHex) {
        List<Integer> binaryKey = convertHexToBinaryList(keyHex);
        List<Integer> binaryPlaintext = convertTextToBinaryList(plaintext);

        int blockCount = binaryPlaintext.size() / 64;
        int remainingBits = binaryPlaintext.size() % 64;

        List<Integer> previousBlock = new ArrayList<>(initializationVector);
        List<Integer> cipherText = new ArrayList<>();

        for (int i = 0; i < blockCount; i++) {
            List<Integer> block = binaryPlaintext.subList(i * 64, (i + 1) * 64);
            List<Integer> xorResult = xorBlocks(previousBlock, block);
            List<Integer> encryptedBlock = desEncryptBlock(xorResult, binaryKey);
            cipherText.addAll(encryptedBlock);
            previousBlock = new ArrayList<>(encryptedBlock);
        }

        if (remainingBits != 0) {
            blockCount++;
            List<Integer> lastBlock = new ArrayList<>(binaryPlaintext.subList(binaryPlaintext.size() - remainingBits, binaryPlaintext.size()));
            int paddingSize = 64 - remainingBits;
            List<Integer> padding = new ArrayList<>(Collections.nCopies(paddingSize, 0));
            lastBlock.addAll(padding);

            List<Integer> xorResult = xorBlocks(previousBlock, lastBlock);
            List<Integer> encryptedBlock = desEncryptBlock(xorResult, binaryKey);
            cipherText.addAll(encryptedBlock);
        }

        return convertBinaryToAscii(cipherText);
    }

    public static List<Integer> f(List<Integer> rightPart, List<Integer> keys) {
        List<Integer> rightPartExt = new ArrayList<>(48);
        for (int i = 0; i < 48; i++) {
            rightPartExt.add(rightPart.get(param.EXP[i]));
        }

        List<Integer> xorResult = new ArrayList<>(48);
        for (int j = 0; j < 48; j++) {
            xorResult.add(rightPartExt.get(j) ^ keys.get(j));
        }

        List<Integer> afterSBox = new ArrayList<>(32);
        for (int j = 0; j < 8; j++) {
            List<Integer> sixBits = xorResult.subList(j * 6, (j + 1) * 6);
            int bits1And6 = (sixBits.get(0) << 1) | sixBits.get(5);
            int bits2To5 = (sixBits.get(1) << 3) | (sixBits.get(2) << 2) | (sixBits.get(3) << 1) | sixBits.get(4);
            int foundInt = param.S_BOX[j][bits1And6 * 16 + bits2To5];
            String binaryString = String.format("%4s", Integer.toBinaryString(foundInt)).replace(' ', '0');
            for (char c : binaryString.toCharArray()) {
                afterSBox.add(Character.getNumericValue(c));
            }
        }

        List<Integer> result = new ArrayList<>(32);
        for (int i = 0; i < 32; i++) {
            result.add(afterSBox.get(param.P[i]));
        }

        return result;
    }
    public static List<Integer> encryptBlock(List<Integer> plaintext_64, List<Integer> key_64) {
        List<Integer> subkeys = generateSubkeys(utils.listToString(key_64));
        List<Integer> iptext = new ArrayList<>(plaintext_64);

        for (int i = 0; i < 64; i++) {
            iptext.set(i, plaintext_64.get(param.IP[i]));
        }
        List<Integer> L = iptext.subList(0, 32);
        List<Integer> R = iptext.subList(32, 64);

        for (int i = 0; i < 16; i++) {
            List<Integer> f_result = f(R, subkeys.subList(i * 48, (i + 1) * 48));
            List<Integer> C = new ArrayList<>(R);
            for (int q = 0; q < 32; q++) {
                R.set(q, L.get(q) ^ f_result.get(q));
            }
            L = new ArrayList<>(C);
        }

        List<Integer> res = new ArrayList<>(R);
        res.addAll(L);
        List<Integer> fptext = new ArrayList<>(res);
        for (int i = 0; i < 64; i++) {
            fptext.set(i, res.get(param.FP[i]));
        }

        return fptext;
    }

    private static List<Integer> convertHexToBinaryList(String hex) {
        List<Integer> binaryList = new ArrayList<>();
        for (char c : Utils.hexToBin(hex).toCharArray()) {
            binaryList.add(Character.getNumericValue(c));
        }
        return binaryList;
    }

    private static List<Integer> convertTextToBinaryList(String text) {
        List<Integer> binaryList = new ArrayList<>();
        for (char c : text.toCharArray()) {
            for (char bit : Utils.charToBinary(c).toCharArray()) {
                binaryList.add(Character.getNumericValue(bit));
            }
        }
        return binaryList;
    }

    private static List<Integer> xorBlocks(List<Integer> block1, List<Integer> block2) {
        List<Integer> xorResult = new ArrayList<>();
        for (int i = 0; i < block1.size(); i++) {
            xorResult.add(block1.get(i) ^ block2.get(i));
        }
        return xorResult;
    }

    private static List<Integer> desEncryptBlock(List<Integer> block, List<Integer> key) {
        return DES.encryptBlock(block, key);
    }

    private static List<Integer> convertBinaryToAscii(List<Integer> binaryList) {
        List<Integer> asciiList = new ArrayList<>();
        for (int i = 0; i < binaryList.size() - 7; i += 8) {
            StringBuilder binaryString = new StringBuilder();
            for (int j = 0; j < 8; j++) {
                binaryString.append(binaryList.get(i + j));
            }
            int asciiValue = Integer.parseInt(binaryString.toString(), 2);
            asciiList.add(asciiValue);
        }
        return asciiList;
    }


    public static String decrypt(List<Integer> IV, List<Integer> ciphertext, String keyHexa) {
        List<Integer> binaryKey = new ArrayList<>();
        for (char c : Utils.hexToBin(keyHexa).toCharArray()) {
            binaryKey.add(Character.getNumericValue(c));
        }

        List<Integer> binaryCiphertextArray = convertCiphertextToBinary(ciphertext);

        int blockNumber = binaryCiphertextArray.size() / 64;

        List<Integer> initVector = new ArrayList<>(IV);
        List<Integer> text = new ArrayList<>();
        for (int i = 0; i < blockNumber; i++) {
            List<Integer> block = binaryCiphertextArray.subList(i * 64, (i + 1) * 64);
            List<Integer> textBlock = decryptBlock(block, binaryKey);
            List<Integer> xorResult = performXOR(initVector, textBlock);
            text.addAll(xorResult);
            initVector = new ArrayList<>(block);
        }

        return convertBinaryToText(text);
    }

    public static List<Integer> decryptBlock(List<Integer> ciphertextBlock, List<Integer> binaryKey) {
        List<Integer> initialPermutation = performInitialPermutation(ciphertextBlock);

        List<Integer> L = initialPermutation.subList(0, 32);
        List<Integer> R = initialPermutation.subList(32, 64);
        List<Integer> subkeys = generateSubkeys(utils.listToString(binaryKey));

        for (int i = 15; i >= 0; i--) {
            List<Integer> fResult = f(R, subkeys.subList(i * 48, (i + 1) * 48));
            List<Integer> C = new ArrayList<>(R);
            for (int q = 0; q < 32; q++) {
                R.set(q, L.get(q) ^ fResult.get(q));
            }
            L = new ArrayList<>(C);
        }

        List<Integer> res = new ArrayList<>(R);
        res.addAll(L);

        List<Integer> finalResult = new ArrayList<>();
        for (int i = 0; i < 64; i++) {
            finalResult.add(res.get(param.FP[i]));
        }

        return finalResult;
    }

    private static List<Integer> performInitialPermutation(List<Integer> ciphertextBlock) {
        List<Integer> initialPermutation = new ArrayList<>();
        for (int i = 0; i < 64; i++) {
            initialPermutation.add(ciphertextBlock.get(param.IP[i]));
        }
        return initialPermutation;
    }

    private static List<Integer> convertCiphertextToBinary(List<Integer> ciphertext) {
        List<Integer> binaryCiphertextArray = new ArrayList<>();
        for (int i : ciphertext) {
            for (char bit : Utils.charToBinary((char) i).toCharArray()) {
                binaryCiphertextArray.add(Character.getNumericValue(bit));
            }
        }
        return binaryCiphertextArray;
    }

    private static List<Integer> performXOR(List<Integer> initVector, List<Integer> textBlock) {
        List<Integer> result = new ArrayList<>();
        for (int i = 0; i < initVector.size(); i++) {
            result.add(initVector.get(i) ^ textBlock.get(i));
        }
        return result;
    }

    private static String convertBinaryToText(List<Integer> binaryList) {
        StringBuilder textBuilder = new StringBuilder();
        StringBuilder currentBlock = new StringBuilder();
        for (int i = 0; i < binaryList.size() - 7; i += 8) {
            StringBuilder binaryString = new StringBuilder();
            for (int j = 0; j < 8; j++) {
                binaryString.append(binaryList.get(i + j));
            }
            int asciiValue = Integer.parseInt(binaryString.toString(), 2);

            if (asciiValue != 0) {
                currentBlock.append((char) asciiValue);
            } else if (!currentBlock.isEmpty()) {
                textBuilder.append(currentBlock).append(" ");
                currentBlock.setLength(0);
            }
        }

        if (!currentBlock.isEmpty()) {
            textBuilder.append(currentBlock);
        }

        int lastIndex = textBuilder.length() - 1;
        if (textBuilder.charAt(lastIndex) == ' ') {
            textBuilder.deleteCharAt(lastIndex);
        }

        return textBuilder.toString();
    }


}
