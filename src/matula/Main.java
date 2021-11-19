package matula;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Zvolte režim:");
        System.out.println("1. Šifrování");
        System.out.println("2. Dešifrování");

        int type = scanner.nextInt();
        if (type == 1) {
            encrypt(scanner);
        } else if (type == 2) {
            decrypt(scanner);
        }
    }

    private static void decrypt(Scanner scanner) throws FileNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        String variation = getVariation(scanner);

        System.out.println("Zadejte tajný klíč:");
        String key = scanner.nextLine();

        System.out.println("Zadejte inicializační vektor:");
        byte[] ivAsBytes = getIvAsBytes(scanner);
        IvParameterSpec ivspec = new IvParameterSpec(ivAsBytes);

        System.out.println("Zadejte zašifrovaný text:");
        String word = scanner.nextLine();

        Cipher cipher = Cipher.getInstance("AES/" + variation + "/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(word));
        System.out.println("Dešifrovaný text: " + new String(plainText));
    }

    private static byte[] getIvAsBytes(Scanner scanner) throws FileNotFoundException {
        byte[] returned = new byte[16];

        System.out.println("Zadejte cestu k .txt souboru s inicializačním vektorem");
        StringBuilder data = new StringBuilder();
        while (true) {
            String path = scanner.nextLine();
            try {
                File myObj = new File(path);
                Scanner myReader = new Scanner(myObj);
                while (myReader.hasNextLine()) {
                    data.append(myReader.nextLine());
                }
                myReader.close();
                break;
            } catch (Exception ignored) {
                System.out.println("Soubor nebyl nalezen, zkuste zadat znovu");
            }
        }
        List<String> ivList;
        while (true) {
            if (data.toString().startsWith("[") && data.toString().endsWith("]")) {
                ivList = Arrays.asList(data.substring(1, data.length() - 1).split(", "));
            } else {
                System.out.println("Zadejte pole ve správném formátu - [čislo, číslo, číslo, ..., číslo]");
                continue;
            }
            if (ivList.size() == 16) {
                for (int i = 0; i < returned.length; i++) {
                    returned[i] = Byte.parseByte(ivList.get(i));
                }
                break;
            } else System.out.println("Pole je příliš krátké");
        }
        return returned;
    }

    private static void encrypt(Scanner scanner) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        IvParameterSpec ivspec = new IvParameterSpec(getRandomIV());

        BufferedWriter writer = new BufferedWriter(new FileWriter("iv.txt"));
        writer.write((Arrays.toString(ivspec.getIV())));
        writer.close();

        System.out.println("Zvolte délku šifrovacího klíče:");
        System.out.println("1. 128");
        System.out.println("2. 192");
        System.out.println("3. 256");

        int length = scanner.nextInt();
        String key;
        switch (length) {
            case 1:
                key = getDesiredBytesKey(scanner, 16);
                break;
            case 2:
                key = getDesiredBytesKey(scanner, 24);
                break;
            case 3:
                key = getDesiredBytesKey(scanner, 32);
                break;
            default:
                throw new IllegalArgumentException();
        }

        String variation = getVariation(scanner);

        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + variation + "/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

        System.out.println("Zadejte slovo k zašifrování");
        String wordToEncrypt = scanner.nextLine();

        System.out.println("Zašifrované slovo: " + Base64.getEncoder().encodeToString(cipher.doFinal(wordToEncrypt.getBytes(StandardCharsets.UTF_8))));
    }

    private static String getVariation(Scanner scanner) {
        System.out.println("Vyberte režím AES");
        System.out.println("1. CBC");
        System.out.println("2. CFB");
        String variation;
        while (true) {
            variation = scanner.nextLine();
            switch (variation) {
                case "1":
                    return "CBC";
                case "2":
                    return "CFB";
                default:
                    System.out.println("Zadejte 1 nebo 2");
            }
        }
    }

    private static String getDesiredBytesKey(Scanner scanner, int desiredBytes) {
        System.out.println("Napište klíč o délce " + desiredBytes + " znaků");
        String key;
        while (true) {
            key = scanner.nextLine();
            if (key.length() != desiredBytes) {
                System.out.println("Napsali jste " + key.length() + " znaky, zadejte klíč o délce " + desiredBytes + " znaků");
            } else break;
        }
        return key;
    }

    private static byte[] getRandomIV() {
        byte[] returned = new byte[16];
        new SecureRandom().nextBytes(returned);
        return returned;
    }
}
