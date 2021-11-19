package matula;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
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

    private static void decrypt(Scanner scanner) {
        String variation = getVariation(scanner);

        System.out.println("Zadejte tajný klíč:");
        String key = scanner.next();

        System.out.println("Zadejte inicializační vektor:");
        String iv = scanner.next();
    }

    private static void encrypt(Scanner scanner) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        IvParameterSpec ivspec = new IvParameterSpec(getRandomIV());
        System.out.println(ivspec);

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

        System.out.println("Tajný klíč je: " + key);

        String variation = getVariation(scanner);

        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/" + variation + "/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);

        System.out.println("Zadejte slovo k zašifrování");
        String wordToEncrypt = scanner.next();

        System.out.println("Zašifrované slovo: " + Base64.getEncoder().encodeToString(cipher.doFinal(wordToEncrypt.getBytes(StandardCharsets.UTF_8))));
    }

    private static String getVariation(Scanner scanner) {
        System.out.println("Vyberte režím AES");
        System.out.println("1. CBC");
        System.out.println("2. CFB");
        String variation;
        while (true) {
            variation = scanner.next();
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
            key = scanner.next();
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
