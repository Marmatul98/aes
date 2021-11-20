package matula;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IllegalBlockSizeException, IOException, BadPaddingException {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Zvolte režim:");
        System.out.println("1. Šifrování");
        System.out.println("2. Dešifrování");

        int type = scanner.nextInt();
        scanner.nextLine();
        if (type == 1) {
            encrypt(scanner);
        } else if (type == 2) {
            decrypt(scanner);
        }
    }

    private static void decrypt(Scanner scanner) throws IllegalBlockSizeException, IOException, BadPaddingException {
        String variation = getVariation(scanner);

        System.out.println("Zadejte tajný klíč:");
        String key = scanner.nextLine();

        System.out.println("Zadejte inicializační vektor:");
        byte[] ivAsBytes = getIvAsBytes(scanner);
        IvParameterSpec ivspec = new IvParameterSpec(ivAsBytes);

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/" + variation + "/PKCS5Padding");
        } catch (Exception ignored) {
            System.out.println("Režim AES nebyl nalezen");
            System.exit(0);
        }
        try {
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
        } catch (Exception ignored) {
            System.out.println("Špatně zadaný klíč nebo inicializační vektor");
            System.exit(0);
        }

        decryptWord(scanner, cipher);
    }

    private static void decryptWord(Scanner scanner, Cipher cipher) throws IOException, IllegalBlockSizeException, BadPaddingException {
        int variation = getWordEntryVariation(scanner, "dešifrování");
        if (variation == 1) {
            System.out.println("Zadejte slovo k dešifrování: ");
            String wordToEncrypt = scanner.nextLine();
            byte[] decodedWord = Base64.getDecoder().decode(wordToEncrypt.getBytes());
            try {
                byte[] decrypted = cipher.doFinal(decodedWord);
                System.out.println("Dešifrované slovo: " + new String(decrypted));
            } catch (Exception ignored) {
                System.out.println("Nepodařilo se dešifrovat slovo");
            }
        } else {
            encryptOrDecryptFile(scanner, cipher, "decrypted");
        }
    }

    private static void encryptOrDecryptFile(Scanner scanner, Cipher cipher, String encryptedOrDecrypted) throws IOException, IllegalBlockSizeException, BadPaddingException {
        String decryptOrEncryptInCzech = "";
        String decryptOrEncryptInCzech2 = "";
        if (encryptedOrDecrypted.equals("encrypted")) {
            decryptOrEncryptInCzech = "zašifrování";
            decryptOrEncryptInCzech2 = "zašifrované";
        } else if (encryptedOrDecrypted.equals("decrypted")) {
            decryptOrEncryptInCzech = "dešifrování";
            decryptOrEncryptInCzech2 = "dešifrované";
        }

        System.out.println("Zadejte cestu k .txt souboru s textem k " + decryptOrEncryptInCzech);
        File file;
        while (true) {
            try {
                String path = scanner.nextLine();
                file = new File(path);
                break;
            } catch (Exception ignored) {
                System.out.println("Soubor nebyl nalezen, zkuste zadat znovu");
            }
        }
        FileInputStream inputStream = null;
        try {
            inputStream = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            System.out.println("Soubor nebyl nalezen, zkuste zadat znovu");
        }
        FileOutputStream outputStream = new FileOutputStream(encryptedOrDecrypted + ".txt");
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
        System.out.println("Slovo bylo " + decryptOrEncryptInCzech2 + " do souboru " + encryptedOrDecrypted + ".txt");
    }


    private static byte[] getIvAsBytes(Scanner scanner) {
        byte[] returned = new byte[16];

        System.out.println("Zadejte cestu k .txt souboru s inicializačním vektorem");
        String data = getTxtFile(scanner);
        List<String> ivList;
        while (true) {
            if (data.startsWith("[") && data.endsWith("]")) {
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

    private static void encrypt(Scanner scanner) throws IllegalBlockSizeException, IOException, BadPaddingException {
        IvParameterSpec ivspec = new IvParameterSpec(getRandomIV());

        try (BufferedWriter writer = new BufferedWriter(new FileWriter("iv.txt"))) {
            writer.write((Arrays.toString(ivspec.getIV())));
        } catch (Exception ignored) {
            System.out.println("Soubor s inicializačním vektorem se nepodařilo vytvořit");
            System.exit(0);
        }

        System.out.println("Do složky s .jar souborem byl vytvořen iv.txt soubor s inicializačním vektorem");

        System.out.println("Zvolte délku šifrovacího klíče:");
        System.out.println("1. 128");
        System.out.println("2. 192");
        System.out.println("3. 256");

        int length = scanner.nextInt();
        scanner.nextLine();
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

        SecretKeySpec secretKey = null;
        Cipher cipher = null;
        try {
            secretKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
            cipher = Cipher.getInstance("AES/" + variation + "/PKCS5Padding");
        } catch (Exception ignored) {
            System.out.println("Režim AES nebyl nalezen");
            System.exit(0);
        }

        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
        } catch (Exception ignored) {
            System.out.println("Nepodařilo se inicializovat šifrovací algoritmus");
            System.exit(0);
        }

        encryptWord(scanner, cipher);
    }

    private static void encryptWord(Scanner scanner, Cipher cipher) throws IOException, IllegalBlockSizeException, BadPaddingException {
        int variation = getWordEntryVariation(scanner, "zašifrování");
        if (variation == 1) {
            System.out.println("Zadejte text k zašifrování");
            String wordToEncrypt = scanner.nextLine();
            String encrypted = Base64.getEncoder().encodeToString(cipher.doFinal(wordToEncrypt.getBytes(StandardCharsets.UTF_8)));
            System.out.println("Zakódované slovo: " + encrypted);
        } else {
            encryptOrDecryptFile(scanner, cipher, "encrypted");
        }
    }

    private static String getTxtFile(Scanner scanner) {
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
        return data.toString();
    }

    private static int getWordEntryVariation(Scanner scanner, String encryptOrDecrypt) {
        System.out.println("Zvolte režim zádání slova k " + encryptOrDecrypt);
        System.out.println("1. Napsat do konzole");
        System.out.println("2. Vložit .txt soubor");
        int variation;
        while (true) {
            variation = scanner.nextInt();
            scanner.nextLine();
            switch (variation) {
                case 1:
                case 2:
                    return variation;
                default:
                    System.out.println("Zadejte 1 nebo 2");
            }
        }
    }

    private static String getVariation(Scanner scanner) {
        System.out.println("Vyberte režím AES");
        System.out.println("1. CBC");
        System.out.println("2. CFB");
        int variation;
        while (true) {
            variation = scanner.nextInt();
            scanner.nextLine();
            switch (variation) {
                case 1:
                    return "CBC";
                case 2:
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
