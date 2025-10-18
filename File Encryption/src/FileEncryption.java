import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Scanner;

public class FileEncryption {

    private static final String ALGORITHM = "AES";

    // Default key file path
    private static final String KEY_FILE = "/Users/somesh/Side Hustle/File-Encryption-Tool/File Encryption/src/secret.key";

    // Key generation
    public static void generateKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            // 256-bit AES key
            keyGen.init(256, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            byte[] key = secretKey.getEncoded();

            Path keyPath = Paths.get(KEY_FILE);

            Files.createDirectories(keyPath.getParent());

            try (FileOutputStream fos = new FileOutputStream(keyPath.toFile())) {
                fos.write(key);
            }

            System.out.println("Key generated and saved in 'secret.key' file at:");
            System.out.println("  " + keyPath.toAbsolutePath());
        } catch (Exception e) {
            System.out.println("Error in generating key: " + e.getMessage());
        }
    }

    // Encrypt file
    public static void encryptFile(String inputFile, String outputFile) {
        try {
            Path keyPath = Paths.get(KEY_FILE);
            if (!Files.exists(keyPath)) {
                System.out.println("Key file not found. Please generate a key first (option 1).");
                return;
            }

            byte[] keyBytes = Files.readAllBytes(keyPath);
            SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            Path inPath = Paths.get(inputFile);
            if (!Files.exists(inPath)) {
                System.out.println("Input file not found: " + inPath.toAbsolutePath());
                return;
            }

            byte[] fileData = Files.readAllBytes(inPath);
            byte[] encryptedData = cipher.doFinal(fileData);

            Path outPath = Paths.get(outputFile);
            Files.createDirectories(outPath.getParent() == null ? outPath.toAbsolutePath().getParent() : outPath.getParent());
            try (FileOutputStream fos = new FileOutputStream(outPath.toFile())) {
                fos.write(encryptedData);
            }

            System.out.println("File encrypted successfully! Saved as " + outPath.toAbsolutePath());
        } catch (Exception e) {
            System.out.println("Error encrypting file: " + e.getMessage());
        }
    }

    // Decrypt file
     public static void decryptFile(String inputFile, String outputFile) {
        try {
            Path keyPath = Paths.get(KEY_FILE);
            if (!Files.exists(keyPath)) {
                System.out.println("Key file not found. Please generate a key first (option 1).");
                return;
            }

            byte[] keyBytes = Files.readAllBytes(keyPath);
            SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            Path inPath = Paths.get(inputFile);
            if (!Files.exists(inPath)) {
                System.out.println("Input file not found: " + inPath.toAbsolutePath());
                return;
            }

            byte[] encryptedData = Files.readAllBytes(inPath);
            byte[] decryptedData = cipher.doFinal(encryptedData);

            Path outPath = Paths.get(outputFile);
            Files.createDirectories(outPath.getParent() == null ? outPath.toAbsolutePath().getParent() : outPath.getParent());
            try (FileOutputStream fos = new FileOutputStream(outPath.toFile())) {
                fos.write(decryptedData);
            }

            System.out.println("File decrypted successfully! Saved as " + outPath.toAbsolutePath());
        } catch (Exception e) {
            System.out.println("Error decrypting file: " + e.getMessage());
        }
    }

    // User choice dispatcher
    public static String userChoice(int choice, Scanner scanner) {
        if (choice == 1) {
            generateKey();
        } else if (choice == 2) {
            System.out.print("Enter the file to encrypt (absolute or relative path): ");
            String inputFile = scanner.nextLine().trim();
            System.out.print("Enter the output file name (where encrypted data will be stored): ");
            String outputFile = scanner.nextLine().trim();
            encryptFile(inputFile, outputFile);
        } else if (choice == 3) {
            System.out.print("Enter the file to decrypt (absolute or relative path): ");
            String inputFile = scanner.nextLine().trim();
            System.out.print("Enter the output file name (where decrypted data will be stored): ");
            String outputFile = scanner.nextLine().trim();
            decryptFile(inputFile, outputFile);
        } else if (choice == 4) {
            return "Exiting... Goodbye!";
        } else {
            System.out.println("Invalid choice! Try again.");
        }
        return null;
    }

    public static void main(String[] args) {
        System.out.println("Welcome to File Encryption Tool!\n");
        System.out.println("Default key file location:");
        System.out.println("  " + Paths.get(KEY_FILE).toAbsolutePath());
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\nFile Encryption Tool");
            System.out.println("1. Generate Key");
            System.out.println("2. Encrypt a File");
            System.out.println("3. Decrypt a File");
            System.out.println("4. Exit");

            System.out.print("Enter your choice: ");
            String line = scanner.nextLine().trim();
            int choice;
            try {
                choice = Integer.parseInt(line);
            } catch (NumberFormatException e) {
                System.out.println("Please enter a numeric choice (1-4).");
                continue;
            }

            String option = userChoice(choice, scanner);
            if (option != null && option.equals("Exiting... Goodbye!")) {
                System.out.println(option);
                break;
            }
        }
        scanner.close();
    }
}
