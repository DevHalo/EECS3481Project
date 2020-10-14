package com.crypt.algorithms;
// import sun.security.krb5.KrbCryptoException;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/* Implementation of the AES algorithm */
/* The Advanced Encryption Standard is a standard encryption and decryption
 * Algorithm  that have been approved by the U.S. National Institute of Standards
 * and Technology in 2001. It's more secure than the previous standard DES (Data
 * Encryption Standard). AES is listed under the symmetric encryption methods.
 * Symmetric Encryption refers to algorithms that use the same key for encryption
 * as well as decryption. As such, the key should be kept secret and must be
 * exchanged between the encryptor and decryptor using a secure channel.
 * The AES processes block of 128 bits using a secret key of 128, 192, or 256 bits. */
public class AES {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    private static final String KEY = "AABBCCDDEEFFGGHH";
    private static final String IV = "AAACCCDDDYYUURRS";

    public static String readFile(String fileName) throws Exception {
        BufferedReader buffer = new BufferedReader(new FileReader(fileName));
        try {
            StringBuilder string = new StringBuilder();
            String row = buffer.readLine();
            while (row != null) {
                string.append(row);
                string.append(System.lineSeparator());
                row = buffer.readLine();
            }
            String all = string.toString();
            return all;
        } finally {
            buffer.close();
        }
    }

    /*** AES Encryption ***/
    public static String encryptAES(String key, String iv, String message) throws Exception {
        byte[] bytesofKey = key.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] keyBytes = md.digest(bytesofKey);
        final byte[] ivByte = iv.getBytes();

        /*** Creating a Key from a given byte array to AES Algorithm ***/
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

        /*** The instance of Cipher class for a given algorithm transformation ***/
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(ivByte));

        /*** Invoke the doFinal method from the Cipher class to perform encryption or
         * decryption on the input bytes ***/
        final byte[] result = cipher.doFinal(message.getBytes());
        /*** Input length must be multiple of 16 when decrypting so we use
         * Base64 library ***/
        return Base64.getMimeEncoder().encodeToString(result);
    }

    /*** AES Decryption ***/
    public static String decryptAES(String key, String iv, String encrypted) throws Exception {
        byte[] bytesofKey = key.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] keyBytes = md.digest(bytesofKey);

        final byte[] ivByte = iv.getBytes();
        final byte[] encryptedBytes = Base64.getMimeDecoder().decode(encrypted);

        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(ivByte));
        final byte[] result = cipher.doFinal(encryptedBytes);
        return new String(result);
    }

    private static void doCrypto(int cipherMode, String key, File inputFile, File outputFile) throws Exception {
        try {
            /*** Creating a Key from a given byte array to a given Algorithm ***/
            Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);

            /*** The instance of Cipher class for a given algorithm transformation ***/
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, secretKey);

            /*** Obtain the input bytes from the file using Java FileInputStream class ***/
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            /*** Invoke the doFinal method from the Cipher class to perform encryption or
             * decryption on the input bytes ***/
            byte[] outputBytes = cipher.doFinal(inputBytes);

            /*** Write the data to a file using Java FileOutputStream class ***/
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException
                | IOException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new Exception("Error Encryption/Decrypting File", ex);
        }
    }

    public static void encryptAES(String key, File inputFile, File outputFile) throws Exception {
        doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
    }

    public static void decryptAES(String key, File inputFile, File outputFile) throws Exception {
        doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
    }

    public static void test_encrypt_decrypt() throws Exception {
        /*** Encrypt the input file "test_text.txt" to another file "output.txt" ***/
        String s = readFile("test_text.txt");
        String res = encryptAES("mykey", IV, s);
        PrintWriter writer = new PrintWriter("output.txt", "UTF-8");
        writer.print(res);
        writer.close();

        /*** Decrypt the output file "output.txt" to another file "output2.txt" ***/
        s = readFile("output.txt");
        res = decryptAES("mykey", IV, s);
        writer = new PrintWriter("output2.txt", "UTF-8");
        writer.print(res);
        writer.close();
    }
}
