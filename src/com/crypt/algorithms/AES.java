package com.crypt.algorithms;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.plaf.synth.SynthTextAreaUI;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


// Implementation of the AES algorithm
public class AES {

    public static void crypt(String filePath, byte[] key, boolean isEncryption) {
        if (isEncryption) encrypt(filePath, key);
        else decrypt(filePath, key);

    }
    private static void encrypt(String filePath, byte[] key)  {

        try {

            Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");

            int aesBlockSize = aes.getBlockSize();
            byte[] toEncrypt = Utilities.readFile(filePath);
            byte[] iv = Utilities.getIV(aesBlockSize);

            // AES keys must be of size 16, 24, or 32
            byte[] keyMod = fixKey(key);

            SecretKeySpec keySpec = new SecretKeySpec(keyMod, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            aes.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            int numPadding = aesBlockSize - (toEncrypt.length % aesBlockSize);
            if (numPadding == aesBlockSize) numPadding = 0;

            // Copy input into pad-sized array. If it wasn't padded, we don't need to copy.
            byte[] paddedToEncrypt;
            if (numPadding == 0) {
                paddedToEncrypt = toEncrypt;
            } else {
                paddedToEncrypt = new byte[toEncrypt.length + numPadding];
                System.arraycopy(toEncrypt, 0, paddedToEncrypt, 0, toEncrypt.length);
            }

            // Do encryption
            byte[] encrypted = aes.doFinal(paddedToEncrypt);

            // write encrypted text to file then append to EOF the number of padding used followed by the IV used
            byte[] padAndIV = new byte[1 + iv.length];
            System.arraycopy(iv, 0, padAndIV, 1, iv.length);
            padAndIV[0] = (byte) numPadding;

            Utilities.writeFile(encrypted, filePath, Utilities.ENCRYPT);
            Utilities.writeDataAtOffset(padAndIV, filePath + Utilities.ENCRYPTED_EXTENSION, 0, true);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException |
                InvalidAlgorithmParameterException | InvalidKeyException e) {
            System.out.println("Encryption failed");
            e.printStackTrace();
        }
    }

    private static void decrypt(String filePath, byte[] key) {

        try {
            Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");

            int aesBlockSize = aes.getBlockSize();

            // Read num of padding and IV from the EOF, then truncate
            byte[] padAndIV = Utilities.readDataAtOffset(filePath, (1 + aesBlockSize), 0, true);

            int numPadding = padAndIV[0] & 0xFF;
            byte[] iv = new byte[aesBlockSize];
            System.arraycopy(padAndIV, 1, iv, 0, iv.length);

            Utilities.truncateDataAtEOF(padAndIV, filePath);

            // AES keys must be of size 16, 24, or 32
            byte[] keyMod = fixKey(key);

            SecretKeySpec keySpec = new SecretKeySpec(keyMod, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Do decryption
            byte[] toDecrypt = Utilities.readFile(filePath);
            aes.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = aes.doFinal(toDecrypt);

            // Un-pad if necessary
            byte[] decryptedUnpadded;
            if (numPadding == 0) {
                decryptedUnpadded = decrypted;
            } else {
                decryptedUnpadded = new byte[decrypted.length - numPadding];
                System.arraycopy(decrypted, 0, decryptedUnpadded, 0, decryptedUnpadded.length);
            }

            Utilities.writeFile(decryptedUnpadded, filePath, Utilities.DECRYPT);

        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException |
                InvalidAlgorithmParameterException | InvalidKeyException e) {
            System.out.println("Decryption failed");
            e.printStackTrace();
        }
    }

    /**
     * Simple key fix
     * @param key key of unknown length
     * @return new key of size 16, 24, or 32 bytes
     *        - Keys of smaller size are repeated to match up to closer size.
     *        - Keys of size > 32 bytes are truncated to 32
     */
    private static byte[] fixKey(byte[] key) {
        if (key.length == 16 || key.length == 24 || key.length == 32) return key;
        if (key.length > 32) return Arrays.copyOfRange(key, 0, 32);

        byte[] fixedKey;

        if (key.length < 16) fixedKey = new byte[16];
        else if (key.length < 24) fixedKey = new byte[24];
        else fixedKey = new byte[32];

        System.arraycopy(key, 0, fixedKey, 0, key.length);
        System.arraycopy(key, 0, fixedKey, key.length, fixedKey.length - key.length);

        return fixedKey;
    }
}
