package com.crypt.algorithms;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


// Implementation of the Blowfish algorithm
public class BLOWFISH {

    public static void crypt(String filePath, byte[] key, boolean isEncryption) {
        if (isEncryption) encrypt(filePath, key);
        else decrypt(filePath, key);

    }
    private static void encrypt(String filePath, byte[] key)  {

        try {

            Cipher blowfish = Cipher.getInstance("Blowfish/CBC/NoPadding");

            int blowBlockSize = blowfish.getBlockSize();
            byte[] toEncrypt = Utilities.readFile(filePath);
            byte[] iv = Utilities.getIV(blowBlockSize);

            SecretKeySpec keySpec = new SecretKeySpec(key, "Blowfish");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            blowfish.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            int numPadding = blowBlockSize - (toEncrypt.length % blowBlockSize);
            if (numPadding == 8) numPadding = 0;

            // Copy input into pad-sized array. If it wasn't padded, we don't need to copy.
            byte[] paddedToEncrypt;
            if (numPadding == 0) {
                paddedToEncrypt = toEncrypt;
            } else {
                paddedToEncrypt = new byte[toEncrypt.length + numPadding];
                System.arraycopy(toEncrypt, 0, paddedToEncrypt, 0, toEncrypt.length);
            }

            // Do encryption
            byte[] encrypted = blowfish.doFinal(paddedToEncrypt);

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
            Cipher blowfish = Cipher.getInstance("Blowfish/CBC/NoPadding");

            int blowBlockSize = blowfish.getBlockSize();

            // Read num of padding and IV from the EOF, then truncate
            byte[] padAndIV = Utilities.readDataAtOffset(filePath, (1 + blowBlockSize), 0, true);

            int numPadding = padAndIV[0] & 0xFF;
            byte[] iv = new byte[blowBlockSize];
            System.arraycopy(padAndIV, 1, iv, 0, iv.length);

            Utilities.truncateDataAtEOF(padAndIV, filePath);

            SecretKeySpec keySpec = new SecretKeySpec(key, "Blowfish");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // Do decryption
            byte[] toDecrypt = Utilities.readFile(filePath);
            blowfish.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decrypted = blowfish.doFinal(toDecrypt);

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
}
