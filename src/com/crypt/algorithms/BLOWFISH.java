package com.crypt.algorithms;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;


// Implementation of the Blowfish algorithm
public class BLOWFISH {

    public static void crypt(String filePath, String key, boolean isEncryption) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
        if (isEncryption) encrypt(filePath, key);
        else decrypt(filePath, key);

    }
    private static void encrypt(String filePath, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException {
        byte[] toEncrypt = Utilities.readFile(filePath);

        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "Blowfish");
        Cipher blowfish = Cipher.getInstance("Blowfish/CBC/NoPadding");

        byte[] iv = new byte[blowfish.getBlockSize()];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        blowfish.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

        byte[] paddedToEncrypt = new byte[toEncrypt.length + 16 - (toEncrypt.length % blowfish.getBlockSize())];
        int addedBytes = 16 - (toEncrypt.length % blowfish.getBlockSize());

        System.arraycopy(toEncrypt, 0, paddedToEncrypt, 0, toEncrypt.length);

        paddedToEncrypt[paddedToEncrypt.length - 1] = (byte) addedBytes;
        byte[] encrypted = blowfish.doFinal(paddedToEncrypt);

        byte[] toWrite = new byte[encrypted.length + blowfish.getBlockSize()];
        System.arraycopy(encrypted, 0, toWrite, 0, encrypted.length);
        System.arraycopy(iv, 0, toWrite, encrypted.length, iv.length);

        Utilities.writeFile(toWrite, filePath, Utilities.ENCRYPT);

        System.out.println("--");

    }

    private static void decrypt(String filePath, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException {

        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "Blowfish");
        Cipher blowfish = Cipher.getInstance("Blowfish/CBC/NoPadding");

        byte[] toDecryptFull = Utilities.readFile(filePath);

        byte[] iv = Arrays.copyOfRange(toDecryptFull, toDecryptFull.length - blowfish.getBlockSize(), toDecryptFull.length);
        byte[] toDecrypt = Arrays.copyOfRange(toDecryptFull, 0, toDecryptFull.length - iv.length);

        blowfish.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        byte[] decrypted = blowfish.doFinal(toDecrypt);

        int numPadding = decrypted[decrypted.length - 1] & 0xFF;
        byte[] decryptedUnpadded = new byte[decrypted.length - numPadding];
        System.arraycopy(decrypted, 0, decryptedUnpadded, 0, decryptedUnpadded.length);

        Utilities.writeFile(decryptedUnpadded, filePath, Utilities.DECRYPT);
    }
}
