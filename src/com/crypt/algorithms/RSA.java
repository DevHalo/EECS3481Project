package com.crypt.algorithms;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

// Implementation of the RSA algorithm
public class RSA {

    private static String publicKey;
    private static String privateKey;

    public static void createKeys() throws NoSuchAlgorithmException {
        Utilities.RSAKeyPairGenerator();
        publicKey = Base64.getEncoder().encodeToString(Utilities.getPublicKey().getEncoded());
        privateKey = Base64.getEncoder().encodeToString(Utilities.getPrivateKey().getEncoded());
    }

    public static PublicKey getPublicKey(String base64PublicKey){
        PublicKey publicKey = null;
        try{
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey(String base64PrivateKey){
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    public static byte[] encrypt(byte[] data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, String privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(privateKey));
        return cipher.doFinal(data);
    }

    public static void crypt(String fileName, byte[] startingKey, boolean encrypt) {
        try {
            // Read input bytes from file and initialize output array
            byte[] input = Utilities.readFile(fileName);
            byte[] output = new byte[input.length];
            if(encrypt)
            {
                output = encrypt(input , publicKey);
            }
            else
            {
                output = decrypt(input , privateKey);
            }
            // Write output to file
            Utilities.writeFile(output, fileName, encrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
