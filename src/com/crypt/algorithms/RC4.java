package com.crypt.algorithms;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

// Implementation of the RC4 algorithm
public class RC4 {

    public static void crypt(String fileName, byte[] startingKey, boolean encrypt) {
        try {
            Cipher cipher = Cipher.getInstance("ARCFOUR");
            SecretKeySpec key = new SecretKeySpec(startingKey, cipher.getAlgorithm());

            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);

            byte[] input = Utilities.readFile(fileName);
            byte[] output = cipher.doFinal(input);

            Utilities.writeFile(output, fileName, encrypt);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }
}
