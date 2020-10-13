package com.crypt.algorithms;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

// Implementation of the Blowfish algorithm
public class BLOWFISH {

    public static final String BLOWFISH = "Blowfish";

    public static void crypt(String filePath, byte[] key, boolean isEncryption) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher blowfish;
        byte[] cryptString = Utilities.readFile(filePath);
        byte[] cryptedString;

            blowfish = Cipher.getInstance(BLOWFISH);
            SecretKeySpec cryptKey = new SecretKeySpec(key, BLOWFISH);
            blowfish.init(getCryptMode(isEncryption), cryptKey);
            cryptedString = blowfish.doFinal(cryptString);
            Utilities.writeFile(cryptedString, filePath, isEncryption);

    }
    private static int getCryptMode(boolean encryption) {
        if (encryption) return Cipher.ENCRYPT_MODE;
        else return Cipher.DECRYPT_MODE;
    }
}
