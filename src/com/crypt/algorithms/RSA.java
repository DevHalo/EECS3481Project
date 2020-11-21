package com.crypt.algorithms;

import javax.crypto.*;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

// Implementation of the RSA algorithm
public class RSA {
    public static void crypt(String fileName, byte[] key, boolean encrypt) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            KeyFactory kf = KeyFactory.getInstance("RSA");

            if (encrypt) {
                // Convert byte array to public key object
                X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));

                cipher.init(Cipher.ENCRYPT_MODE, kf.generatePublic(publicKeySpec));

                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(256);

                SecretKey AESkey = kg.generateKey();

                AES.crypt(fileName, AESkey.getEncoded(), true);

                // Encrypt AES key and append it to the file
                byte[] encryptedAES = cipher.doFinal(AESkey.getEncoded());

                FileOutputStream fs = new FileOutputStream(fileName + Utilities.ENCRYPTED_EXTENSION, true);
                fs.write(encryptedAES);
                fs.close();
            } else {
                // Convert byte array to private key object
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key));
                PrivateKey pk = kf.generatePrivate(privateKeySpec);

                cipher.init(Cipher.DECRYPT_MODE, pk);

                // Grab AES key that was appended at the end of the file
                byte[] encryptedAES = Utilities.readDataAtOffset(fileName,
                        ((RSAPrivateKey) pk).getModulus().bitLength() / 8, 0, true);

                // Decrypt AES key
                byte[] decryptedAES = cipher.doFinal(encryptedAES);

                // Truncate the AES key from the file
                Utilities.truncateDataAtEOF(encryptedAES, fileName);

                // Decrypt the file
                AES.crypt(fileName, decryptedAES, false);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates a RSA key pair
     * @param bits number of bits of the modulus portion
     * @return
     */
    public static KeyPair generateRSAPair(int bits) {
        try {
            KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
            kg.initialize(bits);
            return kg.generateKeyPair();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            noSuchAlgorithmException.printStackTrace();
        }

        return null;
    }
}
