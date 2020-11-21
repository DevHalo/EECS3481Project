package com.crypt.algorithms;

import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

// Implementation of the ECC algorithm
public class ECC {
    public static void crypt(String filePath, byte[] privateKey, byte[] publicKey, boolean encrypt) {
        try {
            // Convert byte arrays to private and public key objects
            KeyFactory kf = KeyFactory.getInstance("EC");
            PrivateKey prKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKey)));
            PublicKey puKey = kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey)));

            // Do the key agreement with third party public key and user's private key via Diffie-Hellman
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(prKey);
            keyAgreement.doPhase(puKey, true);

            // Hash the key to fit the correct size
            MessageDigest md = MessageDigest.getInstance("SHA256");

            // Encrypt the file using the hashed shared secret as our AES key
            AES.crypt(filePath, md.digest(keyAgreement.generateSecret()), encrypt);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    /**
     * Generates an ECC public and private key pair.
     * @return A private and public KeyPair
     */
    public static KeyPair generateECCPair() {
        try {
            KeyPairGenerator kg = KeyPairGenerator.getInstance("EC");
            kg.initialize(256);

            return kg.generateKeyPair();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            noSuchAlgorithmException.printStackTrace();
        }
        return null;
    }
}
