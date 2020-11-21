package com.crypt;

import java.io.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import java.security.*;

import com.crypt.algorithms.*;

import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;
import java.util.Random;

public class CryptoTest {

    private File[] testFiles;
    private String[] sha1s;

    private final String WORKING_DIRECTORY = System.getProperty("user.dir") + "/out/test/EECS3481Project/";
    private String key;

    /**
     * Pretty text for organizing the output of different encryption algorithms.
     * Shows before the method is run.
     */
    @BeforeEach
    void PrintBefore(TestInfo testInfo) {
        System.out.printf("| Commencing %s |%n", testInfo.getDisplayName());
    }

    /**
     * Pretty text for organizing the output of different encryption algorithms.
     * Shows after the method is run
     */
    @AfterEach
    void PrintAfter(TestInfo testInfo) {
        System.out.printf("| End of %s |%n", testInfo.getDisplayName());
    }

    /**
     * Converts SHA1 checksum to hexadecimal string
     */
    String ByteToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (byte b : bytes)
            sb.append(String.format("%02x", b));

        return sb.toString();
    }

    /**
     * Generates a pseudorandom alphanumeric key of length bytes
     * @param bytes Length of the key in number of bytes
     */
    void GenerateKey(int bytes) {
        String alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVXYZ0123456789";
        StringBuilder sb = new StringBuilder();
        Random rand = new Random();

        for (int i = 0; i < bytes; i++) {
            sb.append(alphanumeric.charAt((int) (rand.nextFloat() * alphanumeric.length())));
        }
        key = sb.toString();

        System.out.printf("Generated key of length %d bytes:%n%s%n", bytes, key);
    }

    /**
     * Generates a SHA1 hash from reading a target file. Test will fail if
     * the SHA1 generated from this file does not match the supplied source SHA1.
     *
     * @param fileName  Path object to the file to be checked
     * @param sourceSHA1 String representation of the SHA1 hash
     * @param diff      If true, the method will assert if the SHA1s are supposed to be different
     */
    void VerifySHA1(File fileName, String sourceSHA1, boolean diff) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.reset();

            byte[] fileBytes = Files.readAllBytes(fileName.toPath());

            if (diff) {
                assertNotEquals(sourceSHA1, ByteToHexString(md.digest(fileBytes)));
            } else {
                assertEquals(sourceSHA1, ByteToHexString(md.digest(fileBytes)));
            }
        } catch (NoSuchAlgorithmException e) {
            fail("System does not support SHA1. Test can not be completed.");
        } catch (IOException e) {
            fail("Failed to read output file: " + fileName.getName());
        }
    }

    /**
     * Copy test file from test resources directory to working directory
     */
    @BeforeEach
    void Setup() {
        File resourcesDirectory = new File("test/resources");
        testFiles = resourcesDirectory.listFiles();

        assertNotNull(testFiles);
        sha1s = new String[testFiles.length];

        System.out.println("Moving test files to working directory...");

        for (int i = 0; i < testFiles.length; i++) {
            System.out.printf("Moving file: %s to: %s%s%n", testFiles[i].getName(),
                    WORKING_DIRECTORY, testFiles[i].getName());

            // Copy files from test folder to working directory, then calculate SHA1 from original file.
            try {
                byte[] in = Files.readAllBytes(testFiles[i].toPath());

                FileOutputStream out = new FileOutputStream(new File(WORKING_DIRECTORY +
                        testFiles[i].getName()), false);

                out.write(in);
                out.close();

                MessageDigest md = MessageDigest.getInstance("SHA1");
                md.reset();

                sha1s[i] = ByteToHexString(md.digest(in));

                System.out.printf("FILE NAME: %s | SHA1 CHECKSUM:%n%s%n", testFiles[i].getName(), sha1s[i]);
            } catch (FileNotFoundException fileNotFoundException) {
                fail("Failed to find input file: " + testFiles[i].getName());
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                fail("Failed to initialize SHA1 Message Digest");
            } catch (IOException ioException) {
                fail("An error occurred attempting to copy the test file to the working directory.");
            }
        }

        // Generate a pseudorandom alphanumeric key used to encrypt/decrypt
        GenerateKey(8);
        System.out.println();
    }

    /**
     * Tests the XOR encryption and decryption algorithm
     */
    @Test
    @DisplayName("XOR Encryption and Decryption Test")
    void XORTest() {
        for (int i = 0; i < testFiles.length; i++) {
            File fileName = new File(WORKING_DIRECTORY + testFiles[i].getName());

            // Encrypt file here
            try {
                XOR.crypt(fileName.toString(), key.getBytes(), true);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to encrypt file " + i + "/" + testFiles.length + ": " + fileName.getName() + "%n");
            }

            VerifySHA1(new File(fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION),
                    sha1s[i], true);

            // Decrypt file here
            try {
                XOR.crypt(fileName.toString() + Utilities.ENCRYPTED_EXTENSION,
                        key.getBytes(), false);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to decrypt file " + i + "/" + testFiles.length + ": " + fileName.getName() + "%n");
            }

            VerifySHA1(fileName, sha1s[i], false);
        }
    }

    /**
     * Tests the RC4 encryption and decryption algorithm
     */
    @Test
    @DisplayName("RC4 Encryption and Decryption Test")
    void RC4Test() {
        for (int i = 0; i < testFiles.length; i++) {
            File fileName = new File(WORKING_DIRECTORY + testFiles[i].getName());

            try {
                RC4.crypt(fileName.toString(), key.getBytes(), true);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to encrypt file " + fileName.toString());
            }

            VerifySHA1(new File(fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION),
                    sha1s[i], true);

            try {
                RC4.crypt(fileName.toString() + Utilities.ENCRYPTED_EXTENSION, key.getBytes(), false);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to decrypt file " + fileName.toString());
            }

            VerifySHA1(fileName, sha1s[i], false);
        }
    }

    /**
     * Tests the AES encryption and decryption algorithm
     */
    @Test
    @DisplayName("AES Encryption and Decryption Test")
    void AESTest() {
        for (int i = 0; i < testFiles.length; i++) {
            File fileName = new File(WORKING_DIRECTORY + testFiles[i].getName());

            try {
                AES.crypt(fileName.toString(), key.getBytes(StandardCharsets.UTF_8), Utilities.ENCRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to encrypt file " + fileName.toString());
            }

            VerifySHA1(new File(fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION),
                    sha1s[i], true);

            try {
                AES.crypt(fileName.toString() + Utilities.ENCRYPTED_EXTENSION,
                        key.getBytes(StandardCharsets.UTF_8), Utilities.DECRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to decrypt file " + fileName.toString());
            }

            VerifySHA1(fileName, sha1s[i], false);
        }
    }

    /**
     * Tests the Blowfish encryption and decryption algorithm
     */
    @Test
    @DisplayName("Blowfish Encryption and Decryption Test")
    void BlowfishTest() {
        for (int i = 0; i < testFiles.length; i++) {
            File fileName = new File(WORKING_DIRECTORY + testFiles[i].getName());
            try {
                BLOWFISH.cryptAPI(fileName.toString(), key.getBytes(StandardCharsets.UTF_8), Utilities.ENCRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to encrypt file " + fileName.toString());
            }

            VerifySHA1(new File(fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION),
                    sha1s[i], true);

            try {
                BLOWFISH.cryptAPI(fileName.toString() + Utilities.ENCRYPTED_EXTENSION,
                        key.getBytes(StandardCharsets.UTF_8), Utilities.DECRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to decrypt file " + fileName.toString());
            }

            VerifySHA1(fileName, sha1s[i], false);
        }
    }

    /**
     * Runs the XOR algorithm using Main to simulate command line usage
     */
    @Test
    @DisplayName("Command Line Interface Test")
    void CommandLineTest() {
        for (int i = 0; i < testFiles.length; i++) {
            File fileName = new File(WORKING_DIRECTORY + testFiles[i].getName());

            // Test parameters include:
            // Encryption and Decryption of each file in the test folder, using XOR. User confirmation is skipped.
            assertDoesNotThrow(() ->
                    Main.main(new String[]{"-encrypt", "-i", fileName.getAbsolutePath(), "-xor", key, "-f"}));

            VerifySHA1(new File(fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION),
                    sha1s[i], true);

            assertDoesNotThrow(() ->
                    Main.main(new String[]{"-decrypt", "-i", fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION,
                            "-xor", key, "-f"}));

            VerifySHA1(fileName, sha1s[i], false);
        }
    }

    @Test
    @DisplayName("ECC Key Pair Generation Test")
    void CommandLineTest2() {
        assertDoesNotThrow(() ->
                Main.main(new String[] {"-generate", "ECC"}));
    }

    @Test
    @DisplayName("RSA Key Pair Generation Test")
    void CommandLineTest3() {
        assertDoesNotThrow(() ->
                Main.main(new String[] {"-generate", "RSA"}));
    }

    @Test
    @DisplayName("ECC Command Line Test")
    void CommandLineTest4() {
        for (int i = 0; i < testFiles.length; i++) {
            File fileName = new File(WORKING_DIRECTORY + testFiles[i].getName());

            // Test parameters include:
            // Encryption and Decryption of each file in the test folder, using XOR. User confirmation is skipped.
            assertDoesNotThrow(() ->
                    Main.main(new String[]{"-encrypt", "-i", fileName.getAbsolutePath(), "-xor", key, "-f"}));

            VerifySHA1(new File(fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION),
                    sha1s[i], true);

            assertDoesNotThrow(() ->
                    Main.main(new String[]{"-decrypt", "-i", fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION,
                            "-xor", key, "-f"}));

            VerifySHA1(fileName, sha1s[i], false);
        }
    }

    @Test
    @DisplayName("ECC Encryption and Decryption Test")
    void ECCTest() {
        for (int i = 0; i < testFiles.length; i++) {
            // Generate key pairs
            KeyPair a_pair = ECC.generateECCPair();
            KeyPair b_pair = ECC.generateECCPair();

            if (a_pair == null || b_pair == null) fail();

            byte[] aPrivate = Base64.getEncoder().encode(a_pair.getPrivate().getEncoded());
            byte[] aPublic = Base64.getEncoder().encode(a_pair.getPublic().getEncoded());

            byte[] bPrivate = Base64.getEncoder().encode(b_pair.getPrivate().getEncoded());
            byte[] bPublic = Base64.getEncoder().encode(b_pair.getPublic().getEncoded());

            File fileName = new File(WORKING_DIRECTORY + testFiles[i].getName());

            // Encrypt using person a's private key
            try {
                ECC.crypt(fileName.toString(), aPrivate, bPublic, Utilities.ENCRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to encrypt file " + fileName.toString());
            }

            VerifySHA1(new File(fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION),
                    sha1s[i], true);

            // Decrypt using person b's private key
            try {
                ECC.crypt(fileName.toString() + Utilities.ENCRYPTED_EXTENSION,
                        bPrivate, aPublic, Utilities.DECRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to decrypt file " + fileName.toString());
            }

            VerifySHA1(fileName, sha1s[i], false);
        }
    }

    @Test
    @DisplayName("ECC Encryption and Decryption Test using Command Line")
    void ECCTest2() {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(os);
        PrintStream old = System.out;

        System.setOut(ps);

        assertDoesNotThrow(() ->
                Main.main(new String[] {"-generate", "ECC"}));

        assertDoesNotThrow(() ->
                Main.main(new String[] {"-generate", "ECC"}));

        System.out.flush();
        System.setOut(old);

        String[] str = os.toString().split("\r\n");

        for (int i = 0; i < testFiles.length; i++) {
            File fileName = new File(WORKING_DIRECTORY + testFiles[i].getName());

            // Encrypt using person a's private key
            try {
                ECC.crypt(fileName.toString(), str[1].getBytes(), str[7].getBytes(), Utilities.ENCRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to encrypt file " + fileName.toString());
            }

            VerifySHA1(new File(fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION),
                    sha1s[i], true);

            // Decrypt using person b's private key
            try {
                ECC.crypt(fileName.toString() + Utilities.ENCRYPTED_EXTENSION,
                        str[5].getBytes(), str[3].getBytes(), Utilities.DECRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to decrypt file " + fileName.toString());
            }

            VerifySHA1(fileName, sha1s[i], false);
        }
    }

    @Test
    @DisplayName("RSA Encryption and Decryption Test")
    void RSATest() {
        for (int i = 0; i < testFiles.length; i++) {
            // Generate key pair
            KeyPair pair = RSA.generateRSAPair(1024);

            if (pair == null) fail();

            byte[] privateBytes = Base64.getEncoder().encode(pair.getPrivate().getEncoded());
            byte[] publicBytes = Base64.getEncoder().encode(pair.getPublic().getEncoded());

            File fileName = new File(WORKING_DIRECTORY + testFiles[i].getName());

            // Encrypt using public key
            try {
                RSA.crypt(fileName.toString(), publicBytes, Utilities.ENCRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to encrypt file " + fileName.toString());
            }

            VerifySHA1(new File(fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION),
                    sha1s[i], true);

            // Decrypt using private key
            try {
                RSA.crypt(fileName.toString() + Utilities.ENCRYPTED_EXTENSION, privateBytes, Utilities.DECRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to decrypt file " + fileName.toString());
            }

            VerifySHA1(fileName, sha1s[i], false);
        }
    }

    @Test
    @DisplayName("RSA Encryption and Decryption Test using Command Line")
    void RSATest2() {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(os);
        PrintStream old = System.out;

        System.setOut(ps);

        assertDoesNotThrow(() ->
                Main.main(new String[] {"-generate", "RSA"}));

        System.out.flush();
        System.setOut(old);

        String[] str = os.toString().split("\r\n");

        for (int i = 0; i < testFiles.length; i++) {
            File fileName = new File(WORKING_DIRECTORY + testFiles[i].getName());

            // Encrypt using public key
            try {
                RSA.crypt(fileName.toString(), str[3].getBytes(), Utilities.ENCRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to encrypt file " + fileName.toString());
            }

            VerifySHA1(new File(fileName.getAbsolutePath() + Utilities.ENCRYPTED_EXTENSION),
                    sha1s[i], true);

            // Decrypt using private key
            try {
                RSA.crypt(fileName.toString() + Utilities.ENCRYPTED_EXTENSION,
                        str[1].getBytes(), Utilities.DECRYPT);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to decrypt file " + fileName.toString());
            }

            VerifySHA1(fileName, sha1s[i], false);
        }
    }
}
