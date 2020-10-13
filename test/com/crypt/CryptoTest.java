package com.crypt;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import java.nio.file.Files;

import java.security.MessageDigest;

import com.crypt.algorithms.Utilities;
import com.crypt.algorithms.XOR;

import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class CryptoTest {

    private File[] testFiles;
    private String[] md5s;

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
     * Converts MD5 checksum to hexadecimal string
     */
    String ByteToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (byte b : bytes)
            sb.append(String.format("%02x", b));

        return sb.toString();
    }

    /**
     * Generates a pseudorandom alphanumeric key of length bytes
     *
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
     * Copy test file from test resources directory to working directory
     */
    @BeforeEach
    void Setup() {
        File resourcesDirectory = new File("test/resources");
        testFiles = resourcesDirectory.listFiles();

        assertNotNull(testFiles);
        md5s = new String[testFiles.length];

        System.out.println("Moving test files to working directory...");

        for (int i = 0; i < testFiles.length; i++) {
            System.out.printf("Moving file: %s to: %s%s%n", testFiles[i].getName(),
                    WORKING_DIRECTORY, testFiles[i].getName());

            // Copy files from test folder to working directory, then calculate MD5 from original file.
            try {
                byte[] in = Files.readAllBytes(testFiles[i].toPath());

                FileOutputStream out = new FileOutputStream(new File(WORKING_DIRECTORY +
                        testFiles[i].getName()), false);

                out.write(in);
                out.close();

                MessageDigest md = MessageDigest.getInstance("MD5");
                md.reset();

                md5s[i] = ByteToHexString(md.digest(in));

                System.out.printf("FILE NAME: %s | MD5 CHECKSUM:%n%s%n", testFiles[i].getName(), md5s[i]);
            } catch (FileNotFoundException fileNotFoundException) {
                fail("Failed to find input file: " + testFiles[i].getName());
            } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                fail("Failed to initialize MD5 Message Digest");
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
                XOR.xorFile(fileName.toString(), key.getBytes(), true);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to encrypt file " + i + "/" + testFiles.length + ": " + fileName.getName() + "%n");
            }

            // Decrypt file here
            try {
                XOR.xorFile(fileName.toString() + Utilities.ENCRYPTED_EXTENSION,
                        key.getBytes(), false);
            } catch (Exception e) {
                e.printStackTrace();
                fail("Failed to decrypt file " + i + "/" + testFiles.length + ": " + fileName.getName() + "%n");
            }

            try {
                byte[] output = Files.readAllBytes(fileName.toPath());

                // Check MD5 checksum for match
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.reset();

                byte[] alteredmd5 = md.digest(output);

                assertEquals(md5s[i], ByteToHexString(alteredmd5));
            } catch (IOException ioException) {
                fail("Failed to read decrypted file " + fileName.toString());
            } catch (NoSuchAlgorithmException noAlgoException) {
                fail("Could not initialize MD5 Message Digest");
            }
        }
    }
}
