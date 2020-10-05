package com.crypt;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.security.NoSuchAlgorithmException;

public class CryptoTest {

    File[] testFiles;
    String[] md5s;

    /**
     * Converts MD5 checksum to hexadecimal string
     */
    String ByteToHexString(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();

        for (byte b : bytes)
            sb.append(String.format("%02x", b));

        return sb.toString();
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
            System.out.println("Moving file: " + testFiles[i].getName() + " to: " +
                    System.getProperty("user.dir") + "\\" + testFiles[i].getName());

            // Copy files from test folder to working directory, then calculate MD5 from original file.
            try {
                byte[] in = Files.readAllBytes(testFiles[i].toPath());
                FileOutputStream out = new FileOutputStream(new File(System.getProperty("user.dir") +
                        testFiles[i].getName()));
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.reset();

                out.write(in);
                out.close();

                md5s[i] = ByteToHexString(md.digest(in));
                System.out.println("FILE NAME: " + testFiles[i].getName() + " | MD5 CHECKSUM:");
                System.out.println(md5s[i]);

            } catch (FileNotFoundException | NoSuchAlgorithmException e) {
                fail("This shouldn't happen.");
            } catch (IOException ioException) {
                fail("An error occurred attempting to copy the test file to the working directory.");
            }
        }
    }

    /**
     * Tests the XOR encryption and decryption algorithm
     */
    @Test
    void XORTest() {
        System.out.println("Commencing XOR Encrypt/Decrypt Test");

        for (int i = 0; i < testFiles.length; i++) {
            try {
                byte[] input = Files.readAllBytes(Paths.get(System.getProperty("user.dir") +
                        testFiles[i].getName()));
                // encrypt file here


                // decrypt file here


                byte[] output = input; // TEST REMOVE LATER
                // Check MD5 checksum for match
                MessageDigest md = MessageDigest.getInstance("MD5");
                md.reset();

                byte[] alteredmd5 = md.digest(output);

                assertEquals(md5s[i], ByteToHexString(alteredmd5));
            } catch (IOException ioException) {
                fail("Failed to read decrypted file.");
            } catch (NoSuchAlgorithmException noAlgoException) {
                fail("This shouldn't happen.");
            }
        }
    }
}
