package com.crypt.algorithms;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.List;
import java.util.*;

public class Utilities {
    /*
        Methods to create:
            Read file as bytes (String filename) returns bytearray[] - done
            Write bytes as file (byte[]) returns nothing - done
            Check if file string is empty or null - done
            Rename extensions method(s)  encrypt and normal - done
        Error checking:
            1 .) Check if file/folder is accessible - to do after all algorithms complete
            2 .) Check if file/folder is writeable by user - to do after all algorithms complete
            3 .) Check if file path + file length + new extension is possible - done
     */

    //Encrypted  extension
    public static final String ENCRYPTED_EXTENSION = ".crypt";
    public static final boolean ENCRYPT = true;
    public static final boolean DECRYPT = false;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;
    //Max Path length in Windows
    private static final int MAX_PATH_LENGTH = 249;

    // 2 GB = 2147483648 Bytes == Int.MAX_VAL - 1
    // Set MAX to multiple of 128
    private static final int MAX_FILE_SIZE = Integer.MAX_VALUE - 127;

    /**
     * @param byteLength - Ciphers require have different length of IV
     *                   For AES 128/192/256 Bit = 16/24/32 Bytes
     *                   For Blowfish = 8 Bytes
     * @return - returns IV of byteLength
     */
    public static byte[] getIV(int byteLength) {
        byte[] iv = new byte[byteLength];
        byte[] seed = (new SecureRandom()).generateSeed(byteLength);

        SecureRandom ivGenerator = new SecureRandom(seed);
        ivGenerator.nextBytes(iv);
        return iv;
    }

    /**
     * @param filePathAndName - Name of file to be read in bytes
     * @return - returns a byte array of the file
     */
    public static byte[] readFile(String filePathAndName) {
        //Source:
        // https://stackoverflow.com/questions/858980/file-to-byte-in-java

        try {
            //Debug statement
            //System.out.println(Files.readAllBytes(Paths.get(filePathAndName)).toString());
            long fileSize = Files.size(Paths.get(filePathAndName));

            //If fileSize is greater than the max integer value...
            if (fileSize > MAX_FILE_SIZE) {
                byte[] buffer = new byte[MAX_FILE_SIZE];

                try (BufferedInputStream in = new BufferedInputStream(new FileInputStream(filePathAndName))) {
                    in.read(buffer, 0, MAX_FILE_SIZE);
                }
                return buffer;
            }

            return Files.readAllBytes(Paths.get(filePathAndName));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param filePathAndName - Name of the file to be written
     * @param position        - Traverse the file to position indicated
     * @param EOF             - If True, it seeks to EOF - paddingLength position otherwise,
     *                        it seeks to the position and reads bytes of paddingLength
     */
    public static byte[] readDataAtOffset(String filePathAndName, int paddingLength, long position, boolean EOF) {

        byte[] dataAtPosition = new byte[paddingLength];
        try {
            RandomAccessFile hugeFile = new RandomAccessFile(new File(filePathAndName), "r");

            //if True, it seeks to EOF - Length of Bytes, otherwise it seeks to where you want to go
            hugeFile.seek((EOF) ? hugeFile.length() - paddingLength : position);

            //Reads the data at the position, size is dependant on paddingLength
            hugeFile.read(dataAtPosition, 0, paddingLength);
            hugeFile.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
        return dataAtPosition;
    }

    /**
     * @param buffer          - Needs a byte array of a file
     * @param filePathAndName - Name of the file to be written
     * @param encryptFlag     - Is the file going encrypted (True) or decrypted? (False)
     */
    public static void writeFile(byte[] buffer, String filePathAndName, boolean encryptFlag) {

        try {
            long fileSize = Files.size(Paths.get(filePathAndName));

            //To be re-written
            if (fileSize > MAX_FILE_SIZE) {
                //Source:
                //https://stackoverflow.com/questions/181408/best-way-to-write-bytes-in-the-middle-of-a-file-in-java

                RandomAccessFile hugeFile = new RandomAccessFile(new File(filePathAndName), "rw");
                hugeFile.seek(0);
                hugeFile.write(buffer);
                hugeFile.close();
            } else
                Files.write(Paths.get(filePathAndName), buffer, StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING);

            setExtension(filePathAndName, encryptFlag);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Writes data at either EOF or position chosen
     *
     * @param buffer          - Needs a byte array of a file
     * @param filePathAndName - Name of the file to be written
     * @param position        - Traverse the file to position indicated
     * @param EOF             - If True, it seeks to EOF otherwise,
     *                        it seeks to the position
     */
    public static void writeDataAtOffset(byte[] buffer, String filePathAndName,
                                         long position, boolean EOF) {
        try {
            RandomAccessFile hugeFile = new RandomAccessFile(new File(filePathAndName), "rw");
            hugeFile.seek(EOF ? hugeFile.length() : position);
            hugeFile.write(buffer);
            hugeFile.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Function will truncate file based on size of IV + padding in bytes
     *
     * @param ivWithPadding   - pass the iv WITH padding
     * @param filePathAndName - name of file
     */
    public static void truncateDataAtEOF(byte[] ivWithPadding, String filePathAndName) {
        try {
            RandomAccessFile hugeFile = new RandomAccessFile(new File(filePathAndName), "rw");
            hugeFile.seek(hugeFile.length());
            hugeFile.setLength(hugeFile.length() - ivWithPadding.length);
            hugeFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void setExtension(String filePathAndName, boolean encryptFlag) {

        String newFilePathAndName = "";

        //encryptFlag , if true then encrypt, otherwise normal extension
        if (encryptFlag) {
            //Check if file path + file name < 255
            if (Utilities.isNewExtensionPossible(filePathAndName))
                newFilePathAndName = Utilities.setEncryptedExtension(filePathAndName);
//            else {
//                File newFile = new File(newFilePathAndName);
//                Path originalLocation = Paths.get(newFilePathAndName);
//                Path parentLocation = originalLocation.getParent();
//                //Move file to parent location
//            }
        } else {
            newFilePathAndName = Utilities.setNormalExtension(filePathAndName);
        }

        File oldFile = new File(filePathAndName);
        File newFile = new File(newFilePathAndName);

        if (newFile.exists())
            deleteFile(newFile.toString());

        if (!oldFile.renameTo(newFile))
            System.out.println("Failed to move " + oldFile.getName() + " to " + newFile.getName());
    }

    /**
     * @param filePathAndName - Deletes file
     */
    public static void deleteFile(String filePathAndName) {
        try {
            if (new File(filePathAndName).exists())
                Files.delete(Paths.get(filePathAndName));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * @param buffer - Check if the String is 0 or null
     * @return - If it is, return true, otherwise return false
     */
    public static boolean isEmpty(String buffer) {
        return buffer.length() == 0;
    }

    /**
     * @param filePathAndName - get the filePathAndName of a file as a String
     * @return - returns filePathAndName + encrypted extension
     */
    public static String setEncryptedExtension(String filePathAndName) {
        return isEmpty(filePathAndName) ? filePathAndName : filePathAndName.concat(ENCRYPTED_EXTENSION);
    }

    /**
     * @param filePathAndName - get the filePathAndName of a file as a String
     * @return - returns filePathAndName + decrypted extension
     */
    public static String setNormalExtension(String filePathAndName) {

        //If it does end with extension, remove it
        String newFilePathAndName = "";
        if (filePathAndName.endsWith(ENCRYPTED_EXTENSION))
            newFilePathAndName = filePathAndName.substring(0, filePathAndName.length() - ENCRYPTED_EXTENSION.length());

        return isEmpty(filePathAndName) ? filePathAndName : newFilePathAndName;
    }

    /**
     * @param filePathAndName - Pass a filename to method
     * @return - Checks the filename+encrypted extension
     * is not greater than Windows file limit
     */
    public static boolean isNewExtensionPossible(String filePathAndName) {
        Path buffer = Paths.get(filePathAndName);
        return (buffer.toString().length() +
                filePathAndName.length() +
                ENCRYPTED_EXTENSION.length()
        ) <= MAX_PATH_LENGTH;
    }

    /**
     * Non-recursive iteration and collecting of files,
     * adds each file found to a list and passes it as a file array
     *
     * @param startingFolderOrFile - Starting point to check
     * @return - Returns an array of File(s)
     */
    public static File[] iterateThroughFolder(String startingFolderOrFile) {
        File newTree = new File(startingFolderOrFile);
        List<File> buffer = new ArrayList<>();

        if (newTree.isDirectory()) {
            String[] listOfFiles = newTree.list();
            for (String fileOrFolder : listOfFiles) {
                buffer.add(new File(fileOrFolder));
            }
            File[] output = new File[buffer.size()];

            return buffer.toArray(output);
        }

        return new File[]{newTree};
    }

    /**
     * Recursive iteration and collecting of files,
     * adds each file found to a list and passes it as a file array
     *
     * @param node - Starting point to check
     * @return - Returns an array of File(s)
     */
    public static List<File> fileOrFolder(File node) {

        System.out.println(node.getAbsoluteFile());
        List<File> buffer = new ArrayList<>();

        if (node.isDirectory()) {
            String[] subNote = node.list();
            for (String filename : subNote) {
                File subItem = new File(node, filename);
                fileOrFolder(subItem);
                buffer.add(subItem);
            }
        } else
            buffer.add(node);

        return buffer;
    }

    /**
     * Returns true if the specified algorithm is symmetric
     * @param algorithm
     * @return
     */
    public static boolean isSymmetric(String algorithm) {
        return algorithm.matches("[-]?AES|[-]?XOR|[-]?BLOWFISH|[-]?RC4");
    }

    public static void RSAKeyPairGenerator() throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1048576);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
        writeKeysToFile("publicKey.txt", Base64.getEncoder().encodeToString(getPublicKey().getEncoded()));
        writeKeysToFile("privateKey.txt", Base64.getEncoder().encodeToString(getPrivateKey().getEncoded()));
    }

    public static void writeKeysToFile(String path, String key) throws IOException {
        File f = new File(path);
//        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key.getBytes());
        fos.flush();
        fos.close();
    }

    public static PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static PublicKey getPublicKey() {
        return publicKey;
    }
}
