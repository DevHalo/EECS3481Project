package com.crypt.algorithms;

import java.io.*;
import java.nio.file.*;
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

    //Max Path length in Windows
    private static final int MAX_PATH_LENGTH = 249;


    private static final int MAX_FILE_SIZE = Integer.MAX_VALUE - 16;

    /**
     *
     * @param bytes         - Initial seed for Initialization Vector (IV)
     * @param byteLength    - Ciphers require have different length of IV
     *                        For AES 128/192/256 Bit = 16/24/32 Bytes
     *                        For Blowfish = 8 Bytes
     * @return              - returns IV of byteLength
     */
    public static byte[] getIV(int bytes, int byteLength) {
        byte iv[] = new byte[byteLength];
        Random ivGenerator = new Random(bytes);
        ivGenerator.nextBytes(iv);
        return iv;
    }

    /**
     *
     * @param filePathAndName - Name of file to be read in bytes
     * @return                - returns a byte array of the file
     */
    public static byte[] readFile(String filePathAndName)  {
        //Source:
        // https://stackoverflow.com/questions/858980/file-to-byte-in-java

        try {
            //Debug statement
            //System.out.println(Files.readAllBytes(Paths.get(filePathAndName)).toString());
            long fileSize = Files.size(Paths.get(filePathAndName));

            //If fileSize is greater than the max integer value...
            if (fileSize > MAX_FILE_SIZE)
            {
                byte[] buffer = new byte[MAX_FILE_SIZE];

                try(BufferedInputStream in = new BufferedInputStream(new FileInputStream(filePathAndName))) {

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
     *
     * @param buffer          - Needs a byte array of a file
     * @param filePathAndName - Name of the file to be written
     * @param encryptFlag     - Is the file going encrypted (True) or decrypted? (False)
     */
    public static void writeFile(byte[] buffer, String filePathAndName, boolean encryptFlag) {

        try {
            long fileSize = Files.size(Paths.get(filePathAndName));

            //To be re-written
            if (fileSize > MAX_FILE_SIZE)
            {
                //Source:
                //https://stackoverflow.com/questions/181408/best-way-to-write-bytes-in-the-middle-of-a-file-in-java

                RandomAccessFile hugeFile = new RandomAccessFile(new File(filePathAndName), "rw");
                hugeFile.seek(0);
                hugeFile.write(buffer);
                hugeFile.close();
            }
            else
                Files.write(Paths.get(filePathAndName), buffer, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            String newFilePathAndName = "";

            //encryptFlag otherwise, decrypts true then encrypt, ot
            if (encryptFlag) {
                //Check if file path + file name < 255
                if (Utilities.isNewExtensionPossible(filePathAndName))
                    newFilePathAndName = Utilities.setEncryptedExtension(filePathAndName);
            }
            else {
                newFilePathAndName = Utilities.setNormalExtension(filePathAndName);
            }

            File oldFile = new File(filePathAndName);
            File newFile = new File(newFilePathAndName);

            if (newFile.exists())
                deleteFile(newFile.toString());

            oldFile.renameTo(newFile);


        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    /**
     *
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
     *
     * @param buffer          - Check if the String is 0 or null
     * @return                - If it is, return true, otherwise return false
     */
    public static boolean isEmpty(String buffer) {
        return (buffer.length() == 0 || buffer == null);
    }

    /**
     *
     * @param filePathAndName - get the filePathAndName of a file as a String
     * @return                - returns filePathAndName + encrypted extension
     */
    public static String setEncryptedExtension(String filePathAndName) {
        return isEmpty(filePathAndName) ? filePathAndName : filePathAndName.concat(ENCRYPTED_EXTENSION);
    }

    /**
     *
     * @param filePathAndName - get the filePathAndName of a file as a String
     * @return                - returns filePathAndName + decrypted extension
     */
    public static String setNormalExtension(String filePathAndName) {

        //If it does end with extension, remove it
        String newFilePathAndName  = "";
        if (filePathAndName.endsWith(ENCRYPTED_EXTENSION))
            newFilePathAndName = filePathAndName.substring(0, filePathAndName.length() - ENCRYPTED_EXTENSION.length());

        return isEmpty(filePathAndName) ? filePathAndName : newFilePathAndName;
    }

    /**
     *
     * @param filePathAndName - Pass a filename to method
     * @return                - Checks the filename+encrypted extension
     *                          is not greater than Windows file limit
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
     * @param startingFolderOrFile - Starting point to check
     * @return                     - Returns an array of File(s)
     */
    public static File[] iterateThroughFolder(String startingFolderOrFile){
        File newTree = new File(startingFolderOrFile);
        List<File> buffer = new ArrayList<>();

        if (newTree.isDirectory()) {
            String[] listOfFiles = newTree.list();
            for (String fileOrFolder : listOfFiles)
            {
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
     * @param node             - Starting point to check
     * @return                 - Returns an array of File(s)
     */
    public static List<File> fileOrFolder(File node){

        System.out.println(node.getAbsoluteFile());
        List<File> buffer = new ArrayList<>();

        if(node.isDirectory()){
            String[] subNote = node.list();
            for(String filename : subNote){
                File subItem = new File(node, filename);
                fileOrFolder(subItem);
                buffer.add(subItem);
            }
        }
        else
            buffer.add(node);

        return buffer;
    }
}
