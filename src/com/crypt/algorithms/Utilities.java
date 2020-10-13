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

    public static final String ENCRYPTED_EXTENSION = ".crypt";

    //Max Path length in Windows
    private static final int MAX_PATH_LENGTH = 255;
    private static final int MAX_FILE_SIZE = 8192;

    //Used to add confusion / diffusion to cipher algorithm
    private static int IV_LENGTH = 16;
    private static String SECRET_KEY = "EECS3481";

    public static byte[] getIV(int bytes) {
        byte iv[] = new byte[IV_LENGTH];
        Random ivGenerator = new Random();
        ivGenerator.nextBytes(iv);
        return iv;
    }

    //read file with a specified fPN (file Path and Name) and store it in byte array
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

    //write file with bytes given with a specified fPN (file Path and Name)
    public static void writeFile(byte[] buffer, String filePathAndName, boolean encryptFlag) {

        try {
            long fileSize = Files.size(Paths.get(filePathAndName));

            //If you got a big file (larger than 2 Gb..., just encrypt the first bits instead)
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

            //encryptFlag is true then encrypt, otherwise, decrypt
            if (encryptFlag) {
                //Check if file path + file name < 255
                if (Utilities.isNewExtensionPossible(filePathAndName, ENCRYPTED_EXTENSION))
                    newFilePathAndName = Utilities.setEncryptedExtension(filePathAndName);
            }
            else {
                newFilePathAndName = Utilities.setNormalExtension(filePathAndName);
            }

            File oldFile = new File(filePathAndName);
            File newFile = new File(newFilePathAndName);

            oldFile.renameTo(newFile);

        } catch(IOException e) {
            e.printStackTrace();
        }
    }

//    public static void deleteFile(String filePathAndName) {
//        try {
//            Files.delete(Paths.get(filePathAndName));
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }

    //Check if the string is null or empty
    public static boolean isEmpty(String buffer) {
        return (buffer.length() == 0 || buffer == null);
    }

    //Set the encrypted extension
    public static String setEncryptedExtension(String filePathAndName) {
        return isEmpty(filePathAndName) ? filePathAndName : filePathAndName.concat(ENCRYPTED_EXTENSION);
    }

    //Set the normal extension
    public static String setNormalExtension(String filePathAndName) {

        //If it does end with extension, remove it
        String newFilePathAndName  = "";
        if (filePathAndName.endsWith(ENCRYPTED_EXTENSION))
            newFilePathAndName = filePathAndName.substring(0, filePathAndName.length() - ENCRYPTED_EXTENSION.length());

        return isEmpty(filePathAndName) ? filePathAndName : newFilePathAndName;
    }

    //Check if fPN + extension <= 255
    public static boolean isNewExtensionPossible(String filePathAndName, String extension) {
        return (filePathAndName.length() + extension.length()) <= MAX_PATH_LENGTH;
    }

    public static File[] iterateThroughFolder(String startingFolderOrFile){
        File newTree = new File(startingFolderOrFile);
        List<File> buffer = new ArrayList<>();

        if (newTree.isDirectory()) {
            String[] listOfFiles = newTree.list();
            for (String fileOrFolder : listOfFiles)
            {
                buffer.add(new File(fileOrFolder));
            }
        }

        File[] output = new File[buffer.size()];

        return buffer.toArray(output);
    }

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
        return buffer;
    }
}
