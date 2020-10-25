package com.crypt.algorithms;

public class XOR {
    /* Methods to create:
    Use utilities error checking 1 + 2 to check if you have write permission and then proceed
    to create new file and construct with by the chunks
    Error Checking specific to XOR:  Check if XOR chunk <= byte chunk
    XOR :
    //Use 1 + 2 to check if you have write permission and then proceed - to do after all algorithms complete
    Create new file and construct with XOR chunks
    */

    /*Encrypt or decrypt a string by providing
        1 .) filePath and filename or fileName
        2 .) key, in bytes
        3 .) {Encrypt == True, Decrypt == False}

        something.jar XOR "MMAAD" true
    */

    /**
     * xorFile takes 3 inputs which lets it either encrypt or decrypt a file based on the key
     * @param filePathAndName - Takes a folder and filename as input
     * @param keyBytes        - Takes a key of any given size and encrypts/decrypts the file
     * @param flag            - {true = encrypt | false = decrypt}, used for encrypting file
     */
    public static void crypt(String filePathAndName, byte[] keyBytes, boolean flag) {
        try {

            byte[] bytesToXOR = Utilities.readFile(filePathAndName);
            byte[] xBytes = new byte[bytesToXOR.length];

            //v1:  Iterate through file bytes until i == filePathAndName.length - keyBytes.length
            //v2:  Iterate through file bytes i ^ xor[i mod length of key]

            for(int i = 0; i < bytesToXOR.length; i++)
                xBytes[i] =  (byte)(bytesToXOR[i] ^ keyBytes[i % keyBytes.length]);

            Utilities.writeFile(xBytes, filePathAndName, flag);

        } catch (NullPointerException e) {
            e.printStackTrace();
        }
    }
}