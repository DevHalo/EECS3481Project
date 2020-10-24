package com.crypt.algorithms;

// Implementation of the RC4 algorithm
public class RC4 {

    /**
     * Encrypts or decrypts a file using the RC4 algorithm.
     * @param fileName Path of the file
     * @param startingKey Key used to encrypt the file
     * @param encrypt Whether to encrypt or decrypt the file
     */
    public static void crypt(String fileName, byte[] startingKey, boolean encrypt) {
        try {
            // Read input bytes from file and initialize output array
            byte[] input = Utilities.readFile(fileName);
            byte[] output = new byte[input.length];

            int i = 0, j = 0, plaintextIndex = 0;

            // Initialize permutation of S. Starting key is no longer used after this point
            byte[] S = RC4.initalize(startingKey);

            // Stream Generation
            while (plaintextIndex < input.length) {
                i = (i + 1) % 256;
                j = (j + Byte.toUnsignedInt(S[i])) % 256;

                swap(S, i, j);

                int t = (Byte.toUnsignedInt(S[i]) + Byte.toUnsignedInt(S[j])) % 256;
                byte k = S[t];

                // Encrypt / Decrypt using k XOR'd with plaintext
                output[plaintextIndex] = (byte) (k ^ input[plaintextIndex++]);
            }

            // Write output to file
            Utilities.writeFile(output, fileName, encrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }


        /* Implementation using Java API
        try {
            Cipher cipher = Cipher.getInstance("ARCFOUR");
            SecretKeySpec key = new SecretKeySpec(startingKey, cipher.getAlgorithm());

            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);

            byte[] input = Utilities.readFile(fileName);
            byte[] output = cipher.doFinal(input);

            //Utilities.writeFile(output, fileName, encrypt);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        */
    }

    /**
     * Initializes the permutation of S using key
     * @param key Byte array of secret key
     * @return Permutation of S
     */
    private static byte[] initalize(byte[] key) {
        byte[] S = new byte[256];
        byte[] T = new byte[256];

        for (int i = 0; i < 256; i++) {
            S[i] = (byte) i;
            T[i] = key[i % key.length];
        }

        for (int i = 0, j = 0; i < 256; i++) {
            j = (j + Byte.toUnsignedInt(S[i]) + Byte.toUnsignedInt(T[i])) % 256;
            swap(S, i, j);
        }

        return S;
    }

    /**
     * Swaps arr[i] with arr[j]
     * @param arr Array
     * @param i Index for arr[i]
     * @param j Index for arr[j]
     */
    private static void swap(byte[] arr, int i, int j) {
        byte t = arr[i];
        arr[i] = arr[j];
        arr[j] = t;
    }
}
