package com.crypt.algorithms;

import java.util.Random;

public class Utilities {

    private static String SECRET_KEY = "EECS3481";

    //Used to add confusion / diffusion to cipher algorithm
    private static int IV_LENGTH = 16;

    public static byte[] getIV(int bytes) {
        byte iv[] = new byte[IV_LENGTH];
        Random ivGenerator = new Random();
        ivGenerator.nextBytes(iv);
        return iv;
    }
}
