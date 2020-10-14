package com.crypt;

import com.crypt.algorithms.RC4;
import com.crypt.algorithms.XOR;
import com.crypt.algorithms.Utilities;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

public class Main {

    /**
     * The main entry point of the application
     */
    public static void main(String[] args) {
        switch (args.length) {
            case 0:
                // If user supplies no arguments, show basic usage and option for more information
                System.out.println("Usage:\n<encrypt/decrypt> <filename or folder name> <encryption algorithm>" +
                        " <n tuple secrets>\nExample: encrypt test.txt xor ABCDEFG\n\n" +
                        "Use --help for more info.");
                break;
            case 1:
                // General help menu
                if (args[0].equals("--help")) {
                    System.out.println("To see the supported algorithms, type --help-algos.\n");
                    System.out.println("To see more information about a specific algorithm, type --help <algorithm> " +
                            "(--help xor). The algorithm name is case-insensitive.\n");
                    System.out.println("By default, the program will ask for user confirmation before executing.\n" +
                            "You can skip this by using --force or --f.\n");
                    System.out.println("--dry will run the program, " +
                            "but not execute any of the encryption algorithms.\n");
                    System.out.println("When encrypting files, the extension " + Utilities.ENCRYPTED_EXTENSION +
                            " will be appended to the file name. (test.txt" + Utilities.ENCRYPTED_EXTENSION + ")\n");
                } else if (args[0].equals("--help-algos")) {
                    System.out.println("The application supports the following algorithms:\n\n--Symmetric--\n" +
                            "XOR\nAES\nRC4\nBLOWFISH\n\n--Asymmetric\nRSA\nECC");
                } else System.out.println("Not enough parameters. Did you mean --help?");
                break;
            case 2:
                // Show help menu for algorithms
                if (args[0].equals("--help-algos")) {
                    switch (args[1].toUpperCase()) {
                        case "XOR":
                            System.out.println("XOR only requires a byte key. Supply your key as a string.");
                            break;
                        case "AES":
                            break;
                        case "RC4":
                            break;
                        case "BLOWFISH":
                            break;
                        case "RSA":
                            break;
                        case "ECC":
                            break;
                        default:
                            System.out.println("Not enough parameters. Did you mean --help-algos <algorithm>?");
                            break;
                    }
                } else System.out.println("Not enough parameters or malformed input. See --help for details.");
                break;
            default:
                // Encrypt or Decrypt
                if (!args[0].toUpperCase().equals("ENCRYPT") && !args[0].toUpperCase().equals("DECRYPT")) {
                    System.out.println("Encryption or decryption was not specified.");
                    return;
                }
                boolean encrypt = args[0].toUpperCase().equals("ENCRYPT");

                // Recursively search supplied path for files. Will only return 1 file object if args[1] is a file.
                List<File> files = Utilities.fileOrFolder(new File(args[1]));

                if (files.size() > 0) {
                    Scanner in = new Scanner(System.in);

                    // If true, none of the algorithms will run, but will run through each file anyway.
                    boolean dry = Arrays.stream(args).anyMatch(str -> str.toUpperCase().equals("--DRY"));

                    for (File f : files) {
                        if (f.isDirectory()) {
                            System.out.printf("The folder %s is about to be %s%n", f.getName(),
                                    encrypt ? "encrypted." : "decrypted.");
                            continue;
                        }

                        if (f.getName().endsWith(Utilities.ENCRYPTED_EXTENSION) && encrypt) {
                            System.out.printf("This file already has the %s extension. Are you sure you want to" +
                                            " continue? (YES/Y). Otherwise program will skip this file.",
                                    Utilities.ENCRYPTED_EXTENSION);

                            if (declinePrompt(in)) return;
                        }

                        System.out.printf(" The file %s is about to be %s%n",
                                f.getName(), encrypt ? " encrypted." : "decrypted.");

                        if (dry) {
                            System.out.println("--dry was selected. Skipping algorithm execution.");
                            continue;
                        }

                        // To prevent accidental encryption/decryption, the user will be prompted before executing
                        // any algorithm for EACH file.
                        if (Arrays.stream(args).anyMatch(str ->
                                str.toUpperCase().equals("--FORCE") || str.toUpperCase().equals("-F"))) {
                            System.out.println("Are you sure you want to continue? (YES/Y)." +
                                    " Otherwise program will exit.");

                            if (declinePrompt(in)) return;
                        }

                        // TODO: Parse input for each algorithm
                        switch (args[2].toUpperCase()) {
                            case "XOR":
                                String xor_key = args[3];
                                XOR.xorFile(f.getAbsolutePath(), xor_key.getBytes(), encrypt);
                                break;
                            case "AES":
                                break;
                            case "RC4":
                                String rc4_key = args[3];
                                RC4.crypt(f.getAbsolutePath(), rc4_key.getBytes(), encrypt);
                                break;
                            case "BLOWFISH":
                                break;
                            case "RSA":
                                break;
                            case "ECC":
                                break;
                            default:
                                System.out.println("An invalid algorithm was specified." +
                                        " See --help-algos for more info.");
                                return;
                        }

                        System.out.printf("%s was successfully %s ", f.getName(),
                                encrypt ? "encrypted." : "decrypted.");
                    }
                } else {
                    System.out.println("The file/folder \"" + args[1] + "\" does not exist.");
                    return;
                }

                System.out.printf("End of %s execution. Application exiting.%n", encrypt ? "encryption" : "decryption");
                break;
        }
    }

    /**
     * Returns false if the user answers "yes" or "y" after prompting the user.
     * The answer is case-insensitive.
     */
    private static boolean declinePrompt(Scanner in) {
        String answer = in.nextLine();
        return !answer.toUpperCase().equals("YES") && !answer.toUpperCase().equals("Y");
    }
}