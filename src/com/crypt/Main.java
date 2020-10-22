package com.crypt;

import com.crypt.algorithms.*;

import java.io.File;
import java.util.*;

public class Main {

    /**
     * The main entry point of the application
     */
    public static void main(String[] args) {
        switch (args.length) {
            case 0:
                // If user supplies no arguments, show basic usage and option for more information
                System.out.println("Usage:\n-encrypt/-decrypt -input <file/folder> -<algorithm> " +
                        "<n tuple secrets>\nExample: -encrypt -input test.txt -xor ABCDEFG\n\n" +
                        "Use -help for more info.");
                break;
            case 1:
                // General help menu
                if (args[0].toUpperCase().equals("-HELP")) {
                    System.out.println("To see the supported algorithms, type -help-algos.\n" +
                            "To see more information about a specific algorithm, type -help-algos <algorithm> " +
                            "(-help-algos xor). The algorithm name is case-insensitive.\n" +
                            "By default, the program will ask for user confirmation before executing.\n" +
                            "You can skip this by using -force or -f.\n" +
                            "-dry will run the program, " +
                            "but not execute any of the encryption algorithms.\n" +
                            "Input can be specified using -i or -input followed by the file or folder.\n");

                    System.out.printf("When encrypting files, the extension %1$s will be appended to the file name. " +
                            "(test.txt%1$s)\n", Utilities.ENCRYPTED_EXTENSION);
                } else if (args[0].toUpperCase().equals("-HELP-ALGOS")) {
                    System.out.println("The application supports the following algorithms:\n\n--Symmetric--\n" +
                            "XOR\nAES\nRC4\nBLOWFISH\n\n--Asymmetric\nRSA\nECC");
                } else System.out.println("Not enough parameters. Did you mean -help?");
                break;
            case 2:
                // Show help menu for algorithms
                if (args[0].equals("-help-algos")) {
                    // TODO: write required secrets the user must enter to use for each algorithm
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
                            System.out.println("Not enough parameters or" +
                                    " algorithm does not exist. Did you mean -help-algos <algorithm>?");
                            break;
                    }
                } else System.out.println("Not enough parameters or malformed input. See -help for details.");
                break;
            default:
                // Encrypt or Decrypt
                boolean encrypt = false;
                if (Arrays.stream(args).noneMatch(str -> str.toUpperCase().equals("-DECRYPT"))) {
                    if (Arrays.stream(args).anyMatch(str -> str.toUpperCase().equals("-ENCRYPT"))) {
                        encrypt = true;
                    } else {
                        System.out.println("Encryption or decryption was not specified.");
                        return;
                    }
                }

                // Find -input or -i argument in args
                List<File> files = new ArrayList<>();
                for (int i = 0; i < args.length; i++) {
                    if (args[i].matches("-INPUT|-I|-i|-input")) {
                        if (args.length - 1 == i) {
                            System.out.println("No file specified for input parameter.");
                            return;
                        } else {
                            // Recursively search supplied path for files.
                            files = Utilities.fileOrFolder(new File(args[i + 1]));
                            break;
                        }
                    }
                }

                if (files.size() > 0) {
                    Scanner in = new Scanner(System.in);

                    // If true, none of the algorithms will run, but will run through each file anyway.
                    boolean dry = Arrays.stream(args).anyMatch(str -> str.toUpperCase().equals("-DRY"));

                    // Find algorithm type
                    String algorithm = "";
                    int algoIndex = -1;
                    for (int i = 0; i < args.length; i++) {
                        if (args[i].toUpperCase().matches("-XOR|-AES|-RC4|-BLOWFISH|-RSA|-ECC")) {
                            if (i == args.length - 1) {
                                System.out.println("Algorithm selected but missing parameters.");
                                return;
                            }
                            algorithm = args[i].toUpperCase();
                            algoIndex = i + 1;
                            break;
                        }
                    }

                    if (algorithm.isEmpty()) {
                        System.out.println("An invalid algorithm was specified." +
                                " See --help-algos for more info.");
                        return;
                    }

                    for (File f : files) {
                        if (f.isDirectory()) {
                            System.out.printf("The folder %s is about to be %s%n", f.getName(),
                                    encrypt ? "encrypted." : "decrypted.");
                            continue;
                        }

                        System.out.printf("The file %s is about to be %s%n",
                                f.getName(), encrypt ? "encrypted." : "decrypted.");

                        if (dry) {
                            System.out.println("-dry was selected. Skipping algorithm execution.");
                            continue;
                        }

                        // To prevent accidental encryption/decryption, the user will be prompted before executing
                        // any algorithm for EACH file.
                        if (Arrays.stream(args).noneMatch(str ->
                                str.toUpperCase().equals("-FORCE") || str.toUpperCase().equals("-F"))) {
                            System.out.println("Are you sure you want to continue? (YES/Y)." +
                                    " Otherwise program will exit.");

                            if (declinePrompt(in)) return;

                            if (f.getName().endsWith(Utilities.ENCRYPTED_EXTENSION) && encrypt) {
                                System.out.printf("This file already has the %s extension. Are you sure you want to" +
                                                " continue? (YES/Y). Otherwise program will skip this file.",
                                        Utilities.ENCRYPTED_EXTENSION);

                                if (declinePrompt(in)) return;
                            }
                        }

                        // TODO: Parse input for each algorithm
                        // Note: Must check the number of indices past algoIndex for the correct number of
                        // secrets for the specified algorithm
                        switch (algorithm) {
                            case "-XOR":
                                String xor_key = args[algoIndex];
                                XOR.xorFile(f.getAbsolutePath(), xor_key.getBytes(), encrypt);
                                break;
                            case "-AES":
                                String aes_key = args[algoIndex];
                                AES.crypt(f.getAbsolutePath(), aes_key.getBytes(), encrypt);
                                break;
                            case "-RC4":
                                String rc4_key = args[algoIndex];
                                RC4.crypt(f.getAbsolutePath(), rc4_key.getBytes(), encrypt);
                                break;
                            case "-BLOWFISH":
                                String blowfish_key = args[algoIndex];
                                BLOWFISH.crypt(f.getAbsolutePath(), blowfish_key.getBytes(), encrypt);
                                break;
                            case "-RSA":
                                break;
                            case "-ECC":
                                break;
                        }

                        System.out.printf("%s was successfully %s ", f.getName(),
                                encrypt ? "encrypted." : "decrypted.");
                    }
                } else {
                    System.out.println("The file/folder does not exist.");
                    return;
                }

                System.out.println("Application exiting.");
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
