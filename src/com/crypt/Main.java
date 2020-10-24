package com.crypt;

import com.crypt.algorithms.*;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
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
                        "Use -help for more info, -commands to see all commands, and -help-algos to see a" +
                        " list of algorithms.");
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
                } else if (args[0].toUpperCase().equals("-COMMANDS")) {
                    System.out.println("The application supports the following commands:\n");
                    System.out.printf("%-32s | %s\n", "-input / -i <file/folder>",
                            "Specify an input file or folder of files.");
                    System.out.printf("%-32s | %s\n", "-encrypt / -decrypt", "Specify encryption or decryption mode.");
                    System.out.printf("%-32s | %s\n", "-<algorithm> <secrets>", "Specify the algorithm to be used. See" +
                            " -help-algos for more details on what algorithms you can use.");
                    System.out.printf("%-32s | %s\n", "-force / -f", "Skips the confirmation prompt before the" +
                            " algorithm is executed.");
                    System.out.printf("%-32s | %s\n", "-dry", "The application will execute, but not encrypt/decrypt" +
                            " any of the actual files.");
                } else System.out.println("Not enough parameters. Did you mean -help?");
                break;
            case 2:
                // Show help menu for algorithms
                if (args[0].toUpperCase().equals("-HELP-ALGOS") ||
                    args[0].toUpperCase().equals("-HELP")) {
                    // TODO: write required secrets the user must enter to use for each algorithm
                    switch (args[1].toUpperCase()) {
                        case "XOR":
                            System.out.println("XOR only requires a byte key. Supply your key as a string.\n" +
                                    "Example: -xor MYKEY123");
                            break;
                        case "AES":
                            System.out.println("AES only requires a byte key. Supply your key as a string.\n" +
                                    "The key must be 128-bit, 192-bit, or 256-bit (16, 24, or 32 characters).\n" +
                                    "Example: -aes ABCDEF123456abcdef");
                            break;
                        case "RC4":
                            System.out.println("RC4 only requires a byte key. Supply your key as a string.\n" +
                                    "The key must be at least 8 bits to a maximum of 2048 bits (1 character to a" +
                                    " maximum of 256 characters)\n" +
                                    "Example: -rc4 MYKEY123");
                            break;
                        case "BLOWFISH":
                            System.out.println("Blowfish only requires a byte key. Supply your key as a string.\n" +
                                    "The key must be at least 32 bits to a maximum of 448 bits " +
                                    "(4 characters up to a maximum of 56 characters)\n" +
                                    "Example: -blowfish MYKEY123");
                            break;
                        case "RSA":
                            System.out.println("To be implemented.");
                            break;
                        case "ECC":
                            System.out.println("To be implemented.");
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

                            // Prevents the application from encrypting itself.
                            try {
                                File executable = new File(Main.class.getProtectionDomain().
                                        getCodeSource().getLocation().toURI().getPath());

                                for (File f : files) {
                                    System.out.println(f.getAbsolutePath());
                                    if (f.getCanonicalPath().equals(executable.getCanonicalPath())) {
                                        files.remove(f);
                                        break;
                                    }
                                }
                            } catch (URISyntaxException | IOException e) {
                                e.printStackTrace();
                                System.out.println("Could not get path of executable.");
                                return;
                            }
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

                    int prompt;
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
                                    " (C) will skip this file. Otherwise program will exit.");

                            prompt = declinePrompt(in);

                            if (prompt == 0) return;
                            else if (prompt == -1) continue;

                            if (f.getName().endsWith(Utilities.ENCRYPTED_EXTENSION) && encrypt) {
                                System.out.printf("This file already has the %s extension. Are you sure you want to" +
                                                " continue? (YES/Y). (C) will skip this file. " +
                                                "Otherwise program will exit.", Utilities.ENCRYPTED_EXTENSION);

                                prompt = declinePrompt(in);
                                if (prompt == 0) return;
                                else if (prompt == -1) continue;
                            }
                        }

                        // TODO: Parse input for each algorithm
                        // Note: Reaching this switch statement only guarantees at least one secret is supplied.
                        // Must implement checks for algorithms that require more than 1 secret.
                        switch (algorithm) {
                            case "-XOR":
                                String xor_key = args[algoIndex];

                                if (xor_key.length() < 1) {
                                    System.out.println("You need a key with at least 1 character.");
                                    return;
                                }

                                XOR.xorFile(f.getAbsolutePath(), xor_key.getBytes(), encrypt);
                                break;
                            case "-AES":
                                String aes_key = args[algoIndex];

                                // Check if key is 128-bit, 192-bit, or 256-bit
                                if (aes_key.length() != 16 && aes_key.length() != 24 && aes_key.length() != 32) {
                                    System.out.println("Key must be 128-bit, 192-bit, or 256-bit.");
                                    return;
                                }

                                AES.crypt(f.getAbsolutePath(), aes_key.getBytes(), encrypt);
                                break;
                            case "-RC4":
                                String rc4_key = args[algoIndex];

                                if (rc4_key.length() < 1 || rc4_key.length() > 256) {
                                    System.out.println("Key must be 8-bits to 2048-bits long.");
                                    return;
                                }

                                RC4.crypt(f.getAbsolutePath(), rc4_key.getBytes(), encrypt);
                                break;
                            case "-BLOWFISH":
                                String blowfish_key = args[algoIndex];

                                if (blowfish_key.length() < 4 || blowfish_key.length() > 56) {
                                    System.out.println("Key must be at 32-bits to 448-bits long.");
                                    return;
                                }

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
     * Returns 1 if the user answers "yes" or "y" after prompting the user.
     * Return
     * The answer is case-insensitive.
     * @return -1 if the user types in c. 1 if the user types yes or y. Else 0.
     */
    private static int declinePrompt(Scanner in) {
        String answer = in.nextLine().toUpperCase();
        switch (answer) {
            case "YES":
            case "Y":
                return 1;
            case "C":
                return -1;
            default:
                return 0;
        }
    }
}
