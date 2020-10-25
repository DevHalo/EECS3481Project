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
                generalRequirements();
                break;
            case 1:
                // General help menu
                if (args[0].toUpperCase().equals("-HELP")) {
                    System.out.println("To see the supported algorithms, type -help-algos.\n" +
                            "By default, the program will ask for user confirmation before executing.\n" +
                            "You can skip this by using -force or -f.\n" +
                            "-dry will run the program, " +
                            "but not execute any of the encryption algorithms.\n" +
                            "Input can be specified using -i or -input followed by the file or folder.\n");

                    System.out.printf("When encrypting files, the extension %1$s will be appended to the file name. " +
                            "(test.txt%1$s)\n", Utilities.ENCRYPTED_EXTENSION);
                } else if (args[0].toUpperCase().equals("-HELP-ALGOS")) {
                    System.out.println("The application supports the following algorithms:\n"+
                    "+-----------+------------+\n" +
                    "| Symmetric | Asymmetric |\n" +
                    "+-----------+------------+\n" +
                    "| AES       | ECC        |\n" +
                    "| BLOWFISH  | RSA        |\n" +
                    "| RC4       |            |\n" +
                    "| XOR       |            |\n" +
                    "+-----------+------------+");
                    generalRequirements();
                    keyRequirements("", "", 1, Integer.MAX_VALUE - 1, 99);
                } else System.out.println("Not enough parameters. Did you mean -help?");
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
                        else {
                            System.out.printf("The file %s is about to be %s%n",
                                    f.getName(), encrypt ? "encrypted." : "decrypted.");
                        }

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

                        String key = args[algoIndex];
                        switch (algorithm) {
                            case "-AES":
                                keyRequirements(algorithm, key, 1, Integer.MAX_VALUE - 1, 2);
                                AES.crypt(f.getAbsolutePath(), key.getBytes(), encrypt);
                                break;
                            case "-BLOWFISH":
                                keyRequirements(algorithm, key, 8, 2048, 3);
                                BLOWFISH.crypt(f.getAbsolutePath(), key.getBytes(), encrypt);
                                break;
                            case "-RC4":
                                keyRequirements(algorithm, key, 1, 256, 4);
                                RC4.crypt(f.getAbsolutePath(), key.getBytes(), encrypt);
                                break;
                            case "-XOR":
                                keyRequirements(algorithm, key, 1, Integer.MAX_VALUE - 1, 5);
                                XOR.crypt(f.getAbsolutePath(), key.getBytes(), encrypt);
                                break;
                            case "-RSA":
                                /*To be implemented */
                                break;
                            case "-ECC":
                                /*To be implemented */
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

    private static void keyRequirements(String algorithm, String key, int min, int max, int stringIndex) {
        String[] keyText =
                {"+----------+---------------------+-------------+---------------------------------------------------------------------+\n",
                "| Cipher   | Min / Exact (bytes) | Max (bytes) |                            Requirements                             |\n",
                "| AES      |                          16/24/32 | Key must be exactly 10, 14, or 16 bytes (128, 192, 256 bits)        |\n",
                "| Blowfish |                   8 |        2048 | Key must be between 8-2048 bytes (32-442 bits)                      |\n",
                "| RC4      |                   1 |         256 | Key must be between 1-256 bytes (8-2048 bits)                       |\n",
                "| XOR      |                   1 |           n | Key must be between 1-n bytes (1-n bits)                            |\n",
                "| RSA      |                  64 |           n | Key must be between 64-n bytes (512-n bits)                         |\n",
                "| ECC      |                 163 |           n | Key must be between 512-n bytes (1024  bit - n  RSA/DSA equivalent) |\n"};

        if ((algorithm.toUpperCase().matches("-XOR|-RC4|-BLOWFISH|-RSA|-ECC") && (key.length() < min || key.length() > max)) ||
                (algorithm.equals("-AES") && key.length() != 16 && key.length() != 24 && key.length() != 32) || key.toUpperCase().equals("-INPUT"))  {
            System.out.println(keyText[0] + keyText[1] + keyText[0] + keyText[stringIndex] + keyText[0]);
            System.exit(0);
        }
        else if (stringIndex == 99)
        {
            System.out.println(keyText[0] + keyText[1] + keyText[0]);
            for (int i = 2; i < keyText.length; i++)
                System.out.println(keyText[i]);
            System.out.println(keyText[0]);
            System.exit(0);
        }
    }

    private static void generalRequirements() {
        String text =
        "+-----------+----------------+------------------+--------------------+-----------------+\n" +
        "|  Cipher   |      Key       |     -input       |    -encrypt or     |   force flag    |\n" +
        "|           |  (in bytes)    |  File or Folder  |    -decrypt        |       -f        |\n" +
        "+-----------+----------------+------------------+--------------------+-----------------+\n" +
        "| -AES      |       10/14/16 | text.txt         | Specify encryption | Skips           |\n" +
        "| -Blowfish |         8-2048 | ./Samples        | or decryption      | confirmation    |\n" +
        "| -RC4      |          1-256 |                  |                    | mode before the |\n" +
        "| -XOR      |            1-n |                  |                    | algorithm is    |\n" +
        "| -RSA      |           64-n |                  |                    | executed        |\n" +
        "| -ECC      |          163-n |                  |                    |                 |\n" +
        "+-----------+----------------+------------------+--------------------+-----------------+\n" +
        "| Example:  -AES 0123456789ABCDEF -input test.txt -encrypt -f                          |\n" +
        "|           -AES 0123456789ABCDEF -input test.txt -decrypt -f                          |\n" +
        "+----------+-----------------+------------------+--------------------+----------- -----+";

        System.out.println(text);
        System.exit(0);
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