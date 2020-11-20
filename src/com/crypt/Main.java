package com.crypt;

import com.crypt.algorithms.*;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Main {

    /**
     * The main entry point of the application
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        switch (args.length) {
            case 0:
                // If user supplies no arguments, show basic usage and option for more information
                generalRequirements();
                System.out.println("See -help or -help-algos for more information");
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
                    System.out.println("The application supports the following algorithms:\n" +
                            "+-----------+------------+\n" +
                            "| Symmetric | Asymmetric |\n" +
                            "+-----------+------------+\n" +
                            "| AES       | ECC        |\n" +
                            "| BLOWFISH  | RSA        |\n" +
                            "| RC4       |            |\n" +
                            "| XOR       |            |\n" +
                            "+-----------+------------+");
                    keyRequirements("", "");
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
                        System.exit(-1);
                    }
                }

                // Find -input or -i argument in args
                List<File> files = new ArrayList<>();
                for (int i = 0; i < args.length; i++) {
                    if (args[i].matches("-INPUT|-I|-i|-input")) {
                        if (args.length - 1 == i) {
                            System.out.println("No file specified for input parameter.");
                            System.exit(-1);
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
                                System.exit(-1);
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
                                System.exit(-1);
                            }
                            algorithm = args[i].toUpperCase();
                            algoIndex = i + 1;
                            break;
                        }
                    }

                    if (algorithm.isEmpty()) {
                        System.out.println("An invalid algorithm was specified." +
                                " See --help-algos for more info.");
                        System.exit(-1);
                    }

                    int prompt;
                    for (File f : files) {
                        if (f.isDirectory()) {
                            System.out.printf("The folder %s is about to be %s%n", f.getName(),
                                    encrypt ? "encrypted." : "decrypted.");
                            continue;
                        } else {
                            System.out.printf("The file %s is about to be %s%n",
                                    f.getName(), encrypt ? "encrypted." : "decrypted.");
                        }

                        // To prevent accidental encryption/decryption, the user will be prompted before executing
                        // any algorithm for EACH file.
                        if (Arrays.stream(args).noneMatch(str ->
                                str.toUpperCase().equals("-FORCE") || str.toUpperCase().equals("-F"))) {
                            System.out.println("Are you sure you want to continue? (YES/Y)." +
                                    " (C) will skip this file. Otherwise program will exit.");

                            prompt = declinePrompt(in);

                            if (prompt == 0) System.exit(-1);
                            else if (prompt == -1) continue;

                            if (f.getName().endsWith(Utilities.ENCRYPTED_EXTENSION) && encrypt) {
                                System.out.printf("This file already has the %s extension. Are you sure you want to" +
                                        " continue? (YES/Y). (C) will skip this file. " +
                                        "Otherwise program will exit.", Utilities.ENCRYPTED_EXTENSION);

                                prompt = declinePrompt(in);
                                if (prompt == 0) System.exit(-1);
                                else if (prompt == -1) continue;
                            }
                        }

                        String key = args[algoIndex];

                        keyRequirements(algorithm, key);

                        if (dry) {
                            System.out.println("-dry was selected. Skipping algorithm execution.");
                            continue;
                        }

                        if (Utilities.isSymmetric(algorithm)) {
                            Utilities.cryptSymmetric(algorithm, f.getAbsolutePath(), key.getBytes(), encrypt);
                        } else {
                            // TODO
                            Utilities.cryptAsymmetric(algorithm, f.getAbsolutePath(), key.getBytes(), encrypt);
                        }

                        System.out.printf("%s was successfully %s ", f.getName(),
                                encrypt ? "encrypted." : "decrypted.");
                    }
                } else {
                    System.out.println("The file/folder does not exist.");
                    System.exit(-1);
                }

                System.out.println("Application exiting.");
                break;
        }
    }

    /**
     * Output information regarding a cipher's key requirements if the user
     * entered an invalid key.
     */
    private static void keyRequirements(String algorithm, String key) {
        if (algorithm.startsWith("-")) algorithm = algorithm.substring(1);

        Map<String, String> requirementStrings = new LinkedHashMap<String, String>() {{
            put("DIVIDER",
                    "+----------+-------------+-------------+---------------------------------------------------+\n");
            put("TITLE",
                    "| Cipher   | Min (bytes) | Max (bytes) |                   Requirements                    |\n");
            put("AES",
                    "| AES      |        16 / 24 / 32       | 16, 24, or 32 bytes (128, 192, 256 bits)          |\n");
            put("BLOWFISH",
                    "| Blowfish |      8      |     2048    | 8 - 2048 bytes (32 - 442 bits)                    |\n");
            put("RC4",
                    "| RC4      |      1      |     256     | 1 - 256 bytes (8 - 2048 bits)                     |\n");
            put("XOR",
                    "| XOR      |      1      |     n       | At least 1 byte (8+ bits)                         |\n");
            put("RSA",
                    "| RSA      |      64     |     n       | At least 64 bytes (512+ bits)                     |\n");
            put("ECC",
                    "| ECC      |      128    |     n       | At least 512 bytes (1024+ bit RSA/DSA equivalent) |\n");
        }};

        Map<String, int[]> keyRanges = new LinkedHashMap<String, int[]>() {{
           put("AES", new int[] {16, 32});
           put("BLOWFISH", new int[] {8, 2048});
           put("RC4", new int[] {1, Integer.MAX_VALUE});
           put("RSA", new int[] {64, Integer.MAX_VALUE});
           put("ECC", new int[] {128, Integer.MAX_VALUE});
           put("XOR", new int[] {1, Integer.MAX_VALUE});
        }};

        if (algorithm.isEmpty()) {
            System.out.print(requirementStrings.get("DIVIDER") +
                    requirementStrings.get("TITLE") +
                    requirementStrings.get("DIVIDER"));

            for (String reqString : requirementStrings.keySet()) {
                if (!reqString.equals("DIVIDER") && !reqString.equals("TITLE")) {
                    System.out.print(requirementStrings.get(reqString));
                }
            }

            System.out.println(requirementStrings.get("DIVIDER"));

            System.exit(0);
        } else if ((key.length() < keyRanges.get(algorithm)[0] || key.length() > keyRanges.get(algorithm)[1]) ||
                (algorithm.equals("AES") && key.length() != 16 && key.length() != 24 && key.length() != 32) ||
                key.toUpperCase().equals("-INPUT")) {

            System.out.println("Key supplied did not satisfy requirements. See below:\n");

            System.out.print(requirementStrings.get("DIVIDER") +
                    requirementStrings.get("TITLE") +
                    requirementStrings.get("DIVIDER") +
                    requirementStrings.get(algorithm) +
                    requirementStrings.get("DIVIDER"));

            System.exit(-1);
        }
    }

    /**
     * Prints a table listing all the features of the application
     */
    private static void generalRequirements() {
        String t = "+-----------+------------+---------------+-----------------+-----------------+---------------+\n" +
                "|  Cipher   |    Key     |    -input     |   -encrypt or   |       -f        |     -dry      |\n" +
                "|           | (in bytes) | File / Folder |   -decrypt      |   Force Mode    |      Dry      |\n" +
                "+-----------+----------------+-----------+-----------------+-----------------+---------------+\n" +
                "| -AES      |   16/24/32 | text.txt      | Specify encrypt | Skips           | Run program   |\n" +
                "| -Blowfish |     8-2048 | ./Samples     | or decrypt mode | confirmation    | without       |\n" +
                "| -RC4      |      1-256 |               |                 | mode before the | executing any |\n" +
                "| -XOR      |        1-n |               |                 | algorithm is    | of the        |\n" +
                "| -RSA      |       64-n |               |                 | executed        | algorithms    |\n" +
                "| -ECC      |      163-n |               |                 |                 |               |\n" +
                "+-----------+------------+---------------+-----------------+-----------------+---------------+\n" +
                "| Example:  -AES 0123456789ABCDEF -input test.txt -encrypt -f                                |\n" +
                "|           -AES 0123456789ABCDEF -input test.txt -decrypt -f                                |\n" +
                "+-----------+------------+---------------+-----------------+-----------------+---------------+";
        System.out.println(t);
    }

    /**
     * Returns 1 if the user answers "yes" or "y" after prompting the user.
     * Return
     * The answer is case-insensitive.
     *
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
