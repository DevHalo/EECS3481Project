package com.crypt;

import com.crypt.algorithms.XOR;
import com.crypt.algorithms.Utilities;

import java.io.File;
import java.util.List;

import static java.lang.Thread.sleep;


public class Main {

    public static void main(String[] args) {

        String fileName = "Justice.League.Dark.Apokolips.War.2020.1080p.WEBRip.DD5.1.x264-CM.mkv";
        //String fileName = "51QYvscjWjL._AC_SL1000_.jpg";
        String key = "MMAAD";
//        XOR.xorFile(fileName, key.getBytes(), true);
//        //Source:
//        //https://docs.oracle.com/javase/tutorial/essential/concurrency/sleep.html
//
//        try {
//            sleep(5000);
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        }
//        XOR.xorFile(fileName + utilities.encryptedExtension, key.getBytes(), false);

//        File[] buffer = utilities.iterateThroughFolder("C:\\Users\\DJ\\Downloads\\Test");

        List<File> buffer = Utilities.fileOrFolder(new File("/Users/dj/Downloads/TEST"));

//        for (File elements : buffer)
//        {
//            if (!elements.isDirectory()) {
//                XOR.xorFile(elements.toString(), key.getBytes(), true);
//            }
//        }

        for (File elements : buffer)
        {
            if (!elements.isDirectory()) {
                try {
                    sleep(5000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                XOR.xorFile(elements.toString(), key.getBytes(), false);
            }
        }
    }
}