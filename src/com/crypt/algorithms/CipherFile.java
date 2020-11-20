package com.crypt.algorithms;

import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

public class CipherFile {

    private static final int MAX_BULK_SIZE = Integer.MAX_VALUE - 127;

    private String filePath;
    private int blockSize;

    private long fileLength;
    private long currentPos = 0;

    private RandomAccessFile inFile;

    private Path temp;
    private RandomAccessFile tempOutFile;

    /**
     * Creates new CipherFile
     * @param filePath Path to the file
     * @param blockSize Size of blocks for nextBlock()
     * @throws IOException if files could not be read
     * @throws IllegalBlockSizeException if block size is too large
     */
    public CipherFile (String filePath, int blockSize) throws IOException, IllegalBlockSizeException {
        if (blockSize > MAX_BULK_SIZE) throw new IllegalBlockSizeException("Block is too large");

        this.filePath = filePath;
        this.blockSize = blockSize;

        File file = new File(filePath);
        inFile = new RandomAccessFile(file, "r");
        this.fileLength = inFile.length();

        temp = Files.createTempFile(file.getName(), null);
        tempOutFile = new RandomAccessFile(temp.toFile(), "rw");
    }

    /**
     * Determines whether or not file has more bytes to read
     * @return true if file has more to read, else false
     */
    public boolean hasNext() {
        return currentPos >= fileLength;
    }

    /**
     * Gets next block of bytes from file
     * @param encryption
     * @return Next block of bytes, null if at EOF
     */
    public byte[] nextBlock(boolean encryption) {
        if (!hasNext()) return null;

        byte[] block;
        if (encryption)
            block = readDataAtOffset(currentPos, false, blockSize);
        else
            block = readDataAtOffset(currentPos+blockSize, true, blockSize);
        currentPos += block.length;
        return block;
    }

    /**
     * Resets current pos to 0
     */
    public void resetHead() {
        currentPos = 0;
    }

    /**
     * Sets current pos
     * @param pos The position to set to. If pos > fileLength, pos is set to fileLength
     */
    public void seekTo(long pos) {
        currentPos = Math.min(pos, fileLength);
    }

    /**
     * Reads data from file at offset
     * @param offset The byte offset
     * @param reverse If true, reads from offset from end of file
     * @param size The number of bytes to read
     * @return @size bytes, or less if EOF reached
     */
    public byte[] readDataAtOffset(long offset, boolean reverse, int size) {
        int blockSize = reverse?
                (size > offset ? (int)(offset) : size)
                :
                (size+offset > this.fileLength ? (int)(this.fileLength-offset) : size);

        byte[] data = new byte[blockSize];

        try {
            inFile.seek(reverse ? this.fileLength - offset : offset);
            inFile.read(data, 0, blockSize);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return data;
    }

    /**
     * Writes data at offset to temporary file. Will overwrite if overlapped. Use finish() to complete.
     * @param buffer The data to write
     * @param offset The byte offset
     * @param reverse If true, writes at offset from end of file
     */
    public void writeDataAtOffset(byte[] buffer, long offset, boolean reverse) {
        try {
            tempOutFile.seek(reverse ? tempOutFile.length() - offset : offset);
            tempOutFile.write(buffer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Writes data at EOF to temporary file. Will overwrite if overlapped. Use finish() to complete.
     * @param buffer The data to write
     */
    public void writeData(byte[] buffer) {
        writeDataAtOffset(buffer, 0, true);
    }

    /**
     * Pseudo-truncation. Reader will ignore these bytes
     *
     * @param size The number of bytes to truncate
    */
    public void truncate(long size) {
        this.fileLength -= size;
    }

    /**
     * Replaces file with its encryption/decryption
     * @param encryption Adds crypt ext if true, else removes crypt ext
     * @return True if successful
     */
    public boolean finish(boolean encryption) {
        try {
            Path newFilePath = Paths.get(
                    encryption ?
                    Utilities.setEncryptedExtension(filePath)
                    :
                    Utilities.setNormalExtension(filePath)
            );

            Files.copy(temp, newFilePath, StandardCopyOption.REPLACE_EXISTING);

            tempOutFile.close();
            inFile.close();
            Utilities.deleteFile(this.filePath);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Alternate for finish(true)
     * @return True if successful
     */
    public boolean finishEncryption() {
        return finish(true);
    }

    /**
     * Alternate for finish(false)
     * @return True if successful
     */
    public boolean finishDecryption() {
        return finish(false);
    }

}
