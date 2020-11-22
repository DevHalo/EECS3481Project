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

    private final String filePath;
    private final int blockSize;
    private final boolean isEncryption;

    private long fileLength;
    private long currentPos = 0;

    private final Path tempPath;
    private final RandomAccessFile tempFile;

    /**
     * Creates new CipherFile
     * @param filePath Path to the file
     * @param blockSize Size of blocks for nextBlock()
     * @throws IOException if files could not be read
     * @throws IllegalBlockSizeException if block size is too large
     */
    public CipherFile (String filePath, int blockSize, boolean isEncryption) throws IOException, IllegalBlockSizeException {

        if (blockSize > MAX_BULK_SIZE) throw new IllegalBlockSizeException("Block is too large");

        this.filePath = filePath;
        this.blockSize = blockSize;
        this.isEncryption = isEncryption;

        File file = new File(filePath);

        this.tempPath = Files.createTempFile(file.getName(), null);
        Files.copy(Paths.get(filePath), this.tempPath, StandardCopyOption.REPLACE_EXISTING);

        this.tempFile = new RandomAccessFile(this.tempPath.toFile(), "rw");
        this.fileLength = this.tempFile.length();
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
     * @param encryption Determines direction (true->forward, false->reverse)
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

    public long getCurrentPos() {
        return currentPos;
    }

    /**
     * Sets current pos
     * @param pos The position to set to. If pos > fileLength, pos is set to fileLength
     */
    public void seekTo(long pos) {
        currentPos = Math.min(pos, fileLength);
    }

    /**
     * Pads the file using PKCS#5. (BLOCK SIZE MUST BE < 255 bytes
     */
    public void pad() {
        byte padding = (byte) (blockSize - (fileLength % blockSize));
        if (padding == 0) padding = (byte)blockSize;
        byte[] pad = new byte[padding];
        for (byte i = 0; i < padding; i++)
            pad[i] = padding;
        writeDataEOF(pad);
    }

    /**
     * Unpads the file
     */
    public void unpad() {

        byte padding = readDataAtOffset(1, true, 1)[0];
        byte[] pad = readDataAtOffset(padding, true, padding);

        // Verify padding
        for (byte p : pad) {
            if (p != padding) {
                System.out.println("File was not padded correctly. Aborting decryption.");
                System.exit(-1);
            }
        }

        this.truncate(padding);
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
            tempFile.seek(reverse ? this.fileLength - offset : offset);
            tempFile.read(data, 0, blockSize);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
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
            long pos = reverse ? tempFile.length() - offset : offset;
            tempFile.seek(pos);
            tempFile.write(buffer);
            fileLength = Math.max(pos+buffer.length, fileLength);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Writes data to EOF to temporary file. Use finish() to complete.
     * @param buffer The data to write
     */
    public void writeDataEOF(byte[] buffer) {
        writeDataAtOffset(buffer, 0, true);
    }

    /**
     * Pseudo-truncation. Reader will ignore these bytes. Bytes are truncated on finish() call
     * @param size The number of bytes to truncate
    */
    public void truncate(long size) {
        this.fileLength -= size;
    }

    /**
     * Replaces file with its encryption/decryption
     * @return True if successful
     */
    public boolean finish() {
        try {
            Path newFilePath = Paths.get(
                    this.isEncryption ?
                    Utilities.setEncryptedExtension(filePath)
                    :
                    Utilities.setNormalExtension(filePath)
            );

            tempFile.setLength(fileLength);
            Files.copy(tempPath, newFilePath, StandardCopyOption.REPLACE_EXISTING);

            tempFile.close();
            Utilities.deleteFile(this.filePath);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

}
