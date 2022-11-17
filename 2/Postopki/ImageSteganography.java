package isp.steganography;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Array;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.BitSet;

import static java.util.Arrays.copyOfRange;

/**
 * Assignments:
 * <p>
 * 1. Change the encoding process, so that the first 4 bytes of the steganogram hold the
 * length of the payload. Then modify the decoding process accordingly.
 * 2. Add security: Provide secrecy and integrity for the hidden message. Use GCM for cipher.
 * Also, use AEAD to provide integrity to the steganogram size.
 * 3. Optional: Enhance the capacity of the carrier:
 * -- Use the remaining two color channels;
 * -- Use additional bits.
 */
public class ImageSteganography {

    public static void main(String[] args) throws Exception {
        final byte[] payload = "My secret message".getBytes(StandardCharsets.UTF_8);

        ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram1.png");
        final byte[] decoded = ImageSteganography.decode("images/steganogram1.png", payload.length);
        System.out.printf("Decoded: %s%n", new String(decoded, StandardCharsets.UTF_8));

        /*
        TODO: Assignment 1
        */
        ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram1.png");
        final byte[] decoded1 = ImageSteganography.decode("images/steganogram1.png");
        System.out.printf("Decoded: %s%n", new String(decoded1, "UTF-8"));

        /*
        TODO: Assignment 2
        */
        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        ImageSteganography.encryptAndEncode(payload, "images/2_Morondava.png", "images/steganogram-encrypted.png", key);
        final byte[] decoded2 = ImageSteganography.decryptAndDecode("images/steganogram-encrypted.png", key);

        System.out.printf("Decoded and decrypted: %s%n", new String(decoded2, "UTF-8"));
    }

    /**
     * Encodes given payload into the cover image and saves the steganogram.
     *
     * @param pt      The payload to be encoded
     * @param inFile  The filename of the cover image
     * @param outFile The filename of the steganogram
     * @throws IOException If the file does not exist, or the saving fails.
     */
    public static void encode(final byte[] pt, final String inFile, final String outFile) throws IOException {
        // load the image
        final BufferedImage image = loadImage(inFile);

        final byte [] paddedPt  = ByteBuffer.allocate(pt.length + 4).putInt(pt.length).put(pt).array();
        // Convert byte array to bit sequence
        final BitSet bits = BitSet.valueOf(paddedPt);

        // encode the bits into image
        encodeBits(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
    }

    /**
     * Decodes the message from given filename.
     *
     * @param fileName The name of the file
     * @param size The payload size
     * @return The byte array of the decoded message
     * @throws IOException If the filename does not exist.
     */
    public static byte[] decode(final String fileName, int size) throws IOException {
        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decodeBits(image, size);

        // convert them to bytes
        return bits.toByteArray();
    }

    /**
     * Decodes the message from given filename.
     *
     * @param fileName The name of the file
     * @return The byte array of the decoded message
     * @throws IOException If the filename does not exist.
     */
    public static  byte[] decode(final String fileName) throws  IOException {

        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decodeBits(image);

        // convert them to bytes
        final byte[] bytes =  bits.toByteArray();
        return copyOfRange(bytes, 4, bytes.length);
    }

    /**
     * Encrypts and encodes given plain text into the cover image and then saves the steganogram.
     *
     * @param pt      The plaintext of the payload
     * @param inFile  cover image filename
     * @param outFile steganogram filename
     * @param key     symmetric secret key
     * @throws Exception
     */
    /*public static void encryptAndEncode(final byte[] pt, final String inFile, final String outFile, final Key key)
            throws Exception {

        //Attempt 2
        final Cipher enc = Cipher.getInstance("AES/GCM/NoPadding");
        enc.init(Cipher.ENCRYPT_MODE,key);
        final byte [] iv = enc.getIV();

        enc.updateAAD(iv);
        final byte[] ct = enc.doFinal(pt);

        byte[] content = new byte[iv.length + ct.length];

        for(int i = 0; i < content.length; i++){
            //Insert the IV.
            if(i < iv.length){
                Array.setByte(content,i,iv[i]);
            }

            // Insert the encrypted text
            else {
                Array.setByte(content,i, ct[i - iv.length]);
            }
        }

        encode(content, inFile, outFile);
    }

    /**
     * Decrypts and then decodes the message from the steganogram.
     *
     * @param fileName name of the steganogram
     * @param key      symmetric secret key
     * @return plaintext of the decoded message
     * @throws Exception
     */
   /* public static byte[] decryptAndDecode(final String fileName, final Key key) throws Exception {

        // Init a dummy cipher to get a dummy IV, and it's length.
        final Cipher dummyCipher = Cipher.getInstance("AES/GCM/NoPadding");
        dummyCipher.init(Cipher.ENCRYPT_MODE, key);
        final int iVLength = dummyCipher.getIV().length;

        // Get the IV plus encrypted text.
        final byte[] decoded = decode(fileName,12+33);

        // Get the ct length.
        final int ctLength = decoded.length - iVLength;
        byte[] originalIv = new byte[iVLength];
        byte[] ctPlusTag = new byte[ctLength];
/*
        for (int i = 4; i < decoded.length; i++) {

            // First N bytes are the iv.

            if (i < iVLength+4) {
                Array.setByte(originalIv, i, decoded[i]);
            }
            // Others ones are ct bytes.
            else if (i >= iVLength+4) {
                Array.setByte(ctPlusTag, i - iVLength, decoded[i]);
            }
        }

        byte [] iv = Arrays.copyOfRange(
                originalIv,
          4      ,
                originalIv.length
        );

        //Get integrity tag from old CT bytes.
        final byte[] oldTag = Arrays.copyOfRange(
                ctPlusTag,
                ctPlusTag.length - 16,
                ctPlusTag.length
        );

        /* Ta tag ni kul
        byte[] tag2 = new byte[]{
                0,0,0,45
        };

        final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
        decrypt.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));

        decrypt.updateAAD(fileName.getBytes());
        var t = Arrays.copyOfRange(

                ctPlusTag,
                0,
                ctPlusTag.length-16
        );

        /*return decrypt.doFinal(Arrays.copyOfRange(

                ctPlusTag,
                0,
                ctPlusTag.length-16
        ));
        return decrypt.doFinal(ctPlusTag);
        //Tried a few times, but thats the best solution I can com up with.
    }*/
    /**
     * Encrypts and encodes given plain text into the cover image and then saves the steganogram.
     *
     * @param pt      The plaintext of the payload
     * @param inFile  cover image filename
     * @param outFile steganogram filename
     * @param key     symmetric secret key
     * @throws Exception
     */
    public static void encryptAndEncode(final byte[] pt, final String inFile, final String outFile, final Key key)
            throws Exception {

        final Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] iv = encrypt.getIV();

        byte[] file  = outFile.getBytes();
        encrypt.updateAAD(outFile.getBytes());
        byte[] ctPlusTag = encrypt.doFinal(pt);

        // Get the new array that holds the tag, unencrypted IV with the encrypted message.
        int ivPlusCipherTextLength = iv.length + ctPlusTag.length;
        byte[] ivPlusCipherTextBytes = new byte[ivPlusCipherTextLength];

        for(int i = 0; i < ivPlusCipherTextLength; i++){
            if(i < iv.length){
                Array.setByte(ivPlusCipherTextBytes,i,iv[i]);
            }
            else{
                Array.setByte(ivPlusCipherTextBytes,i, ctPlusTag[i - iv.length]);
            }
        }

        encode(ivPlusCipherTextBytes, inFile, outFile);
    }

    /**
     * Decrypts and then decodes the message from the steganogram.
     *
     * @param fileName name of the steganogram
     * @param key      symmetric secret key
     * @return plaintext of the decoded message
     * @throws Exception
     */

    public static byte[] decryptAndDecode(final String fileName, final Key key) throws Exception {

        // Init a dummy cipher to get a dummy IV, and it's length.
        final Cipher dummyCipher = Cipher.getInstance("AES/GCM/NoPadding");
        dummyCipher.init(Cipher.ENCRYPT_MODE, key);
        final int iVLength = dummyCipher.getIV().length;

        // Get the IV plus encrypted text.
        final byte[] decoded = decode(fileName);

        // Get the ct length.
        final int ctLength = decoded.length - iVLength;
        byte [] originalIv = new byte[iVLength];
        byte [] ctPlusTag = new byte[ctLength];

        for(int i = 0; i < decoded.length;i++){

            // First N bytes are the iv.
            if(i < iVLength ){
                Array.setByte(originalIv,i,decoded[i]);
            }
            // Others ones are ct bytes.
            else{
                Array.setByte(ctPlusTag,i - iVLength, decoded[i]);
            }
        }

        //Get integrity tag from old CT bytes.
        final byte[] oldTag = Arrays.copyOfRange(
                ctPlusTag,
                ctPlusTag.length - 16,
                ctPlusTag.length
        );

        final Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
        decrypt.init(Cipher.DECRYPT_MODE, key ,new GCMParameterSpec(128,originalIv));

        decrypt.updateAAD(fileName.getBytes());

        return decrypt.doFinal(ctPlusTag);
    }


    /**
     * Loads an image from given filename and returns an instance of the BufferedImage
     *
     * @param inFile filename of the image
     * @return image
     * @throws IOException If file does not exist
     */
    protected static BufferedImage loadImage(final String inFile) throws IOException {
        return ImageIO.read(new File(inFile));
    }

    /**
     * Saves given image into file
     *
     * @param outFile image filename
     * @param image   image to be saved
     * @throws IOException If an error occurs while writing to file
     */
    protected static void saveImage(String outFile, BufferedImage image) throws IOException {
        ImageIO.write(image, "png", new File(outFile));
    }

    /**
     * Encodes bits into image. The algorithm modifies the least significant bit
     * of the red RGB component in each pixel.
     *
     * @param payload Bits to be encoded
     * @param image   The image onto which the payload is to be encoded
     */
    protected static void encodeBits(final BitSet payload, final BufferedImage image) {
        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < payload.size(); x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < payload.size(); y++) {
                final Color original = new Color(image.getRGB(x, y));

                // Let's modify the red component only
                final int newRed = payload.get(bitCounter) ?
                        original.getRed() | 0x01 : // sets LSB to 1
                        original.getRed() & 0xfe;  // sets LSB to 0

                // Create a new color object
                final Color modified = new Color(newRed, original.getGreen(), original.getBlue());

                // Replace the current pixel with the new color
                image.setRGB(x, y, modified.getRGB());

                // Uncomment to see changes in the RGB components
                // System.out.printf("%03d bit [%d, %d]: %s -> %s%n", bitCounter, x, y, original, modified);

                bitCounter++;
            }
        }
    }

    /**
     * Decodes the message from the steganogram
     *
     * @param image steganogram
     * @param size  the size of the encoded steganogram
     * @return {@link BitSet} instance representing the sequence of read bits
     */
    protected static BitSet decodeBits(final BufferedImage image, int size) {
        final BitSet bits = new BitSet();
        final int sizeBits = 8 * size;

        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < sizeBits; x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < sizeBits; y++) {
                final Color color = new Color(image.getRGB(x, y));
                final int lsb = color.getRed() & 0x01;
                bits.set(bitCounter, lsb == 0x01);
                bitCounter++;
            }
        }

        return bits;
    }

    /**
     * Decodes the message from the steganogram
     *
     * @param image steganogram
     * @return {@link BitSet} instance representing the sequence of read bits
     */
    protected static BitSet decodeBits(final BufferedImage image) {
        final BitSet bits = new BitSet();
        int sizeBits = 32;

        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < sizeBits; x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < sizeBits; y++) {
                final Color color = new Color(image.getRGB(x, y));
                final int lsb = color.getRed() & 0x01;
                bits.set(bitCounter, lsb == 0x01);
                bitCounter++;

                if(bitCounter == 32) {
                   sizeBits += 8 * ByteBuffer.wrap(bits.toByteArray()).getInt();
                }
            }
        }

        return bits;
    }
}
