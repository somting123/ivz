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
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.BitSet;

/**
 * Assignments:
 * <p>
 * 1. Change the encoding process, so that the first 4 bytes of the steganogram hold the
 * length of the payload. Then modify the decoding process accordingly.
 * 2. Add security: Provide secrecy and integrity for the hidden message. Use GCM for cipher.
 * Also, use AEAD to provide integrity to the steganogram size.
 * 3. Extra: Enhance the capacity of the carrier:
 * -- Use the remaining two color channels;
 * -- Use additional bits.
 */
public class ImageSteganography {

    public static void main(String[] args) throws Exception {
        final byte[] payload = "HueHue".getBytes(StandardCharsets.UTF_8);

        /*
        ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
        final byte[] decoded = ImageSteganography.decode("images/steganogram.png", payload.length);
        System.out.printf("Decoded: %s%n", new String(decoded, StandardCharsets.UTF_8));
        */

        /*
        // TODO: Assignment 1
        ImageSteganography.encode1(payload, "images/1_Kyoto.png", "images/steganogram.png");
        final byte[] decoded1 = ImageSteganography.decode1("images/steganogram.png");
        System.out.printf("Decoded: '%s'.%n", new String(decoded1, "UTF-8"));
        */


        // TODO: Assignment 2
        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        ImageSteganography.encryptAndEncode(payload, "images/2_Morondava.png", "images/steganogram-encrypted.png", key);
        final byte[] decoded2 = ImageSteganography.decryptAndDecode("images/steganogram-encrypted.png", key);
        // final byte[] decoded2 = ImageSteganography.decode1("images/steganogram-encrypted.png");

        System.out.printf("Decoded: %s%n", new String(decoded2, "UTF-8"));

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

        // Convert byte array to bit sequence
        final BitSet bits = BitSet.valueOf(pt);

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
    }

    public static void encode1(final byte[] pt, final String inFile, final String outFile) throws IOException {
        // load the image
        final BufferedImage image = loadImage(inFile);

        // prepend the payload length
        byte[] lenpt = new byte[pt.length + 4];
        lenpt[0] = (byte) (pt.length / 16777216L);
        lenpt[1] = (byte) ((pt.length / 65536) % 256);
        lenpt[2] = (byte) ((pt.length / 256) % 256);
        lenpt[3] = (byte) (pt.length % 256);
        System.arraycopy(pt, 0, lenpt, 4, pt.length);

        // Convert byte array to bit sequence
        final BitSet bits = BitSet.valueOf(lenpt);

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
    }

    /**
     * Decodes the message from given filename.
     *
     * @param fileName The name of the file
     * @return The byte array of the decoded message
     * @throws IOException If the filename does not exist.
     */
    public static byte[] decode(final String fileName, int size) throws IOException {
        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decode(image, size);

        // convert them to bytes
        return bits.toByteArray();
    }

    public static byte[] decode1(final String fileName) throws IOException {
        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decode1(image);

        // convert them to bytes
        byte[] lenPT = bits.toByteArray();

        // extract payload length
        int len = 0;
        for (int i = 0; i < 4; i++) {
            len *= 256;
            len += lenPT[i] < 0 ? lenPT[i] + 256 : lenPT[i];
        }

        // return the payload
        byte[] ret = new byte[len];
        System.arraycopy(lenPT, 4, ret, 0, len);
        return ret;
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
    public static void encryptAndEncode(final byte[] pt, final String inFile, final String outFile, final Key key)
            throws Exception {
        // load the image
        final BufferedImage image = loadImage(inFile);

        // payload length header
        byte[] bytelen = {
                (byte) (pt.length / 16777216L),
                (byte) ((pt.length / 65536) % 256),
                (byte) ((pt.length / 256) % 256),
                (byte) (pt.length % 256)
        };

        // Encrypt the payload
        final Cipher ciph = Cipher.getInstance("AES/GCM/NoPadding");
        ciph.init(Cipher.ENCRYPT_MODE, key);
        ciph.updateAAD(bytelen);
        final byte[] ct = ciph.doFinal(pt);

        //ciphertext length header
        byte[] ciphlen = {
                (byte) (ct.length / 16777216L),
                (byte) ((ct.length / 65536) % 256),
                (byte) ((ct.length / 256) % 256),
                (byte) (ct.length % 256)
        };

        // copy data
        byte[] lenpt = new byte[ct.length + 20];
        System.arraycopy(ciphlen, 0, lenpt, 0, 4);
        System.arraycopy(bytelen, 0, lenpt, 4, 4);
        System.arraycopy(ct, 0, lenpt, 8, ct.length);
        System.arraycopy(ciph.getIV(), 0, lenpt, ct.length + 8, 12);

        // Convert byte array to bit sequence
        final BitSet bits = BitSet.valueOf(lenpt);

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
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
        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decode1(image);

        // convert them to bytes
        byte[] lenPT = bits.toByteArray();

        // extract ciphertext, payload length
        int ciphLen = 0;
        for (int i = 0; i < 4; i++) {
            ciphLen *= 256;
            ciphLen += lenPT[i] < 0 ? lenPT[i] + 256 : lenPT[i];
        }
        int ptLen = 0;
        for (int i = 4; i < 8; i++) {
            ptLen *= 256;
            ptLen += lenPT[i] < 0 ? lenPT[i] + 256 : lenPT[i];
        }

        // extract the ciphertext and IV
        byte[] ct = new byte[ciphLen];
        System.arraycopy(lenPT, 8, ct, 0, ciphLen);
        byte[] iv = new byte[12];
        System.arraycopy(lenPT, 8 + ciphLen, iv, 0, 12);

        // decrypt the message
        final Cipher ciph = Cipher.getInstance("AES/GCM/NoPadding");
        final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
        ciph.init(Cipher.DECRYPT_MODE, key, specs);
        ciph.updateAAD(lenPT, 4, 4);
        final byte[] pt = ciph.doFinal(ct);

        return pt;
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
    protected static void encode(final BitSet payload, final BufferedImage image) {
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
                // System.out.printf("%03d bit [%d, %d]: %s -> %s%n", bitCounter, i, j, original, modified);

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
    protected static BitSet decode(final BufferedImage image, int size) {
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

    protected static BitSet decode1(final BufferedImage image) {
        final BitSet bits = new BitSet();

        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth(); x++) {
            for (int y = image.getMinY(); y < image.getHeight(); y++) {
                final Color color = new Color(image.getRGB(x, y));
                final int lsb = color.getRed() & 0x01;
                bits.set(bitCounter, lsb == 0x01);
                bitCounter++;
            }
        }

        return bits;
    }
}
