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
 * 3. Optional: Enhance the capacity of the carrier:
 * -- Use the remaining two color channels;
 * -- Use additional bits.
 */
public class ImageSteganography {

    public static void main(String[] args) throws Exception {
        final byte[] payload = "My secret message".getBytes(StandardCharsets.UTF_8);

        // ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
        // final byte[] decoded = ImageSteganography.decode("images/steganogram.png", payload.length);
        // System.out.printf("Decoded: %s%n", new String(decoded, StandardCharsets.UTF_8));

        
        // TODO: Assignment 1
        // ImageSteganography.encode1(payload, "images/1_Kyoto.png", "images/steganogram.png");
        // final byte[] decoded1 = ImageSteganography.decode1("images/steganogram.png");
        // System.out.printf("Decoded: %s%n", new String(decoded1, "UTF-8"));

        
        // TODO: Assignment 2
        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        ImageSteganography.encryptAndEncode(payload, "images/2_Morondava.png", "images/steganogram-encrypted.png", key);
        final byte[] decoded2 = ImageSteganography.decryptAndDecode("images/steganogram-encrypted.png", key);

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
        encodeBits(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
    }

    public static void encode1(final byte[] pt, final String inFile, final String outFile) throws IOException {
        // load the image
        final BufferedImage image = loadImage(inFile);

        byte[] ptL = new byte[4];
        ptL[0] = (byte) (((pt.length / 65536) / 256) % 256);
        ptL[1] = (byte) ((pt.length / 65536) % 256);
        ptL[2] = (byte) ((pt.length / 256) % 256);
        ptL[3] = (byte) (pt.length % 256);

        System.out.println("ptL: " + pt.length);
        System.out.println("ptL: " + ptL[0]+ ptL[1]+ ptL[2]+ ptL[3]);

        byte[] concPT = new byte[pt.length + ptL.length];
        System.arraycopy(ptL, 0, concPT, 0, ptL.length);
        System.arraycopy(pt, 0, concPT, ptL.length, pt.length);

        // for (int i = 0; i < 10; i++) {
        //     System.out.println(i + ": " + concPT[i]);
        // }

        // Convert byte array to bit sequence
        final BitSet bits = BitSet.valueOf(concPT);

        // encode the bits into image
        encodeBits(bits, image);

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
        final BitSet bits = decodeBits(image, size);

        // convert them to bytes
        return bits.toByteArray();
    }

    public static byte[] decode1(final String fileName) throws IOException {
        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decodeBits1(image);

        byte[] ptL = bits.toByteArray();
        // System.out.println("pt: " + ptL[1] + "\n");

        int factor = 0;
        int length = 0;
        for (int i = 3; i > 0; i--) {
            factor *= 256;
            length += factor == 0 ? ptL[i] : ptL[i] * factor;
        }
        // System.out.println("length: " + length + "\n");
        
        byte[] arr2 = new byte[length];
        System.arraycopy(ptL, 4, arr2, 0, length);
        return arr2;
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

        final BufferedImage image = loadImage(inFile);

        byte[] ptL = new byte[4];
        ptL[0] = (byte) (((pt.length / 65536) / 256) % 256);
        ptL[1] = (byte) ((pt.length / 65536) % 256);
        ptL[2] = (byte) ((pt.length / 256) % 256);
        ptL[3] = (byte) (pt.length % 256);

        final Cipher encode = Cipher.getInstance("AES/GCM/NoPadding");
        encode.init(Cipher.ENCRYPT_MODE, key); 
        encode.updateAAD(ptL);
        final byte[] ct = encode.doFinal(pt);

        byte[] ctL = new byte[4];
        ctL[0] = (byte) (((ct.length / 65536) / 256) % 256);
        ctL[1] = (byte) ((ct.length / 65536) % 256);
        ctL[2] = (byte) ((ct.length / 256) % 256);
        ctL[3] = (byte) (ct.length % 256);

        final byte[] iv = encode.getIV();

        byte[] concat = new byte[8 + ct.length + iv.length];
        System.arraycopy(ptL, 0, concat, 0, 4);
        System.arraycopy(ctL, 0, concat, 4, 4);
        System.arraycopy(ct, 0, concat, 8, ct.length);
        System.arraycopy(iv, 0, concat, 8 + ct.length, iv.length);

        // Convert byte array to bit sequence
        final BitSet bits = BitSet.valueOf(concat);

        // encode the bits into image
        encodeBits(bits, image);

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
        
        final BufferedImage image = loadImage(fileName);

        final BitSet bits = decodeBits1(image);

        byte[] bytArr = bits.toByteArray();

        int factor = 0;
        int ptL = 0;
        for (int i = 3; i > 0; i--) {
            factor *= 256;
            ptL += factor == 0 ? bytArr[i] : bytArr[i] * factor;
        }

        factor = 0;
        int ctL = 0;
        for (int i = 7; i > 4; i--) {
            factor *= 256;
            ctL += factor == 0 ? bytArr[i] : bytArr[i] * factor;
        }
        System.out.println("ptL: " + ptL + "\n");
        System.out.println("ctL: " + ctL + "\n");
        
        byte[] ct = new byte[ctL];
        System.arraycopy(bytArr, 8, ct, 0, ctL);
        byte[] iv= new byte[12];
        System.arraycopy(bytArr, 8 + ct.length, iv, 0, 12);

        final Cipher decode = Cipher.getInstance("AES/GCM/NoPadding");
        final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
        decode.init(Cipher.DECRYPT_MODE, key, specs);
        decode.updateAAD(bytArr, 0, 4);
        final byte[] pt = decode.doFinal(ct);

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

    protected static BitSet decodeBits1(final BufferedImage image) {
        final BitSet bits = new BitSet();
        // final int sizeBits = 8 * size;

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
