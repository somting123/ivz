package isp.integrity;

import sun.security.provider.SHA;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

/**
 * Modified implementation of SHA-1 algorithm that allows the caller
 * to set the internal state of the algorithm.
 * <p>
 * Internally, this class instantiates a default implementation of SHA-1 that
 * is provided by Oracle in class  {@link sun.security.provider.SHA sun.security.provider.SHA}.
 * <p>
 * The default implementation, however, does not allow you to manually set the internal
 * state of the algorithm. The reason is that the variables that hold the internal state,
 * are declared private. To work around this limitation, this class wraps the default implementation
 * and grants access to required state fields by using reflection.
 */
class ModifiedSHA1 {
    /**
     * SHA-1 uses 512-bit (64-byte) block size
     */
    final static int BLOCK_SIZE = 64;

    /**
     * The longest padding can have 65-bytes
     */
    final static byte[] PADDING = new byte[65];

    static {
        PADDING[0] = (byte) 0x80;
    }

    private final SHA alg = new SHA();

    /**
     * Updates the digest using the specified array of bytes.
     *
     * @param input the array of bytes.
     */
    public void update(byte[] input) {
        try {
            final Method m = alg.getClass().getSuperclass().getDeclaredMethod(
                    "engineUpdate", byte[].class, int.class, int.class);
            m.setAccessible(true);
            m.invoke(alg, input, 0, input.length);
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    /**
     * Completes the hash computation by performing final operations such as padding.
     * The digest is reset after this call is made.
     *
     * @return the array of bytes for the resulting hash value.
     */
    public byte[] digest() {
        try {
            final Method method = alg.getClass().getSuperclass().getDeclaredMethod("engineDigest");
            method.setAccessible(true);
            return (byte[]) method.invoke(alg);
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    /**
     * Sets the internal state of the algorithm.
     *
     * @param state      byte array representing the state
     * @param blockCount number of blocks that have been hashed so far
     *                   (depends on the length of the message and the length of the secret)
     */
    public void setState(byte[] state, long blockCount) {
        final ByteBuffer buffer = ByteBuffer.wrap(state);
        final int[] stateAsInt = {buffer.getInt(0), buffer.getInt(4),
                buffer.getInt(8), buffer.getInt(12), buffer.getInt(16)
        };

        try {
            // set the initial state
            final Field stateField = alg.getClass().getDeclaredField("state");
            stateField.setAccessible(true);
            stateField.set(alg, stateAsInt);

            // set the number of processed bytes
            final Field processedField = alg.getClass().getSuperclass().getDeclaredField("bytesProcessed");
            processedField.setAccessible(true);
            processedField.set(alg, BLOCK_SIZE * blockCount);
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    public static void main(String[] args) throws Exception {
        final Random random = new Random();
        final byte[] someBytes = new byte[1024 * 1024];
        random.nextBytes(someBytes);

        // Using JCA to compute the digest
        final MessageDigest jcaSha1 = MessageDigest.getInstance("SHA-1");
        jcaSha1.update(someBytes);

        // Using ModifiedSHA1 to compute the digest
        final ModifiedSHA1 modifiedSHA1 = new ModifiedSHA1();
        modifiedSHA1.update(someBytes);

        System.out.printf("Are digests the same? %s",
                Arrays.equals(jcaSha1.digest(), modifiedSHA1.digest()));
    }
}
