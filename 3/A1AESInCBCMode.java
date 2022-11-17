package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * AES in CBC mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AESInCBCMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                System.out.println("[MESSAGE] " + message);
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */
                byte[] pt = message.getBytes();
                System.out.println("[PT] " + Agent.hex(pt));

                final Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                encrypt.init(Cipher.ENCRYPT_MODE, key);
                final byte[] cipherText = encrypt.doFinal(pt);
                final byte[] iv = encrypt.getIV();

                System.out.println("[CT] " + Agent.hex(cipherText));

                for (int i = 0; i < 10; i++) {
                    send("bob", iv);
                    send("bob", cipherText);
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */
                final byte[] iv = receive("alice");
                IvParameterSpec ivSpec = new IvParameterSpec(iv);

                final byte[] cipherText = receive("alice");
                final Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);
                final byte[] dt = decrypt.doFinal(cipherText);
                System.out.println("[PT] " + Agent.hex(dt));
                System.out.println("[MESSAGE] " + new String(dt));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
