package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using a
 * AES in CBC mode
 * <p>
 * http://docs.oracle.com/javase/10/docs/technotes/guides/security/crypto/CryptoSpec.html#Cipher
 */
public class AgentCommunicationSymmetricCipher {
    public static String AES_CBC = "AES/CBC/PKCS5Padding";

    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message
                 *
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */
                final Cipher encryption = Cipher.getInstance(AES_CBC);
                encryption.init(Cipher.ENCRYPT_MODE, key);
                byte[] cipherText = encryption.doFinal(message.getBytes());

                print("Sent: " + Agent.hex(cipherText) + ", " + Agent.hex(encryption.getIV()));

                send("bob", cipherText);
                send("bob", encryption.getIV());
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
                final byte[] cipherText = receive("alice");
                final byte[] iv = receive("alice");

                final Cipher decryption = Cipher.getInstance(AES_CBC);
                decryption.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                byte[] message = decryption.doFinal(cipherText);

                print("Received: " + new String(message));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
