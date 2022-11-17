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
 * AES in counter mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AESInCTRMode {
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
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */
                for(int i = 0; i < 11; i++) {
                    if (i == 0) {
                        
                        final byte[] pt = (message + " " + i).getBytes();
                        // print("[PT] " + i + " - "  + Agent.hex(pt));
                        
                        final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
                        encrypt.init(Cipher.ENCRYPT_MODE, key);
                        final byte[] cipherText = encrypt.doFinal(pt);
                        
                        print("[CT] " + i + " - " + Agent.hex(cipherText));
                        // print("[IV S] " + Agent.hex(encrypt.getIV()));
                        send("bob", cipherText);
                        send("bob", encrypt.getIV());

                    } else {
                        final byte[] receivedCipherText = receive("bob");
                        final byte[] receivedIV = receive("bob");

                        Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");
                        decrypt.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(receivedIV));
                        final byte[] receivedMessage = decrypt.doFinal(receivedCipherText); 
                        print("[MR] " + i + " - " + new String(receivedMessage));
                        
                        if (i < 10) {
                            final byte[] pt = (message + " " + i).getBytes();
                            // print("[PT] " + i + " - " + Agent.hex(pt));
                            
                            Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");
                            
                            encrypt.init(Cipher.ENCRYPT_MODE, key);
                            byte[] cipherText = encrypt.doFinal(pt);
                            print("[CT] " + i + " - " + Agent.hex(cipherText));
                            send("bob", cipherText);
                            send("bob", encrypt.getIV());
                        }
                    }
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
                for(int i = 0; i < 10; i++) {
                    final byte[] receivedCipherText = receive("alice");
                    final byte[] receivedIV = receive("alice");
                    
                    Cipher decrypt = Cipher.getInstance("AES/CTR/NoPadding");
                    
                    IvParameterSpec ivSpec = new IvParameterSpec(receivedIV);
                    decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);
                    
                    final byte[] receivedMessage = decrypt.doFinal(receivedCipherText); 
                    print("[MA R] " + i + " - " + new String(receivedMessage));
                    
                    final String messageB = "I love you too, Alice. Kisses, Bob.";
                    final byte[] pt = messageB.getBytes();
                    // print("[PT] " + Agent.hex(pt));

                    final Cipher encrypt = Cipher.getInstance("AES/CTR/NoPadding");

                    encrypt.init(Cipher.ENCRYPT_MODE, key, ivSpec);
                    final byte[] cipherText = encrypt.doFinal(pt);

                    print("[CT S] " + i + " - " + Agent.hex(cipherText));
                    // print("[IV S] " + Agent.hex(encrypt.getIV()));
                    send("alice", cipherText);
                    send("alice", encrypt.getIV());
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
