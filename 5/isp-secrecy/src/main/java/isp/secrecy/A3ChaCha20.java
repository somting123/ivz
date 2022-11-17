package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

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
                 * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                 */
                for (int counter = 0; counter < 11; counter++) {
                    if (counter == 0) {
                            
                        byte[] nonce = new byte[12];
                        new SecureRandom().nextBytes(nonce);
                        
                        // print("[nonce]  : " + Agent.hex(nonce));
                        
                        // print("[PT]  : " + ' ' + counter + ' '  + message);
                        byte[] pt = message.getBytes();
                            
                        final Cipher encrypt = Cipher.getInstance("ChaCha20");
                        ChaCha20ParameterSpec chaParam = new ChaCha20ParameterSpec(nonce, counter);
                        encrypt.init(Cipher.ENCRYPT_MODE, key, chaParam);
                        byte[] cipherText = encrypt.doFinal(pt);
                        
                        print("[CT]" + Agent.hex(cipherText));
                        
                        send("bob", cipherText);
                        send("bob", nonce);
                    } else {

                        final byte[] receivedCipherText = receive("bob");
                        final byte[] nonce = receive("bob");
                        
                        Cipher decrypt = Cipher.getInstance("ChaCha20");
                        
                        ChaCha20ParameterSpec chaParam = new ChaCha20ParameterSpec(nonce, counter);
                        decrypt.init(Cipher.DECRYPT_MODE, key, chaParam);
                        final byte[] receivedMessage = decrypt.doFinal(receivedCipherText); 
    
                        print("[MB R] -" + counter + ' ' + new String(receivedMessage));

                        if (counter < 10) {
                            byte[] nonce2 = new byte[12];
                            new SecureRandom().nextBytes(nonce2);
                            // print("[nonce]  : " + Agent.hex(nonce));
                            
                            // print("[PT]  : " + counter + ' '  + message);
                            byte[] pt = message.getBytes();
                                
                            final Cipher encrypt = Cipher.getInstance("ChaCha20");
                            ChaCha20ParameterSpec chaParam2 = new ChaCha20ParameterSpec(nonce2, counter);
                            encrypt.init(Cipher.ENCRYPT_MODE, key, chaParam2);
                            byte[] cipherText = encrypt.doFinal(pt);
                            
                            print("[CT] " + Agent.hex(cipherText));
                            
                            send("bob", cipherText);
                            send("bob", nonce2);
                        }
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final String message2 = "I love you too, Alice. Kisses, Bob.";

                for(int counter = 0; counter < 10; counter++) {

                    final byte[] receivedCipherText = receive("alice");
                    final byte[] nonce = receive("alice");
                    
                    Cipher decrypt = Cipher.getInstance("ChaCha20");
                    
                    ChaCha20ParameterSpec chaParam = new ChaCha20ParameterSpec(nonce, counter);
                    decrypt.init(Cipher.DECRYPT_MODE, key, chaParam);
                    final byte[] receivedMessage = decrypt.doFinal(receivedCipherText); 

                    print("[MA R] -" + counter + " - " + new String(receivedMessage));



                    byte[] nonce2 = new byte[12];
                    new SecureRandom().nextBytes(nonce2);
                    // print("[nonce]  : " + Agent.hex(nonce));
                    
                    // print("[PT]  : " + ' ' + counter + ' '  + message2);
                    byte[] pt = message2.getBytes();
                        
                    final Cipher encrypt = Cipher.getInstance("ChaCha20");
                    ChaCha20ParameterSpec chaParam2 = new ChaCha20ParameterSpec(nonce2, counter + 1);
                    encrypt.init(Cipher.ENCRYPT_MODE, key, chaParam2);
                    byte[] cipherText = encrypt.doFinal(pt);
                    
                    print("[CT] "+ " - " + Agent.hex(cipherText));
                    
                    send("alice", cipherText);
                    send("alice", nonce2);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
