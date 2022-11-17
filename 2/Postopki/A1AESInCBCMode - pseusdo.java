package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * AES in CTR mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AESInCBCMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        
        final Key key = KeyGenerator.getInstance("AES").generateKey();
        Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        // Za CTR je 
        Cipher aesCBC = Cipher.getInstance("AES/CBC/NoPadding");
        
        //Za ChaCha20 je
        Cipher chaCha20  = Cipher.getInstance("ChaCha20");
        byte [] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        int counter = 5;
        
        
        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                
                // A to B za A
                byte [] plainTextBytes = "I love you Bob. Kisses, Alice.".getBytes();
                
                aesCBC.init(Cipher.ENCRYPT_MODE, key);
                byte [] cipherTextBytes = aesCBC.init(plainTextBytes);
                byte [] iV = aesCBC.getIV();
                
                send("bob",cipherTextBytes);
                send("bob", iV);
                
                // B to A
                byte [] receivedCTBytes = receve("alice");
                byte [] iV = receive("alice");
                aesCBC.init(CipherMode.DECRYPT, new IvParameterSpec(iv));
                byte message  = aesCBC.doFinal(receivedCTBytes);
                
                // Za B obrneš prejemnike/pošiljatelje.
                
                // Za CHACHA20 
                chaCha20.init(CipherMode.ENCRYPT, new ChaCha20ParameterSpec(nonce, counter));
                chaCha20.init(CipherMode.DECRYPT, new ChaCha20ParameterSpec(nonce, counter));
                
                    }
                }
            }
        });
        env.connect("alice", "bob");
        env.start();
    }
}
