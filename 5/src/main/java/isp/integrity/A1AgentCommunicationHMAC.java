package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import java.nio.charset.StandardCharsets;
import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                for(int i = 0; i < 11; i++) {
                    if (i == 0) {

                        final String text = "I hope you get this message intact. Kisses, Alice.";
                        final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                        final Mac alice = Mac.getInstance("HmacSHA256");
                        alice.init(key);
                        final byte[] tag1 = alice.doFinal(pt);

                        final String messageHmacAsString = Agent.hex(tag1);
                        System.out.println("Alice's HMAC: " + messageHmacAsString);
                        
                        send("bob", pt);
                        send("bob", tag1);
                    } else {
                        byte[] pt = receive("bob");
                        byte[] tag1 = receive("bob");
    
                        final Mac alice = Mac.getInstance("HmacSHA256");
                        alice.init(key);
                        final byte[] tag2 = alice.doFinal(pt);
    
                        boolean textHasTegridy = HMACExample.verify3(tag1, tag2, key);
                        print("Text intact: " + textHasTegridy);
                        print("[MR]: "+ i + " - " + new String(pt));


                        final String text = "It was! How 'bout this one?. Kisses, Alice.";
                        final byte[] pt2 = text.getBytes(StandardCharsets.UTF_8);
                        final byte[] tag21 = alice.doFinal(pt2);

                        final String messageHmacAsString = Agent.hex(tag21);
                        System.out.println("Alice's HMAC: " + messageHmacAsString);
                        
                        send("bob", pt2);
                        send("bob", tag21);
                    }
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                for(int i = 0; i < 10; i++) {

                    byte[] pt = receive("alice");
                    byte[] tag1 = receive("alice");

                    final Mac bob = Mac.getInstance("HmacSHA256");
                    bob.init(key);
                    final byte[] tag2 = bob.doFinal(pt);

                    boolean textHasTegridy = HMACExample.verify3(tag1, tag2, key);
                    print("Text intact: " + textHasTegridy);
                    print("[MR]: "+ i + " - " + new String(pt));


                    final String text = "It was intact. How 'bout this one?.";
                    final byte[] pt2 = text.getBytes(StandardCharsets.UTF_8);
                    final byte[] tag21 = bob.doFinal(pt2);

                    final String messageHmacAsString = Agent.hex(tag21);
                    System.out.println("Bob's HMAC: " + messageHmacAsString);
                    
                    send("alice", pt2);
                    send("alice", tag21);
                }
            }

        });

        env.connect("alice", "bob");
        env.start();
    }
}
