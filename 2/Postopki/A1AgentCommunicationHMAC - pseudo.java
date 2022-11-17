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
        final Mac a = Mac.getInstance("HmacSHA256");
        a.init(key);

        final Environment env = new Environment();

            env.add(new Agent("alice") {
                @Override
                public void task() throws Exception {

                    // A to B za A
                    byte[] plainTextBytes = "I love you Bob. Kisses, Alice.".getBytes(StandardCharsets.UTF_8);
                    byte[] tagFromAlice = a.doFinal(plainTextBytes);

                    send("bob", plainTextBytes);
                    send("bob", tagFromAlice);

                    // B to A

                    byte[] bobFromMsg = receive("alice");
                    byte[] tagFromTheSameMessage = receive("alice");

                    byte[] newTagFromBobMsg = a.doFinal(bobFromMsg);

                    if (verify3()) {
                        "Yippie Kay yaaay motherfucker."
                    } else {
                        "Que?"
                    }
                    // Za B obrneš prejemnike/pošiljatelje.s
                }
            });
            env.connect("alice", "bob");
            env.start();
        }

