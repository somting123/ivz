
public class A3AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();
        final SecretKey key2 = KeyGenerator.getInstance("AES").generateKey();

        byte [] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        int counter = 5;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // A payload of 200 MB.
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Compute digest out of data.
                final MessageDigest dA = MessageDigest.getInstance("SHA-256");
                final byte[] hash = dA.digest(data);

                // Send data to Bob.
                send("bob", data);

                // Alice then computes the digest of the data and sends the digest to public-space
                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.
                final Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
                c.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(nonce));
                byte [] sendToPublic = c.doFinal(hash);
                send("public-space",sendToPublic);
            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {

                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice.
                byte[] recieveCtFromAlice  = receive("alice");
                final Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
                c.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(nonce));
                byte [] sendToBob = c.doFinal(recieveCtFromAlice);

                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob.
                final Cipher c2 = Cipher.getInstance("AES/GCM/NoPadding");
                c2.init(Cipher.ENCRYPT_MODE,key2);
                send("bob",c2.doFinal(sendToBob));
                send("bob", c2.getIV());
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                // Data from Alice.
                byte [] dataFromAlice = receive("alice");

                // Compute digest.
                final MessageDigest dfa = MessageDigest.getInstance("SHA-256");
                byte [] dataFromAliceHash = dfa.digest(dataFromAlice);

                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space
                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
                final byte [] encHashFromPublic = receive("public-space");
                final byte [] iV = receive("public-space");
                final Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE,key2,new GCMParameterSpec(128,iV));
                byte [] receivedHash = c.doFinal(encHashFromPublic);

                        if(verify(dataFromAliceHash,receivedHash)){
                            System.out.println("Data valid!");
                        }
                        else{
                            System.out.println("Data invalid!");
                        }
            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }

}