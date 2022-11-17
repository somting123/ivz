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
        
        //Za RSA generiraš dva keya (za vsakega po enga).
        final KeyPairGenerator kpgA = KeyPairGenerator.getInstance("RSA");
        final KeyPair kpA = kpgA.generateKeyPair();
        final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
        
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
                
                // Za pri CHACHA20 
                chaCha20.init(CipherMode.ENCRYPT, new ChaCha20ParameterSpec(nonce, counter));
                chaCha20.init(CipherMode.DECRYPT, new ChaCha20ParameterSpec(nonce, counter));

                // A ENCRYPTA S PUBLIC KEYEM OD OD BOBA
                rsaEnc.init(Cipher.ENCRYPT_MODE, kpB.getPublic());
                // A DECRYPTA S SVOJIM PRIVATE KEYEM
                rsaEnc.init(Cipher.ENCRYPT_MODE, kpA.getPrivate());
                    }
                }
            }
        });
        env.connect("alice", "bob");
        env.start();
    }
}
