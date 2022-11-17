
public class A1AgentCommunicationHMAC {
  
    // Verify if key is present
    public static boolean verify3(byte[] tag1, byte[] tag2, Key key)
            throws NoSuchAlgorithmException, InvalidKeyException {

        final Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        final byte[] tagtag1 = mac.doFinal(tag1);
        final byte[] tagtag2 = mac.doFinal(tag2);

        return Arrays.equals(tagtag1, tagtag2);
    }

    // Universal verify.
    public static boolean verify2(byte[] tag1, byte[] tag2){
        if (tag1 == tag2)
            return true;
        if (tag1 == null || tag2 == null)
            return false;

        int length = tag1.length;
        if (tag2.length != length)
            return false;

        // This loop never terminates prematurely
        byte result = 0;
        for (int i = 0; i < length; i++) {
            result |= tag1[i] ^ tag2[i];
        }
        return result == 0;
    }
    
    // Generate key for HMAC.
    public static SecretKey genKey(String password, byte[] salt){
        
        final SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final KeySpec specs = new PBEKeySpec(password.toCharArray(), salt,10000, 128);

        return pbkdf.generateSecret(specs);
    }

  

    
    
}