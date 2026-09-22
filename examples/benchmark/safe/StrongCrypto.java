package demo.safe;

import java.security.MessageDigest;
import java.security.SecureRandom;

public class StrongCrypto {
    public byte[] digest(byte[] value) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return MessageDigest.getInstance("SHA-256").digest(value);
    }
}

