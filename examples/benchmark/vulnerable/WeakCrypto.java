package demo.vulnerable;

import java.security.MessageDigest;
import java.util.Random;

public class WeakCrypto {
    public byte[] digest(byte[] value) throws Exception {
        int nonce = new Random().nextInt();
        return MessageDigest.getInstance("MD5").digest((nonce + new String(value)).getBytes());
    }
}

