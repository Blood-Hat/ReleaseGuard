package demo.vulnerable;

import java.io.InputStream;
import java.io.ObjectInputStream;

public class UnsafeDeserializer {
    public Object read(InputStream input) throws Exception {
        return new ObjectInputStream(input).readObject();
    }
}

