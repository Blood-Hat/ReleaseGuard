package demo.safe;

import java.io.DataInputStream;
import java.io.InputStream;

public class SafeParser {
    public String read(InputStream input) throws Exception {
        return new DataInputStream(input).readUTF();
    }
}

