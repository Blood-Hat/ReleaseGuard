package demo.safe;

import java.util.Set;

public class SafeProcess {
    private static final Set<String> ALLOWED = Set.of("status", "version");

    public String selectAction(String requested) {
        if (!ALLOWED.contains(requested)) {
            throw new IllegalArgumentException("Unsupported action");
        }
        return requested;
    }
}

