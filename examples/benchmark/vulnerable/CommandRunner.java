package demo.vulnerable;

public class CommandRunner {
    public Process run(String userInput) throws Exception {
        return Runtime.getRuntime().exec("cmd /c " + userInput);
    }
}

