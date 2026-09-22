package demo.vulnerable;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class VulnerableLogin {
    private static final String password = "admin123";

    public ResultSet find(Connection connection, String username) throws Exception {
        Statement statement = connection.createStatement();
        String sql = "SELECT * FROM users WHERE username='" + username + "'";
        return statement.executeQuery(sql);
    }
}

