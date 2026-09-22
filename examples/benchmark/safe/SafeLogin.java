package demo.safe;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SafeLogin {
    public ResultSet find(Connection connection, String username) throws Exception {
        PreparedStatement statement = connection.prepareStatement(
            "SELECT id, username FROM users WHERE username = ?"
        );
        statement.setString(1, username);
        return statement.executeQuery();
    }
}

