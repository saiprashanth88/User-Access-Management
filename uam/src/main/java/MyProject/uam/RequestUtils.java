package MyProject.uam;

import java.sql.*;
import java.util.*;

public class RequestUtils {
	public static List<Request> getRequests() throws Exception {
        List<Request> requests = new ArrayList<>();
        Connection c = SampleDb.connect(); // Assuming SampleDb.connect() method exists for database connection
        ResultSet rs = c.prepareStatement("SELECT * FROM requests").executeQuery();
        while (rs.next()) {
            Request request = new Request(
                rs.getString("username"), 
                rs.getString("request_type"), 
                rs.getString("request_value"), 
                rs.getBoolean("status")
            );
            requests.add(request);
        }
        return requests;
    }
}
