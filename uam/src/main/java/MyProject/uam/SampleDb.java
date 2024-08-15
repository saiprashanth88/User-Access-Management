package MyProject.uam;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class SampleDb {


public static Connection connect() throws SQLException
{
	try {
		Class.forName(
		        "com.mysql.cj.jdbc.Driver");
	} catch (ClassNotFoundException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	String driver="com.mysql.cj.jdbc.Driver",url="jdbc:mysql://localhost:3306/project",username="root",password="root";
	Connection c= DriverManager.getConnection(url,username,password);
	return c;
}
}
