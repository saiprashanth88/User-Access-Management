package MyProject.uam;

import java.io.*;
import java.sql.*;
import java.sql.Date;
import java.time.LocalDate;
import java.util.*;

public class User {
	 private String firstname;
	    private String lastname;
	    private String username;
	    private String email;
	    private String password;
	    private String managerID; // Added this field
	    private String passkey;
	    @Override
		public String toString() {
			return "User [firstname=" + firstname + ", lastname=" + lastname + ", username=" + username + ", email=" + email
					+ ", password=" + password + ", managerID=" + managerID + "]";
		}

		// Constructor with all the fields
	    public User(String firstname, String lastname, String username, String email, String password, String managerID) {
	        this.firstname = firstname;
	        this.lastname = lastname;
	        this.username = username;
	        this.email = email;
	        this.password = password;
	        this.managerID = managerID;
	    }
	    public User(String firstname, String lastname, String username, String email, String password, String managerID, String passkey) {
	        this.firstname = firstname;
	        this.lastname = lastname;
	        this.username = username;
	        this.email = email;
	        this.password = password;
	        this.managerID = managerID;
	        this.passkey = passkey;
	    }
	    public User(String firstname, String lastname, String username, String managerID) {
	        this.firstname = firstname;
	        this.lastname = lastname;
	        this.username = username;
	        
	        this.managerID = managerID;
	    }
	    public User(String firstname, String lastname, String username) {
	    	this.firstname=firstname;
	    	this.lastname=lastname;
	    	this.username=username;
	    }
public User(String password) {
	this.password=password;
}
	    // Getters and Setters
	    public String getFirstName() {
	        return firstname;
	    }

	    public void setFirstName(String firstname) {
	        this.firstname = firstname;
	    }

	    public String getLastName() {
	        return lastname;
	    }

	    public void setLastName(String lastname) {
	        this.lastname = lastname;
	    }

	    public String getUsername() {
	        return username;
	    }

	    public void setUsername(String username) {
	        this.username = username;
	    }

	    public String getEmail() {
	        return email;
	    }

	    public void setEmail(String email) {
	        this.email = email;
	    }

	    public String getPassword() {
	        return password;
	    }

	    public void setPassword(String password) {
	        this.password = password;
	    }

	    public String getManagerID() {
	        return managerID;
	    }

	    public void setManagerID(String managerID) {
	        this.managerID = managerID;
	    }

	   
	    public String encryptPassword() {
	        File file = new File("C:\\Sai Prashanth\\uam\\uam\\src\\main\\webapp\\enc1.txt");
	        if (!file.exists()) {
	            throw new RuntimeException("enc1.txt not found");
	        }

	        Map<Character, String> charMapping = new HashMap<>();
	        try (Scanner sc = new Scanner(file)) {
	            int row = 1;
	            while (sc.hasNextLine()) {
	                String line = sc.nextLine();
	                for (int col = 0; col < line.length(); col++) {
	                    char currentChar = line.charAt(col);
	                    String encryptedValue = row + "" + (col + 1);
	                    charMapping.put(currentChar, encryptedValue);
	                }
	                row++;
	            }
	        } catch (FileNotFoundException e) {
	            throw new RuntimeException("Failed to read enc1.txt", e);
	        }

	        StringBuilder encryptedPassword = new StringBuilder();
	        for (char c : password.toCharArray()) {
	            String encryptedValue = charMapping.get(c);
	            if (encryptedValue != null) {
	                encryptedPassword.append(encryptedValue);
	            } else {
	                encryptedPassword.append(c);
	            }
	            
	        }

	        return encryptedPassword.toString();
	    }

	    public String generateUsername() {
	        String baseUsername = firstname.toLowerCase() + "." + lastname.toLowerCase();
	        String username = baseUsername;
	        int count = 0;

	        try (Connection conn = SampleDb.connect()) {
	            String query = "SELECT COUNT(*) FROM details WHERE username LIKE ?";
	            try (PreparedStatement stmt = conn.prepareStatement(query)) {
	                stmt.setString(1, username + "%");
	                try (ResultSet rs = stmt.executeQuery()) {
	                	if (rs.next() && rs.getInt(1) > 0) {
	                        count = rs.getInt(1) + 1;
	                        username = baseUsername + count;
	                    }
	                }
	            }
	        } catch (SQLException e) {
	            throw new RuntimeException("Failed to generate username", e);
	        }

	        return username;
	    }

	   
		public void registerUser() {
	        
	        String userType = "user";
	        String encPassword = encryptPassword();
	        String username= generateUsername();
	        try (Connection conn = SampleDb.connect()) {
	            String checkQuery = "SELECT COUNT(*) FROM details";
	            try (PreparedStatement checkStmt = conn.prepareStatement(checkQuery);
	                 ResultSet rs = checkStmt.executeQuery()) {
	                if (rs.next() && rs.getInt(1) == 0) {
	                    userType = "admin";
	                }
	            }

	            String query = "INSERT INTO details (firstname, lastname, username, email, password, user_type, date, passkey) VALUES (?, ?, ?, ?, ?, ?, ?,?)";
	            try (PreparedStatement stmt = conn.prepareStatement(query)) {
	                stmt.setString(1, firstname);
	                stmt.setString(2, lastname);
	                stmt.setString(3, username);
	                stmt.setString(4, email);
	                stmt.setString(5, encPassword);
	                stmt.setString(6, userType);
	                stmt.setDate(7, Date.valueOf(LocalDate.now())); 
	                stmt.setString(8, passkey);
	                stmt.executeUpdate();
	            }
	        } catch (SQLException e) {
	            throw new RuntimeException("Registration failed: " + e.getMessage(), e);
	        }
	    }
		public String getUsername(String email) {
			try(Connection conn = SampleDb.connect()){
				String encPassword = encryptPassword();
				String user = null;
				String query = "Select username from details where email = ?  AND password = ?";
				 try (PreparedStatement check = conn.prepareStatement(query)) {
		                check.setString(1, email);
		                check.setString(2, encPassword);
		                try(ResultSet rs = check.executeQuery()){
		                	if(rs.next()) {
		                		user = rs.getString("username");
		                		
		                	}
		                }
			
			}
			return user;	 
			}catch(SQLException e) {
				throw new RuntimeException("Unable to get username:" ,e); 
			}
		}

	    public String login() {
	        try (Connection conn = SampleDb.connect()) {
	            String encPassword = encryptPassword();
	            String query = "SELECT username,user_type FROM details WHERE username = ? AND password = ?";
	            try (PreparedStatement check = conn.prepareStatement(query)) {
	                check.setString(1, username);
	                check.setString(2, encPassword);
	                try (ResultSet rs = check.executeQuery()) {
	                    if (rs.next()) {
	                        return rs.getString("user_type");
	                    }
	                }
	            }
	        } catch (SQLException e) {
	            throw new RuntimeException("Login Failed: " + e.getMessage(), e);
	        }
	        return "Login failed";
	    }
	    
	    public String forgot() {
	        try (Connection conn = SampleDb.connect()) {
	           
	            String query = "SELECT username,user_type FROM details WHERE username = ? AND passkey = ?";
	            try (PreparedStatement check = conn.prepareStatement(query)) {
	                check.setString(1, username);
	                check.setString(2, passkey);
	                try (ResultSet rs = check.executeQuery()) {
	                    if (rs.next()) {
	                        return rs.getString("user_type");
	                    }
	                }
	            }
	        } catch (SQLException e) {
	            throw new RuntimeException("Login Failed: " + e.getMessage(), e);
	        }
	        return "Enter your Correct Username and Passkey";
	    }
	    public void requestRole(String requestedRole) {
	        try (Connection conn = SampleDb.connect()) {
	            String query = "INSERT INTO requests (username, request_type, request_value, status) VALUES (?, ?, ?, FALSE)";
	            try (PreparedStatement stmt = conn.prepareStatement(query)) {
	                stmt.setString(1, username);
	                stmt.setString(2, "Role Request");
	                stmt.setString(3, requestedRole);
	                stmt.executeUpdate();
	            }
	        } catch (SQLException e) {
	            throw new RuntimeException("Failed to request role: " + e.getMessage(), e);
	        }
	    }
	    
	    public void requestResources(String requestedRole) throws SQLException {
	        try (Connection conn = SampleDb.connect()) {
	            // Check if the resource exists
	            String checkQuery = "SELECT COUNT(*) FROM resources WHERE resource_name = ?";
	            try (PreparedStatement checkStmt = conn.prepareStatement(checkQuery)) {
	                checkStmt.setString(1, requestedRole);
	                ResultSet rs = checkStmt.executeQuery();
	                
	                if (rs.next() && rs.getInt(1) > 0) {
	                    // Resource exists, proceed with the request
	                    String requestType = "Resource Request";
	                    String insertQuery = "INSERT INTO requests (username, request_type, request_value, status) VALUES (?, ?, ?, false)";
	                    
	                    try (PreparedStatement insertStmt = conn.prepareStatement(insertQuery)) {
	                        insertStmt.setString(1, username);
	                        insertStmt.setString(2, requestType);
	                        insertStmt.setString(3, requestedRole);
	                        insertStmt.executeUpdate();
	                    }
	                    
	                    System.out.println("Resource request submitted successfully.");
	                } else {
	                    // Resource does not exist
	                    throw new SQLException("Requested resource does not exist.");
	                }
	            }
	        } catch (SQLException e) {
	            throw new SQLException("Failed to request resource: " + e.getMessage(), e);
	        }
	    }

	    public List<String> getResourcesForUser(String username) throws SQLException {
	        List<String> resources = new ArrayList<>();
	        String query = "SELECT resource_name FROM user_resources WHERE username = ?";
	        
	        try (Connection conn = SampleDb.connect();
	             PreparedStatement stmt = conn.prepareStatement(query)) {
	            
	            stmt.setString(1, username);
	            ResultSet rs = stmt.executeQuery();
	            
	            while (rs.next()) {
	                resources.add(rs.getString("resource_name"));
	            }
	        }
	        
	        return resources;
	    }
	    
	    public void assignManager(String username) {
	        try (Connection conn = SampleDb.connect()) {
	            String query = "UPDATE details SET user_type = 'manager' WHERE username = ?";
	            
	            try (PreparedStatement stmt = conn.prepareStatement(query)) {
	                stmt.setString(1, username);
	                
	                int rowsAffected = stmt.executeUpdate();
	                
	                if (rowsAffected > 0) {
	                    System.out.println("User type updated to manager successfully.");
	                } else {
	                    throw new RuntimeException("No user found with the username: " + username);
	                }
	            }
	        } catch (SQLException e) {
	            throw new RuntimeException("Failed to assign manager: " + e.getMessage(), e);
	        }
	    }
	    
	    
	   
}
