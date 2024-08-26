package MyProject.uam;

import java.io.*;
import java.sql.*;
import java.util.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.ws.FaultAction;

/**
 * Root resource (exposed at "myresource" path)
 */
@Path("myresource")
public class MyResource {

    /**
     * Method handling HTTP GET requests. The returned object will be sent
     * to the client as "text/plain" media type.
     *
     * @return String that will be returned as a text/plain response.
     */
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String getIt() {
        return "Got it!";
    }
    @GET
    @Path("db")
    public String db_connect() throws ClassNotFoundException, SQLException {
        Connection c = SampleDb.connect();
        if (c != null)
            return "Connected";
        else
            return "Not Connected!";
    }
    @POST
    @Path("register")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public void register(@FormParam("firstname") String firstname,
                         @FormParam("lastname") String lastname,
                         @FormParam("email") String email,
                         @FormParam("password") String password,
                         @FormParam("confirm_password") String confirmPassword,
                         @FormParam("passkey") String passkey,
                         @Context HttpServletResponse response) throws IOException {
        if (!password.equals(confirmPassword)) {
            response.sendRedirect("/uam/register.jsp?message=Passwords do not match");
            return;
        }

        if (!isValidPassword(password)) {
            response.sendRedirect("/uam/register.jsp?message=Password must be at least 6 characters long and include one uppercase letter, one lowercase letter, and one special character, and one digit");
            return;
        }

        try {
            User ob = new User(firstname, lastname, null, email, password, null, passkey);
            ob.registerUser();
            String username = ob.getUsername(email);
            response.sendRedirect("/uam/registrationSuccess.jsp?message=Registration successful&username=" + username);
        } catch (Exception e) {
            response.sendRedirect("/uam/register.jsp?message=Registration failed: " + e.getMessage());
        }
    }
    @POST
    @Path("changepassword")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response changePassword(@FormParam("newPassword") String newPassword, @Context HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("username") == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                           .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                           .build();
        }

        String username = (String) session.getAttribute("username");

        if (!isValidPassword(newPassword)) {
            return Response.status(Response.Status.BAD_REQUEST)
                           .entity("{\"error\": \"Password does not meet the criteria.\"}")
                           .build();
        }

        User ob = new User(newPassword);
        String encryptedPassword = ob.encryptPassword();

        String updateQuery = "UPDATE details SET password = ? WHERE username = ?";
        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(updateQuery)) {

            stmt.setString(1, encryptedPassword);
            stmt.setString(2, username);

            int rowsAffected = stmt.executeUpdate();
            if (rowsAffected > 0) {
                return Response.ok("{\"success\": true, \"url\": \"/uam\"}").build();
            } else {
                return Response.serverError().entity("{\"error\": \"Failed to change password.\"}").build();
            }
        } catch (SQLException e) {
            return Response.serverError().entity("{\"error\": \"Database error: " + e.getMessage() + "\"}").build();
        }
    }
    @POST
    @Path("forgotPassword")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public void forgotPassword(@FormParam("newPassword") String newPassword,
    		@FormParam("confirm_newPassword")String confirmNewPassword,
    		@Context HttpServletRequest request,
    		@Context HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("username") == null) {
            response.sendRedirect("/uam/changePassword.jsp?message=Passwords do not match");

        }

        String username = (String) session.getAttribute("username");
        if (!newPassword.equals(confirmNewPassword)) {
            response.sendRedirect("/uam/changePassword.jsp?message=Passwords do not match");
            return;
        }
        if (!isValidPassword(newPassword)) {
            response.sendRedirect("/uam/changePassword.jsp?message=Passwords do not match");

        }

        User ob = new User(newPassword);
        String encryptedPassword = ob.encryptPassword();

        String updateQuery = "UPDATE details SET password = ? WHERE username = ?";
        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(updateQuery)) {

            stmt.setString(1, encryptedPassword);
            stmt.setString(2, username);

            int rowsAffected = stmt.executeUpdate();
            if (rowsAffected > 0) {
                response.sendRedirect("/uam/?message=Success! Login with your new password");

            } else {
                response.sendRedirect("/uam/?message=Passwords do not match");
            }
        } catch (SQLException e) {
            response.sendRedirect("/uam/?message=Passwords do not match");
        }
    }

    private boolean isValidPassword(String password) {
        if (password.length() < 6) {
            return false;
        }

        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasSpecial = false;
        boolean hasDigit = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                hasUpper = true;
            } else if (Character.isLowerCase(c)) {
                hasLower = true;
            } else if (Character.isDigit(c)) {
                hasDigit = true;
            } else if (!Character.isLetterOrDigit(c)) {
                hasSpecial = true;
            }
        }

        return hasUpper && hasLower && hasSpecial && hasDigit;
    }


   

    @POST
    @Path("login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void login(@FormParam("username") String username,
                      @FormParam("password") String password,
                      @Context HttpServletRequest request,
                      @Context HttpServletResponse response) throws IOException {
        try {
            User ob = new User(null, null, username, null, password,null);
            String loginResult = ob.login();
            String failure = "Login Failed";

            if ("user".equals(loginResult)) {
                HttpSession session = request.getSession();
                session.setAttribute("username", username);
                response.sendRedirect("/uam/user.html?username=" + username);
            } else if ("admin".equals(loginResult) || "Admin".equals(loginResult)) {
                HttpSession session = request.getSession();
                session.setAttribute("username", username);
                response.sendRedirect("/uam/admin.html?username=" + username);
            } else if ("manager".equals(loginResult) || "Manager".equals(loginResult)) {
                HttpSession session = request.getSession();
                session.setAttribute("username", username);
                response.sendRedirect("/uam/manager.html?username=" + username);
            } else {
                response.sendRedirect("/uam/?message=" + failure); 
            }
        } catch (Exception e) {
            response.sendRedirect("/uam/?message=Cannot login");
        }
    }
    

    @POST
    @Path("forgot")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void forgot(@FormParam("username") String username,
                      @FormParam("passkey") String passkey,
                      @Context HttpServletRequest request,
                      @Context HttpServletResponse response) throws IOException {
        try {
            User ob = new User(null, null, username, null, null,null,passkey);
            String loginResult = ob.forgot();
            String failure = "Enter your Correct Username and Passkey";

            if ("user".equals(loginResult)) {
                HttpSession session = request.getSession();
                session.setAttribute("username", username);
                response.sendRedirect("/uam/changePassword.jsp?username=" + username);
            } else if ("admin".equals(loginResult) || "Admin".equals(loginResult)) {
                HttpSession session = request.getSession();
                session.setAttribute("username", username);
                response.sendRedirect("/uam/changePassword.jsp?username=" + username);
            } else if ("manager".equals(loginResult) || "Manager".equals(loginResult)) {
                HttpSession session = request.getSession();
                session.setAttribute("username", username);
                response.sendRedirect("/uam/changePassword.jsp?username=" + username);
            } else {
                response.sendRedirect("/uam/forgot.jsp?message=" + failure); 
            }
        } catch (Exception e) {
            response.sendRedirect("/uam/forgot.jsp?message=Cannot login");
        }
    }
    @Path("/checkSession")
    public class SessionResource {
        @GET
        @Produces(MediaType.APPLICATION_JSON)
        public Response checkSession(@Context HttpServletRequest request) {
            HttpSession session = request.getSession(false);
            if (session == null || session.getAttribute("username") == null) {
                return Response.status(Response.Status.UNAUTHORIZED).build(); // Session is not valid
            } else {
                return Response.ok().build(); // Session is valid
            }
        }
    }

    
    
    @POST
    @Path("logout")
    public Response logout(@Context HttpServletRequest request) {
        HttpSession session = request.getSession(false); // Get the existing session, do not create a new one
        if (session != null) {
            session.invalidate(); // Invalidate the session
        }
        return Response.ok().build(); // Respond with HTTP 200 OK
    }
    @POST
    @Path("requestRole")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void requestRole(@FormParam("requestedRole") String requestedRole,
                            @Context HttpServletRequest request,
                            @Context HttpServletResponse response) throws IOException {
        try {
            HttpSession session = request.getSession();
            String username = (String) session.getAttribute("username");

            if (username != null) {
                User ob = new User(null, null, username, null, null,null);
                ob.requestRole(requestedRole);
                response.sendRedirect("/uam/roleRequestSuccess.jsp");
            } else {
                response.sendRedirect("/uam/?message=Session expired, please login again.");
            }
        } catch (Exception e) {
            response.sendRedirect("/uam/?message=Cannot process request");
        }
    }
    
    
    @POST
    @Path("requestResources")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void requestResources(@FormParam("resourceName")String requestResources,
    		@Context HttpServletRequest request,
            @Context HttpServletResponse response) throws IOException {
    	try {
            HttpSession session = request.getSession();
            String username = (String) session.getAttribute("username");
            if (username != null) {
            	User ob = new User(null, null, username, null, null,null);
            	ob.requestResources(requestResources);
                response.sendRedirect("/uam/roleRequestSuccess.jsp");

            } 
    	else {
                response.sendRedirect("/uam/?message=Session expired, please login again.");
            }
    	}catch (Exception e) {
                response.sendRedirect("/uam/?message=Resource doesnot Exists");
            }
    }
    @GET
    @Path("requests")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRequests(@Context HttpServletRequest request) {
        List<Request> requests = new ArrayList<>();
        try {
            HttpSession session = request.getSession(false); // Use false to avoid creating a new session
            if (session == null || session.getAttribute("username") == null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                               .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                               .build();
            }

            try (Connection conn = SampleDb.connect()) {
                String query = "SELECT * FROM requests WHERE status = 0";
                try (PreparedStatement stmt = conn.prepareStatement(query);
                     ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        String username = rs.getString("username");
                        String requestType = rs.getString("request_type");
                        String requestValue = rs.getString("request_value");
                        boolean approved = rs.getBoolean("approved");
                        requests.add(new Request(username, requestType, requestValue, approved));
                    }
                }
            } catch (SQLException e) {
                return Response.serverError().entity("Error fetching requests: " + e.getMessage()).build();
            }
        } catch (Exception e) {
            return Response.serverError().entity("Unexpected error: " + e.getMessage()).build();
        }

        return Response.ok(requests).build();
    }


    @GET
    @Path("accepted")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getaccepted(@Context HttpServletRequest request) {
    	HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
        	return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                    .build();        }
        
        String username1 = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (username1 == null) {
        	return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                    .build();        }
        List<Request> requests = new ArrayList<>();
        try (Connection conn = SampleDb.connect()) {
            String query = "SELECT * FROM requests WHERE username =?";
            
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, username1);
             
                ResultSet rs = stmt.executeQuery();
                
                while (rs.next()) {
                    String username = rs.getString("username");
                    String requestType = rs.getString("request_type");
                    
                    String requestValue = rs.getString("request_value");
                    boolean status = rs.getBoolean("status");
                    boolean approved = rs.getBoolean("approved");
                    requests.add(new Request(username, requestType, requestValue,status, approved));
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching requests: " + e.getMessage()).build();
        }
        return Response.ok(requests).build();
    }
    
    
    @POST
    @Path("request/accept")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response acceptRequest(@FormParam("username") String username,
                                  @FormParam("requestType") String requestType,
                                  @FormParam("requestValue") String requestValue) {
        try (Connection conn = SampleDb.connect()) {
            String updateQuery = "UPDATE requests SET status = 1, approved = 1 WHERE username = ? AND request_type = ? AND request_value = ?";
            try (PreparedStatement stmt = conn.prepareStatement(updateQuery)) {
                stmt.setString(1, username);
                stmt.setString(2, requestType);
                stmt.setString(3, requestValue);
                stmt.executeUpdate();
                
                // Additional logic for Role Request
                if (requestType.equals("Role Request")) {
                    String updateDetailsQuery = "UPDATE details SET user_type = ? WHERE username = ?";
                    try (PreparedStatement updateStmt = conn.prepareStatement(updateDetailsQuery)) {
                        updateStmt.setString(1, requestValue);
                        updateStmt.setString(2, username);
                        updateStmt.executeUpdate();
                    }
                }

                // Additional logic for Resource Request
                if (requestType.equals("Resource Request")) {
                    String insertQuery = "INSERT INTO user_resources (username, resource_name) VALUES (?, ?)";
                    try (PreparedStatement insertStmt = conn.prepareStatement(insertQuery)) {
                        insertStmt.setString(1, username);
                        insertStmt.setString(2, requestValue);
                        insertStmt.executeUpdate();
                    }
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error accepting request: " + e.getMessage()).build();
        }
        return Response.ok("Request accepted").build();
    }

    @POST
    @Path("request/reject")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response rejectRequest(@FormParam("username") String username,
                                  @FormParam("requestType") String requestType,
                                  @FormParam("requestValue") String requestValue) {
        try (Connection conn = SampleDb.connect()) {
            String updateQuery = "UPDATE requests SET status = 1, approved = 0 WHERE username = ? AND request_type = ? AND request_value = ?";
            try (PreparedStatement stmt = conn.prepareStatement(updateQuery)) {
                stmt.setString(1, username);
                stmt.setString(2, requestType);
                stmt.setString(3, requestValue);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error rejecting request: " + e.getMessage()).build();
        }
        return Response.ok("Request rejected").build();
    }

    @GET
    @Path("resources")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getResources(@Context HttpServletRequest request) {
        List<Resource> resources = new ArrayList<>();
        try {
            HttpSession session = request.getSession(false); // Use false to avoid creating a new session
            if (session == null || session.getAttribute("username") == null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                               .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                               .build();
            }

            try (Connection conn = SampleDb.connect()) {
                String query = "SELECT resource_name FROM resources";
                try (Statement stmt = conn.createStatement();
                     ResultSet rs = stmt.executeQuery(query)) {

                    while (rs.next()) {
                        Resource resource = new Resource();
                        resource.setResourceName(rs.getString("resource_name"));
                        resources.add(resource);
                    }
                }
            } catch (SQLException e) {
                return Response.serverError().entity("Error fetching resources: " + e.getMessage()).build();
            }
        } catch (Exception e) {
            return Response.serverError().entity("Unexpected error: " + e.getMessage()).build();
        }

        // Return the list of resources as a JSON response
        return Response.ok(resources).build();
    }


    @POST
    @Path("resource/delete")
    @Consumes("application/x-www-form-urlencoded")
    public Response deleteResource(@FormParam("resourceName") String resourceName) {
        try (Connection conn = SampleDb.connect()) {
            conn.setAutoCommit(false);
            
            try {
                String deleteReferencesQuery = "DELETE FROM user_resources WHERE resource_name = ?";
                try (PreparedStatement stmt = conn.prepareStatement(deleteReferencesQuery)) {
                    stmt.setString(1, resourceName);
                    stmt.executeUpdate();
                }

                String deleteResourceQuery = "DELETE FROM resources WHERE resource_name = ?";
                try (PreparedStatement stmt = conn.prepareStatement(deleteResourceQuery)) {
                    stmt.setString(1, resourceName);
                    int rowsAffected = stmt.executeUpdate();
                    
                    if (rowsAffected > 0) {
                        conn.commit();
                        return Response.ok("Resource deleted successfully").build();
                    } else {
                        conn.rollback();
                        return Response.status(Response.Status.NOT_FOUND).entity("Resource not found").build();
                    }
                }
            } catch (SQLException e) {
                conn.rollback();
                return Response.serverError().entity("Error deleting resource: " + e.getMessage()).build();
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Database connection error: " + e.getMessage()).build();
        }
    }
    
    @GET
    @Path("userresources")
    public Response getUserResources(@Context HttpServletRequest request) {
        List<UserResource> userResources = new ArrayList<>();
        try {
            HttpSession session = request.getSession(false); // Use false to avoid creating a new session
            if (session == null || session.getAttribute("username") == null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                               .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                               .build();
            }
        try (Connection conn = SampleDb.connect()) {
            String query = "SELECT username, resource_name FROM user_resources";
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(query)) {

                while (rs.next()) {
                    UserResource ur = new UserResource();
                    ur.setUsername(rs.getString("username"));
                    ur.setResourceName(rs.getString("resource_name"));
                    userResources.add(ur);
                }
            }
        } } catch (SQLException e) {
            return Response.serverError().entity("Error fetching user resources: " + e.getMessage()).build();
        }

        return Response.ok(userResources).build();
    }

    @POST
    @Path("resource/remove")
    @Consumes("application/x-www-form-urlencoded")
    public Response removeResourceFromUser(@FormParam("username") String username,
                                           @FormParam("resourceName") String resourceName) {
        try (Connection conn = SampleDb.connect()) {
            String deleteQuery = "DELETE FROM user_resources WHERE username = ? AND resource_name = ?";
            try (PreparedStatement stmt = conn.prepareStatement(deleteQuery)) {
                stmt.setString(1, username);
                stmt.setString(2, resourceName);
                int rowsAffected = stmt.executeUpdate();

                if (rowsAffected > 0) {
                    return Response.ok("Resource removed successfully").build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("Resource or user not found").build();
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error removing resource: " + e.getMessage()).build();
        }
    }
    
    @POST
    @Path("checkresources")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response checkResources(@FormParam("username") String username, @Context HttpServletRequest request) {
        List<String> resources = new ArrayList<>();
        
        try {
            HttpSession session = request.getSession(false); // Use false to avoid creating a new session
            if (session == null || session.getAttribute("username") == null) {
                // Return a JSON response indicating the need to redirect
                return Response.status(Response.Status.UNAUTHORIZED)
                               .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                               .build();
            }

            try (Connection conn = SampleDb.connect()) {
                String query = "SELECT resource_name FROM user_resources WHERE username = ?";
                try (PreparedStatement stmt = conn.prepareStatement(query)) {
                    stmt.setString(1, username);
                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            resources.add(rs.getString("resource_name"));
                        }
                    }
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching resources: " + e.getMessage()).build();
        }

        StringBuilder responseHtml = new StringBuilder("<h3>Resources for user: " + username + "</h3>");
        if (resources.isEmpty()) {
            responseHtml.append("<p>No resources found for the user.</p>");
        } else {
            responseHtml.append("<ul>");
            for (String resource : resources) {
                responseHtml.append("<li>").append(resource).append("</li>");
            }
            responseHtml.append("</ul>");
        }

        return Response.ok(responseHtml.toString()).build();
    }

   
//    @GET
//    @Path("users")
//    @Produces(MediaType.APPLICATION_JSON)
//    public Response getUsers(@Context HttpServletRequest request) {
//    	HttpSession session = request.getSession(false); // Use false to avoid creating a new session
//        if (session == null || session.getAttribute("username") == null) {
//            // Return a response indicating redirection
//            return Response.status(Response.Status.UNAUTHORIZED)
//                           .entity("REDIRECT:/uam/?message=Session expired, please login again.")
//                           .build();
//        }
//        try (Connection conn = SampleDb.connect()) {
//            String query = "SELECT firstname, lastname, username, managerID FROM details";
//            try (PreparedStatement stmt = conn.prepareStatement(query);
//                 ResultSet rs = stmt.executeQuery()) {
//
//                List<User> users = new ArrayList<>();
//                while (rs.next()) {
//                    String firstname = rs.getString("firstname");
//                    String lastname = rs.getString("lastname");
//                    String username = rs.getString("username");
//                    String managerID = rs.getString("managerID");
//                    
//                    User user = new User(firstname, lastname, username, managerID);
//                    users.add(user);
//                }
//                
//                return Response.ok(users.toString()).build();
//            }
//        } catch (SQLException e) {
//            return Response.serverError().entity("Database error: " + e.getMessage()).build();
//        }
//    }
    @GET
    @Path("users")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getUsers(@Context HttpServletRequest request) {
        try {
            HttpSession session = request.getSession(false); // Use false to avoid creating a new session
            if (session == null || session.getAttribute("username") == null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                               .entity("Session expired or not logged in. Please log in again.")
                               .build();
            }
            
            try (Connection conn = SampleDb.connect()) {
                String query = "SELECT firstname, lastname, username, managerID FROM details";
                try (PreparedStatement stmt = conn.prepareStatement(query);
                     ResultSet rs = stmt.executeQuery()) {

                    StringBuilder responseBuilder = new StringBuilder();
                    while (rs.next()) {
                        String firstname = rs.getString("firstname");
                        String lastname = rs.getString("lastname");
                        String username = rs.getString("username");
                        String managerID = rs.getString("managerID");
                        
                        responseBuilder.append(String.format("User [firstname=%s, lastname=%s, username=%s, managerID=%s]%n", 
                                                              firstname, lastname, username, managerID));
                    }
                    
                    return Response.ok(responseBuilder.toString()).build();
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        }
    }

    @POST
    @Path("addUser")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public void addUser(@FormParam("firstname") String firstname,
                         @FormParam("lastname") String lastname,
                         @FormParam("email") String email,
                         @Context HttpServletResponse response) throws IOException {
        
        try {
        	String password = "12345";
        	String passkey = "1234";
            User ob = new User(firstname, lastname, null, email, password,null,passkey);
            ob.registerUser();
            String username = ob.getUsername(email);
            response.sendRedirect("/uam/addUserSuccess.jsp?message=User Added successful&username=" + username);
        } catch (Exception e) {
            response.sendRedirect("/uam/userAddFailure.jsp?message=Failed To add User: " + e.getMessage());
        }
    }

    @POST
    @Path("updateuser")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response updateUser(
            @FormParam("username") String oldUsername,
            @FormParam("firstname") String firstname,
            @FormParam("lastname") String lastname) {

        Connection conn = null;
        PreparedStatement updateDetailsStmt = null;
        PreparedStatement updateUserResourcesStmt = null;
        PreparedStatement updateRequestsStmt = null;

        try {
            conn = SampleDb.connect();
            conn.setAutoCommit(false); // Start transaction

            // Generate a new username based on the updated firstname and lastname
            User user = new User(firstname, lastname, oldUsername);
            String newUsername = user.generateUsername();

            // Update the username, firstname, and lastname in the details table
            String updateDetailsQuery = "UPDATE details SET username = ?, firstname = ?, lastname = ? WHERE username = ?";
            updateDetailsStmt = conn.prepareStatement(updateDetailsQuery);
            updateDetailsStmt.setString(1, newUsername);
            updateDetailsStmt.setString(2, firstname);
            updateDetailsStmt.setString(3, lastname);
            updateDetailsStmt.setString(4, oldUsername);
            updateDetailsStmt.executeUpdate();

            // Update the username in the user_resources table
            String updateUserResourcesQuery = "UPDATE user_resources SET username = ? WHERE username = ?";
            updateUserResourcesStmt = conn.prepareStatement(updateUserResourcesQuery);
            updateUserResourcesStmt.setString(1, newUsername);
            updateUserResourcesStmt.setString(2, oldUsername);
            updateUserResourcesStmt.executeUpdate();

            // Update the username in the requests table
            String updateRequestsQuery = "UPDATE requests SET username = ? WHERE username = ?";
            updateRequestsStmt = conn.prepareStatement(updateRequestsQuery);
            updateRequestsStmt.setString(1, newUsername);
            updateRequestsStmt.setString(2, oldUsername);
            updateRequestsStmt.executeUpdate();

            // Commit the transaction
            conn.commit();

            return Response.ok("User updated successfully. New username: " + newUsername).build();
        } catch (SQLException e) {
            if (conn != null) {
                try {
                    conn.rollback(); // Rollback in case of error
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
            return Response.serverError().entity("Failed to update user: " + e.getMessage()).build();
        } finally {
            // Close resources in the finally block to ensure they're always closed
            if (updateDetailsStmt != null) {
                try {
                    updateDetailsStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (updateUserResourcesStmt != null) {
                try {
                    updateUserResourcesStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (updateRequestsStmt != null) {
                try {
                    updateRequestsStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    
//    @POST
//    @Path("addresource")
//    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
//    public Response addResource(@FormParam("resourceName") String resourceName) {
//        String insertResourceQuery = "INSERT INTO resources (resource_name) VALUES (?)";
//
//        try (Connection conn = SampleDb.connect();
//             PreparedStatement stmt = conn.prepareStatement(insertResourceQuery)) {
//
//            stmt.setString(1, resourceName);
//            int rowsAffected = stmt.executeUpdate();
//
//            if (rowsAffected > 0) {
//                return Response.ok("Resource added successfully.").build();
//            } else {
//                return Response.serverError().entity("Failed to add resource.").build();
//            }
//
//        } catch (SQLException e) {
//            return Response.serverError().entity("Database error: " + e.getMessage()).build();
//        }
//    }
    @POST
    @Path("addresource")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_PLAIN)
    public Response addResource(@FormParam("resourceName") String resourceName, @Context HttpServletRequest request) {
        // Check if session exists and get the username
        HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null || session.getAttribute("username") == null) {
            // Return a plain text response indicating the session is expired
            return Response.status(Response.Status.UNAUTHORIZED)
                           .entity("Session expired, please login again.")
                           .build();
        }

        String insertResourceQuery = "INSERT INTO resources (resource_name) VALUES (?)";

        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(insertResourceQuery)) {

            stmt.setString(1, resourceName);
            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                return Response.ok("Resource added successfully.").build();
            } else {
                return Response.serverError().entity("Failed to add resource.").build();
            }

        } catch (SQLException e) {
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        }
    }

    @GET
    @Path("/showTeam")
    @Produces(MediaType.APPLICATION_JSON)
    public Response showTeam(@Context HttpServletRequest request) {
        HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
        	return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                    .build();        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
        	return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                    .build();        }
        
        List<String> teamMembers = getTeamMembersByManagerID(managerID);
        return Response.ok(teamMembers).build();
    }

    private List<String> getTeamMembersByManagerID(String managerID) {
        List<String> teamMembers = new ArrayList<>();
        String query = "SELECT username FROM details WHERE managerID = ?";
        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, managerID);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    teamMembers.add(rs.getString("username"));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace(); // Consider better error handling here
        }
        return teamMembers;
    }

    @GET
    @Path("/getNullUsers")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getNullUsers(@Context HttpServletRequest request) {
        HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
        	return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                    .build();        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
        	return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                    .build();        }
        
        List<String> teamMembers = getAllNullUsers();
        return Response.ok(teamMembers).build();
    }
    
    private List<String> getAllNullUsers() {
        List<String> teamMembers = new ArrayList<>();
        String type = "user";
        String query = "SELECT username FROM details WHERE managerID IS NULL and user_type = ?";
        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, type);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    teamMembers.add(rs.getString("username"));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace(); 
        }
        return teamMembers;
    }
    
    
    
    
    @POST
    @Path("/addToTeam")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response addToTeam(@FormParam("username") String username,@Context HttpServletRequest request) {
    	HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
        }
        String updateQuery = "UPDATE details SET managerID = ? WHERE username = ?";

        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(updateQuery)) {

            stmt.setString(1, managerID);
            stmt.setString(2, username);
            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                return Response.ok("User added to team successfully.").build();
            } else {
                return Response.serverError().entity("Failed to add user to team.").build();
            }

        } catch (SQLException e) {
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        }
    }
    
    
    @GET
    @Path("/getManagerResources")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getManagerResources(@Context HttpServletRequest request) {
        HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
        	return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                    .build();        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
        	return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                    .build();
        	}
        
        
        List<String> resources = getAllManagerResources(managerID);
        return Response.ok(resources).build();
    }

    private List<String> getAllManagerResources(String managerID) {
        List<String> resources = new ArrayList<>();
        
        // Update the query to fetch resources based on the managerID
        String query = "SELECT resource_name FROM user_resources WHERE username = ?";
        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, managerID);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    resources.add(rs.getString("resource_name")); // Fetch the correct column
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return resources;
    }
    
    
    @GET
    @Path("/fetchResources")
    public Response fetchResources(@Context HttpServletRequest request) {
    	 HttpSession session = request.getSession(false); // Use false to avoid creating a new session
         if (session == null) {
        	 return Response.status(Response.Status.UNAUTHORIZED)
                     .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                     .build();      
        	 }
         
         String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
         if (managerID == null) {
        	 return Response.status(Response.Status.UNAUTHORIZED)
                     .entity("{\"redirect\": true, \"url\": \"/uam/?message=Session expired, please login again.\"}")
                     .build();
        	 }
         
         List<String> l2 = getAllManagerResources(managerID);
         
         List<String> l1 = new ArrayList<>();

         try (Connection conn = SampleDb.connect()) {
             String query = "SELECT resource_name FROM resources";
             try (Statement stmt = conn.createStatement();
                  ResultSet rs = stmt.executeQuery(query)) {

                 while (rs.next()) {
                     l1.add(rs.getString("resource_name"));
                 }
             }
         } catch (SQLException e) {
             return Response.serverError().entity("Error fetching resources: " + e.getMessage()).build();
         }
         
         l1.removeAll(l2);
         
         return Response.ok(l1).build();
    }
   

    @POST
    @Path("resourceRemove")
    @Consumes("application/x-www-form-urlencoded")
    public Response removeResourceFromManager(@Context HttpServletRequest request,
                                           @FormParam("resourceName") String resourceName) {
        try (Connection conn = SampleDb.connect()) {
        	HttpSession session = request.getSession(false); // Use false to avoid creating a new session
            if (session == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
            }
            
            String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
            if (managerID == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
            }
            String deleteQuery = "DELETE FROM user_resources WHERE username = ? AND resource_name = ?";
            try (PreparedStatement stmt = conn.prepareStatement(deleteQuery)) {
                stmt.setString(1, managerID);
                stmt.setString(2, resourceName);
                int rowsAffected = stmt.executeUpdate();

                if (rowsAffected > 0) {
                    return Response.ok("Resource removed successfully").build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("Resource or user not found").build();
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error removing resource: " + e.getMessage()).build();
        }
    }

}
