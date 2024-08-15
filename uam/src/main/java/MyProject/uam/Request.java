package MyProject.uam;

import java.sql.*;

public class Request {
	 private String username;
	    private String requestType;
	    private String requestValue;
	    private boolean approved;

	    public String getUsername() {
			return username;
		}



		public void setUsername(String username) {
			this.username = username;
		}



		public String getRequestType() {
			return requestType;
		}



		public void setRequestType(String requestType) {
			this.requestType = requestType;
		}



		public String getRequestValue() {
			return requestValue;
		}



		public void setRequestValue(String requestValue) {
			this.requestValue = requestValue;
		}



		public boolean isApproved() {
			return approved;
		}



		public void setApproved(boolean approved) {
			this.approved = approved;
		}



		public Request(String username, String requestType, String requestValue, boolean approved) {
	        this.username = username;
	        this.requestType = requestType;
	        this.requestValue = requestValue;
	        this.approved = approved;
	    }

	  
	  

	    
	    
	    
	}
