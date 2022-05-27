package com.ohrs.payload.response;

import java.util.List;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@Data
@ToString

public class UserInfoResponse {
	
	private Long id;
	private String username;
	private String email;
	private String contactno;
	private List<String> roles;

	public UserInfoResponse(Long id, String username, String email, String contactno, List<String> roles) {
		this.id = id;
		this.username = username;
		this.email = email;
		this.contactno = contactno;
		this.roles = roles;
	}

}
