package pl.poznan.put.ASmobilebackend.models;

import java.util.List;

public class User {
	private String login;
	private String password;
	private List<String> roles;
	
	public User() {
		
	}
	
	public User(String login, String password) {
		this.login = login;
		this.password = password;
	}
	
	public String getLogin() {
		return login;
	}
	
	public void setLogin(String login) {
		this.login = login;
	}
	
	public String getPassword() {
		return password;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}
	
	public List<String> getRoles() {
		return roles;
	}
	
	public void setRoles(List<String> roles) {
		this.roles = roles;
	}
	
	@Override
	public String toString() {
		return "User " + login + " with roles " + roles;
	}
}
