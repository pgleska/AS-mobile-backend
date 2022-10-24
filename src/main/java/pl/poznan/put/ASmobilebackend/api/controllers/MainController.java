package pl.poznan.put.ASmobilebackend.api.controllers;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import pl.poznan.put.ASmobilebackend.models.User;

@RestController
@RequestMapping("/api")
public class MainController {

	private Map<String, User> usersMap;
	
	public MainController(Environment env) {
		usersMap = new HashMap<>();
		
		for(int i = 0;;i++) {
			String login = env.getProperty(String.format("users[%d].login", i));
			if(login == null) break;
			else {
				List<String> rolesList = new ArrayList<>();			
				for(int j = 0;;j++) {
					if(env.getProperty(String.format("users[%d].roles[%d]", i, j)) != null)
						rolesList.add(env.getProperty(String.format("users[%d].roles[%d]", i, j)));
					else
						break;
				}
				User user = new User();
				user.setLogin(login);
				user.setRoles(rolesList);
				usersMap.put(login, user);								
			}
		}
		
	}
	
	@PreAuthorize("hasAuthority('user')")
	@GetMapping(value = "/users/{login}", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, String> userDetails(Principal principal, @PathVariable("login") String login) {
		Map<String, String> response = new HashMap<>();
		String msg;
		
		if(!principal.getName().equals(login)) 
			msg = "I shouldn't do it but I will tell you about this user - " + usersMap.get(login);
		else
			msg = "I will tell you everything about myself - " + usersMap.get(login);
		
		response.put("message", msg);
		return response;
	}
	
	@PreAuthorize("hasAuthority('user')")
	@GetMapping(value = "/users/admin", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, String> adminDetails() {
		Map<String, String> response = new HashMap<>();		
		response.put("message", "I will tell you everything about admin - " + usersMap.get("einstein"));
		return response;
	}
	
	@PreAuthorize("hasAuthority('user')")
	@GetMapping(value = "/users", produces = MediaType.APPLICATION_JSON_VALUE)
	public List<User> allUsers() {
		List<User> all = new ArrayList<>();
		usersMap.forEach((k, v) -> all.add(v));
		return all;
	}
	
	@PreAuthorize("hasAuthority('user')")
	@GetMapping(value = "/allEndpoints", produces = MediaType.APPLICATION_JSON_VALUE)
	public List<Map<String, String>> allEndpoints() {
		List<Map<String, String>> result = new ArrayList<>();
		result.add(Map.of("message", "/api/users/{login}"));
		result.add(Map.of("message", "/api/users/admin"));
		result.add(Map.of("message", "/api/users"));
		result.add(Map.of("message", "/api/hidden"));
		result.add(Map.of("message", "/api/allEndpoints"));
		return result;
	}
	
	@GetMapping(value = "/hidden", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, String> hiddenEndpoint() {
		return Map.of("message", "This is a hidden endpoint with no authorization");
	}
}
