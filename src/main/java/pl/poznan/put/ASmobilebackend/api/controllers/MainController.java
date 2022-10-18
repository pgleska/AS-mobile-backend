package pl.poznan.put.ASmobilebackend.api.controllers;

import java.security.Principal;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class MainController {

	@PreAuthorize("hasAuthority('user')")
	@GetMapping(value = "/helloUser", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, String> helloUser() {
		return Map.of("hello", "jol");
	}
	
	@PreAuthorize("hasAuthority('admin')")
	@GetMapping(value = "/helloAdmin", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, String> helloAdmin(Principal principal) {
		return Map.of("hello", "witam");
	}
}
