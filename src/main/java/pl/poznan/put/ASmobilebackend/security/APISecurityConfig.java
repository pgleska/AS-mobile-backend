package pl.poznan.put.ASmobilebackend.security;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class APISecurityConfig {

	@Value("${api.secret}")
	private String SECRET;
	
	private final Environment environment;
	
	private Map<String, List<String>> usersRoles;
	
	public APISecurityConfig(Environment environment) {
		this.environment = environment;
		this.usersRoles = new HashMap<>();
	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public UserDetailsService userDetailsService(BCryptPasswordEncoder passwordEncoder) {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		for(int i = 0;;i++) {
			String login = environment.getProperty(String.format("users[%d].login", i));
			if(login == null) break;
			else {
				String password = environment.getProperty(String.format("users[%d].password", i));
				List<String> rolesList = new ArrayList<>();			
				for(int j = 0;;j++) {
					if(environment.getProperty(String.format("users[%d].roles[%d]", i, j)) != null)
						rolesList.add(environment.getProperty(String.format("users[%d].roles[%d]", i, j)));
					else
						break;
				}
				
				String[] roles = rolesList.toArray(new String[0]);
				
				usersRoles.put(login, rolesList);
				
				manager.createUser(
					User.withUsername(login)
					.password(passwordEncoder.encode(password))			
					.roles(roles)
					.build()
				);
			}

		}
		return manager;
	}
	
	@Bean
	public AuthenticationManager authenticationManager(HttpSecurity http, UserDetailsService userDetailsService) throws Exception {
		return http.getSharedObject(AuthenticationManagerBuilder.class)
				.userDetailsService(userDetailsService)
				.and()
				.build();
	}
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	
		http.csrf().disable()
			.authorizeHttpRequests()
			.antMatchers("/api/**")
			.authenticated()
			.and()
			.addFilter(new JWTAuthenticationFilter(authenticationManager(http, userDetailsService(bCryptPasswordEncoder())), SECRET, usersRoles))
			.addFilter(new JWTAuthorizationFilter(authenticationManager(http, userDetailsService(bCryptPasswordEncoder())), SECRET, usersRoles))
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		
		
		return http.build();
	}
}
