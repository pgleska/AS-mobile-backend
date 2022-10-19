package pl.poznan.put.ASmobilebackend.security;

import static com.auth0.jwt.algorithms.Algorithm.HMAC256;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;

import pl.poznan.put.ASmobilebackend.models.User;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	private final String secret;			
	private final AuthenticationManager authenticationManager;
	private final Map<String, List<String>> usersRoles;
	private User creds;
	
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, String secret, Map<String, List<String>> usersRoles) {
		this.authenticationManager = authenticationManager;
		this.secret = secret;
		this.usersRoles = usersRoles;
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest req,
			HttpServletResponse res) throws AuthenticationException {
		
		try {
			creds = new ObjectMapper()
					.readValue(req.getInputStream(), User.class);						
			
			return authenticationManager.authenticate(
					(Authentication) new UsernamePasswordAuthenticationToken(
                            creds.getLogin(),
                            creds.getPassword(),
                            Collections.emptyList())
					);
			
		} catch (IOException e) {
			throw new RuntimeException(e);
		}		
	}
	
	@Override
    protected void successfulAuthentication(HttpServletRequest req,
                                            HttpServletResponse res,
                                            FilterChain chain,
                                            Authentication auth) throws IOException, ServletException {
    	
		String userName = ((org.springframework.security.core.userdetails.User)auth.getPrincipal()).getUsername();
		
        String token = JWT.create()
                .withSubject(userName)
                .withClaim("roles", usersRoles.get(userName).toString())
                .sign(HMAC256(secret));
        
        String body = "{\"JWT\" : \""+ token + "\"}";
        res.setContentType(MediaType.APPLICATION_JSON_VALUE);
        res.getWriter().write(body);
        res.getWriter().flush();
        res.getWriter().close();
    }
}
