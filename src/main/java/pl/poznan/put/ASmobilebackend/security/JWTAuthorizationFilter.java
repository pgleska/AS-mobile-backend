package pl.poznan.put.ASmobilebackend.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private static final String HEADER = "Authorization";
	private static final String TOKEN_PREFIX = "Bearer ";
	
	private final String secret;
	private final Map<String, List<String>> usersRoles;
	
	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, String secret, Map<String, List<String>> usersRoles) {
		super(authenticationManager);
		this.secret = secret;
		this.usersRoles = usersRoles;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String header = request.getHeader(HEADER);
		
		if(Objects.isNull(header) || !header.startsWith(TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}
		
		UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
	}
	
	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(HEADER);
		token = token.replace(TOKEN_PREFIX, "");
		
		String userLogin = JWT.require(Algorithm.HMAC256(secret))
				.build()
				.verify(token)
				.getSubject();
		
		if(Objects.nonNull(userLogin)) {
			List<String> roles = usersRoles.get(userLogin);
			Collection<SimpleGrantedAuthority> grantedAuthorites = new ArrayList<>();
			roles.forEach(role -> grantedAuthorites.add(new SimpleGrantedAuthority(role)));
			return new UsernamePasswordAuthenticationToken(userLogin, null, grantedAuthorites);
		}
		
		return null;
	}
}
