
package com.zuul.gateway.EurekaZuulGateway.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class AuthorizationFilter extends BasicAuthenticationFilter {

	private Environment theEnvironment;

	public AuthorizationFilter(AuthenticationManager theAuthenticationManager, Environment theEnvironments) {
		super(theAuthenticationManager);
		this.theEnvironment = theEnvironments;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String authorizationHeader = request.getHeader(theEnvironment.getProperty("authorization.token.header.name"));

		// check if authorizationHeader null or header does not starts with Bearer
		if (authorizationHeader == null
				|| !authorizationHeader.startsWith(theEnvironment.getProperty("authorization.token.header.prefix"))) {
			chain.doFilter(request, response);
			return;
		}

		UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {

		String authorizationHeader = request.getHeader(theEnvironment.getProperty("authorization.token.header.name"));

		// check if authorizationHeader null or header does not starts with Bearer if
		if (authorizationHeader == null) {
			return null;
		}

		String token = authorizationHeader.replace(theEnvironment.getProperty("authorization.token.header.prefix"), "");

		String userId = Jwts.parser().setSigningKey(theEnvironment.getProperty("token.secret")).parseClaimsJws(token)
				.getBody().getSubject();

		return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
	}

}
