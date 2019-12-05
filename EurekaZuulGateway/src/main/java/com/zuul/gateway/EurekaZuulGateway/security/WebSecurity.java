
package com.zuul.gateway.EurekaZuulGateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	private Environment theEnvironment;

	@Autowired
	public WebSecurity(Environment theEnvironment) {
		this.theEnvironment = theEnvironment;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().disable();

		http.authorizeRequests()
				.antMatchers(HttpMethod.POST, theEnvironment.getProperty("api.registration.manager.url.path"))
				.permitAll().antMatchers(HttpMethod.POST, theEnvironment.getProperty("api.login.url.path")).permitAll()
				.anyRequest().authenticated().and()
				.addFilter(new AuthorizationFilter(authenticationManager(), theEnvironment));

		// for session management
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}

}
