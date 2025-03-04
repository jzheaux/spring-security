/*
 * Copyright 2002-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.resource.authentication;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;

/**
 * A {@link Jwt} authentication converter that merges the {@link Jwt} and the underlying
 * {@link UserDetails} and its authorities that the {@link Jwt} refers to.
 *
 * @author Josh Cummings
 * @since 6.5
 */
public class JwtUserDetailsAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

	private final UserDetailsService userDetailsService;

	private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

	private String principalClaimName = JwtClaimNames.SUB;

	public JwtUserDetailsAuthenticationConverter(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	public AbstractAuthenticationToken convert(Jwt jwt) {
		String username = jwt.getClaimAsString(this.principalClaimName);
		try {
			UserDetails details = this.userDetailsService.loadUserByUsername(username);
			Collection<GrantedAuthority> authorities = this.jwtGrantedAuthoritiesConverter.convert(jwt);
			Set<GrantedAuthority> union = Stream.concat(authorities.stream(), details.getAuthorities().stream())
				.collect(Collectors.toSet());
			return new UsernamePasswordAuthenticationToken(details, jwt, union);
		}
		catch (UsernameNotFoundException ex) {
			throw new BadCredentialsException(
					"Failed to authenticate as " + this.principalClaimName + " is not a user");
		}
	}

	/**
	 * Sets the {@link Converter Converter&lt;Jwt, Collection&lt;GrantedAuthority&gt;&gt;}
	 * to use. Defaults to {@link JwtGrantedAuthoritiesConverter}.
	 * @param jwtGrantedAuthoritiesConverter the converter
	 * @see JwtGrantedAuthoritiesConverter
	 */
	public void setJwtGrantedAuthoritiesConverter(
			Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
		Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
		this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
	}

	/**
	 * Sets the principal claim name. Defaults to {@link JwtClaimNames#SUB}.
	 * @param principalClaimName the principal claim name
	 */
	public void setPrincipalClaimName(String principalClaimName) {
		Assert.hasText(principalClaimName, "principalClaimName cannot be empty");
		this.principalClaimName = principalClaimName;
	}

}
