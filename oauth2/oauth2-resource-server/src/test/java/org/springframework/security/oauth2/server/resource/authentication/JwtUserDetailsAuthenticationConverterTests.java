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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * Tests for {@link JwtUserDetailsAuthenticationConverter}
 */
@ExtendWith(MockitoExtension.class)
class JwtUserDetailsAuthenticationConverterTests {

	JwtUserDetailsAuthenticationConverter jwtAuthenticationConverter;

	@Mock
	UserDetailsService userDetailsService;

	@BeforeEach
	void setUp() {
		this.jwtAuthenticationConverter = new JwtUserDetailsAuthenticationConverter(this.userDetailsService);
	}

	@Test
	void convertWhenDefaultGrantedAuthoritiesConverterSet() {
		given(this.userDetailsService.loadUserByUsername(any())).willReturn(withUsername("mock-test-subject"));
		Jwt jwt = TestJwts.jwt().claim("scope", "message:read message:write").build();
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt);
		Collection<GrantedAuthority> authorities = authentication.getAuthorities();
		assertThat(AuthorityUtils.authorityListToSet(authorities)).containsExactlyInAnyOrder("SCOPE_message:read",
				"SCOPE_message:write", "ROLE_USER");
	}

	@Test
	void whenSettingNullGrantedAuthoritiesConverter() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(null))
			.withMessage("jwtGrantedAuthoritiesConverter cannot be null");
	}

	@Test
	void convertWithOverriddenGrantedAuthoritiesConverter() {
		given(this.userDetailsService.loadUserByUsername(any())).willReturn(withUsername("mock-test-subject"));
		Jwt jwt = TestJwts.jwt().claim("scope", "message:read message:write").build();
		Converter<Jwt, Collection<GrantedAuthority>> grantedAuthoritiesConverter = (token) -> AuthorityUtils
			.createAuthorityList("blah");
		this.jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt);
		Collection<GrantedAuthority> authorities = authentication.getAuthorities();
		assertThat(AuthorityUtils.authorityListToSet(authorities)).containsExactlyInAnyOrder("blah", "ROLE_USER");
	}

	@Test
	void convertWhenUserNotFoundThenBadCredentials() {
		given(this.userDetailsService.loadUserByUsername(any()))
			.willThrow(new UsernameNotFoundException("user not found"));
		assertThatExceptionOfType(BadCredentialsException.class)
			.isThrownBy(() -> this.jwtAuthenticationConverter.convert(TestJwts.jwt().build()));
	}

	@Test
	void whenSettingNullPrincipalClaimName() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.jwtAuthenticationConverter.setPrincipalClaimName(null))
				.withMessage("principalClaimName cannot be empty");
		// @formatter:on
	}

	@Test
	void whenSettingEmptyPrincipalClaimName() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.jwtAuthenticationConverter.setPrincipalClaimName(""))
				.withMessage("principalClaimName cannot be empty");
		// @formatter:on
	}

	@Test
	void whenSettingBlankPrincipalClaimName() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.jwtAuthenticationConverter.setPrincipalClaimName(" "))
				.withMessage("principalClaimName cannot be empty");
		// @formatter:on
	}

	@Test
	void convertWhenPrincipalClaimNameSet() {
		given(this.userDetailsService.loadUserByUsername(any())).willReturn(withUsername("100"));
		this.jwtAuthenticationConverter.setPrincipalClaimName("user_id");
		Jwt jwt = TestJwts.jwt().claim("user_id", "100").build();
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt);
		assertThat(authentication.getName()).isEqualTo("100");
	}

	@Test
	void convertWhenPrincipalClaimNameSetAndClaimValueIsNotString() {
		given(this.userDetailsService.loadUserByUsername(any())).willReturn(withUsername("100"));
		this.jwtAuthenticationConverter.setPrincipalClaimName("user_id");
		Jwt jwt = TestJwts.jwt().claim("user_id", 100).build();
		AbstractAuthenticationToken authentication = this.jwtAuthenticationConverter.convert(jwt);
		assertThat(authentication.getName()).isEqualTo("100");
	}

	private UserDetails withUsername(String username) {
		return User.withUsername(username).password("password").authorities("ROLE_USER").build();
	}

}
