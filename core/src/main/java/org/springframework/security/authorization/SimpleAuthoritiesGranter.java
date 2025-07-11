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

package org.springframework.security.authorization;

import java.time.Clock;
import java.time.Duration;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthoritiesContainer;
import org.springframework.security.core.authority.ExpirableGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public final class SimpleAuthoritiesGranter implements AuthoritiesGranter {

	private final Duration grantingTime;

	private final Collection<String> authorities;

	private Clock clock = Clock.systemUTC();

	public SimpleAuthoritiesGranter(String... authorities) {
		this.grantingTime = null;
		this.authorities = List.of(authorities);
	}

	public SimpleAuthoritiesGranter(Duration grantingTime, String... authorities) {
		this.grantingTime = grantingTime;
		this.authorities = List.of(authorities);
	}

	@Override
	public Boolean grantsAuthority(GrantedAuthority authority) {
		return this.authorities.contains(authority.getAuthority());
	}

	@Override
	public AuthoritiesContainer grantAuthorities(AuthoritiesContainer authentication) {
		return authentication.grantedAuthorities((authorities) -> {
			for (String authority : this.authorities) {
				if (this.grantingTime == null) {
					authorities.add(new SimpleGrantedAuthority(authority));
				}
				else {
					authorities
						.add(new ExpirableGrantedAuthority(authority, this.clock.instant().plus(this.grantingTime)));
				}
			}
		});
	}

	@Override
	public Collection<GrantedAuthority> neededAuthorities(AuthoritiesContainer authentication) {
		Set<String> authorities = new HashSet<>(this.authorities);
		for (GrantedAuthority authority : authentication.getGrantedAuthorities()) {
			authorities.remove(authority.getAuthority());
		}
		return authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
	}

}
