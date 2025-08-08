/*
 * Copyright 2004-present the original author or authors.
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
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.ExpirableGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

public final class AlwaysAuthoritiesGranter implements AuthoritiesGranter {

	private final @Nullable Duration grantingTime;

	private final Collection<String> authorities;

	private Clock clock = Clock.systemUTC();

	public AlwaysAuthoritiesGranter(String... authorities) {
		this.grantingTime = null;
		this.authorities = List.of(authorities);
	}

	public AlwaysAuthoritiesGranter(Duration grantingTime, String... authorities) {
		Assert.notEmpty(authorities, "authorities cannot be empty");
		this.grantingTime = grantingTime;
		this.authorities = List.of(authorities);
	}

	@Override
	public Collection<String> grantableAuthorities() {
		return this.authorities;
	}

	@Override
	public Authentication grantAuthorities(Authentication authentication) {
		Collection<GrantedAuthority> toGrant = new HashSet<>();
		for (String authority : this.authorities) {
			if (this.grantingTime == null) {
				toGrant.add(new SimpleGrantedAuthority(authority));
			}
			else {
				Instant expiresAt = this.clock.instant().plus(this.grantingTime);
				toGrant.add(new ExpirableGrantedAuthority(authority, expiresAt));
			}
		}
		Collection<GrantedAuthority> current = new HashSet<>(authentication.getGrantedAuthorities());
		toGrant.addAll(current);
		return authentication.withGrantedAuthorities(toGrant);
	}

	public void setClock(Clock clock) {
		this.clock = clock;
	}

}
