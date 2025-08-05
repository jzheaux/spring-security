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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public final class CompositeAuthoritiesGranter implements AuthoritiesGranter {

	private final Collection<AuthoritiesGranter> authoritiesGranters;

	public CompositeAuthoritiesGranter(AuthoritiesGranter... authorities) {
		this.authoritiesGranters = List.of(authorities);
	}

	public CompositeAuthoritiesGranter(Collection<AuthoritiesGranter> authorities) {
		this.authoritiesGranters = new ArrayList<>(authorities);
	}

	@Override
	public boolean grantsAuthority(GrantedAuthority authority) {
		for (AuthoritiesGranter granter : this.authoritiesGranters) {
			if (granter.grantsAuthority(authority)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public Authentication grantAuthorities(Authentication authentication) {
		Authentication granted = authentication;
		for (AuthoritiesGranter granter : this.authoritiesGranters) {
			granted = granter.grantAuthorities(granted);
		}
		return granted;
	}

	public static Builder withDefaultAuthority(String authority) {
		return new Builder().authoritiesGranters((g) -> g.add(new CurrentAuthoritiesMergingAuthoritiesGranter()))
			.authoritiesGranters((g) -> g.add(new SimpleAuthoritiesGranter(authority)));
	}

	public static final class Builder {

		private List<AuthoritiesGranter> authoritiesGranters = new ArrayList<>();

		private Builder() {
		}

		public Builder mergeCurrentAuthorities() {
			this.authoritiesGranters.add(new CurrentAuthoritiesMergingAuthoritiesGranter());
			return this;
		}

		public Builder authoritiesGranters(Consumer<List<AuthoritiesGranter>> authoritiesGranters) {
			authoritiesGranters.accept(this.authoritiesGranters);
			return this;
		}

		public AuthoritiesGranter build() {
			return new CompositeAuthoritiesGranter(this.authoritiesGranters);
		}

	}

}
