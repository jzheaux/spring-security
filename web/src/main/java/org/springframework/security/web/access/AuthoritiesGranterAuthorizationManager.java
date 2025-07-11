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

package org.springframework.security.web.access;

import java.util.Collection;
import java.util.function.Supplier;

import org.springframework.security.authorization.AuthoritiesGranter;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthoritiesContainer;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class AuthoritiesGranterAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

	private final AuthoritiesGranter granter;

	public AuthoritiesGranterAuthorizationManager(AuthoritiesGranter granter) {
		this.granter = granter;
	}

	@Override
	public AuthorizationResult authorize(Supplier<Authentication> authentication, RequestAuthorizationContext object) {
		if (!(authentication.get() instanceof AuthoritiesContainer container)) {
			return null;
		}
		Collection<GrantedAuthority> neededAuthorities = this.granter.neededAuthorities(container);
		return new AuthorityAuthorizationDecision(neededAuthorities.isEmpty(), neededAuthorities);
	}

}
