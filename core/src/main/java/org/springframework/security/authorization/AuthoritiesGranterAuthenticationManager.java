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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public final class AuthoritiesGranterAuthenticationManager implements AuthenticationManager {

	private final AuthenticationManager authenticationManager;

	private final AuthoritiesGranter authoritiesGranter;

	public AuthoritiesGranterAuthenticationManager(AuthenticationManager manager, AuthoritiesGranter granter) {
		this.authenticationManager = manager;
		this.authoritiesGranter = granter;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Authentication result = this.authenticationManager.authenticate(authentication);
		return this.authoritiesGranter.grantAuthorities(result);
	}

}
