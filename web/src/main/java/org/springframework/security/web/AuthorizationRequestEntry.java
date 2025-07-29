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

package org.springframework.security.web;

import org.springframework.security.authorization.AuthoritiesGranter;
import org.springframework.util.Assert;

public class AuthorizationRequestEntry {

	private final AuthoritiesGranter granter;

	private final AuthenticationEntryPoint requester;

	private final int order;

	public AuthorizationRequestEntry(AuthoritiesGranter granter, AuthenticationEntryPoint requester, int order) {
		Assert.notNull(granter, "authoritiesGranter cannot be null");
		Assert.notNull(requester, "authenticationEntryPoint cannot be null");
		this.granter = granter;
		this.requester = requester;
		this.order = order;
	}

	public AuthoritiesGranter getAuthoritiesGranter() {
		return this.granter;
	}

	public AuthenticationEntryPoint getAuthenticationEntryPoint() {
		return this.requester;
	}

	public int getOrder() {
		return this.order;
	}

}
