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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.authorization.AuthoritiesGranter;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.SimpleAuthoritiesGranter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public interface AuthorizableConfigurer<C> {

	C grants(AuthoritiesGranter granter);

	default C grants(String authority) {
		return grants(new SimpleAuthoritiesGranter(authority));
	}

	C authenticates(AuthoritiesGranter granter);

	default C authenticates() {
		return authenticates(new SimpleAuthoritiesGranter("authenticated"));
	}

	C needs(AuthorizationManager<RequestAuthorizationContext> needs);

	default C needs(String authority) {
		return needs(AuthorityAuthorizationManager.hasAuthority(authority));
	}

}
