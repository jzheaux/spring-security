/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.authentication.preauth.websphere;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public final class WebsphereAuthenticationConverter implements AuthenticationConverter {
	private final WASUsernameAndGroupsExtractor wasUsernameAndGroupsExtractor;

	private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	public WebsphereAuthenticationConverter() {
		this(new DefaultWASUsernameAndGroupsExtractor());
	}

	public WebsphereAuthenticationConverter(WASUsernameAndGroupsExtractor wasUsernameAndGroupsExtractor) {
		this.wasUsernameAndGroupsExtractor = wasUsernameAndGroupsExtractor;
		this.authenticationDetailsSource = new WebSpherePreAuthenticatedWebAuthenticationDetailsSource(wasUsernameAndGroupsExtractor);
	}

	public WebsphereAuthenticationConverter(WASUsernameAndGroupsExtractor wasUsernameAndGroupsExtractor, AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.wasUsernameAndGroupsExtractor = wasUsernameAndGroupsExtractor;
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		Object principal = this.wasUsernameAndGroupsExtractor.getCurrentUserName();
		if (principal == null) {
			return null;
		}
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, "N/A");
		token.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return token;
	}
}
