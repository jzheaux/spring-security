/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.resource.web.access;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenErrorUtils;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Translates any {@link AccessDeniedException} into a corresponding HTTP response in accordance with
 * <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate</a>
 *
 * @author Josh Cummings
 * @since 5.1
 */
public final class BearerTokenAccessDeniedHandler implements AccessDeniedHandler {

	private static final Collection<String> WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES =
			Arrays.asList("scope", "scp");

	private String defaultRealmName;

	@Override
	public void handle(
			HttpServletRequest request,
			HttpServletResponse response,
			AccessDeniedException accessDeniedException)
			throws IOException, ServletException {

		String scope = getScope(request.getUserPrincipal());
		BearerTokenError error = insufficientScope(scope);
		String wwwAuthenticate = BearerTokenErrorUtils
				.computeWWWAuthenticateHeaderValue(this.defaultRealmName, error);

		response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
		response.setStatus(error.getHttpStatus().value());
	}

	public void setDefaultRealmName(String defaultRealmName) {
		this.defaultRealmName = defaultRealmName;
	}

	private static String getScope(Principal principal) {
		if ( principal instanceof AbstractOAuth2TokenAuthenticationToken ) {
			Map<String, Object> attributes = ((AbstractOAuth2TokenAuthenticationToken) principal)
					.getTokenAttributes();

			for (String attributeName : WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES) {
				Object scopes = attributes.get(attributeName);
				if (scopes instanceof String) {
					return (String) scopes;
				} else if (scopes instanceof Collection) {
					Collection coll = (Collection) scopes;
					return (String) coll.stream()
							.map(String::valueOf)
							.collect(Collectors.joining(" "));
				}
			}
		}

		return "";
	}

	private static BearerTokenError insufficientScope(String scope) {
		return new BearerTokenError(
				BearerTokenErrorCodes.INSUFFICIENT_SCOPE,
				HttpStatus.FORBIDDEN,
				String.format("The token provided has insufficient scope [%s] for this request", scope),
				"https://tools.ietf.org/html/rfc6750#section-3.1",
				scope
		);
	}
}
