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

package org.springframework.security.oauth2.resourceserver.web.access;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.resourceserver.BearerTokenError;
import org.springframework.security.oauth2.resourceserver.web.BearerTokenErrorUtils;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Translates any {@link AccessDeniedException} into a corresponding HTTP response in accordance with
 * <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate</a>
 *
 * @author Josh Cummings
 * @since 5.1
 */
public final class BearerTokenAccessDeniedHandler implements AccessDeniedHandler {

	private String defaultRealmName;

	@Override
	public void handle(
			HttpServletRequest request,
			HttpServletResponse response,
			AccessDeniedException accessDeniedException)
			throws IOException, ServletException {

		String wwwAuthenticate;
		String realmName = this.defaultRealmName;
		HttpStatus status = HttpStatus.FORBIDDEN;

		if (accessDeniedException instanceof OAuth2AccessDeniedException) {
			OAuth2Error error = ((OAuth2AccessDeniedException) accessDeniedException).getError();

			wwwAuthenticate = BearerTokenErrorUtils.computeWWWAuthenticateHeaderValue(realmName, error);

			if (error instanceof BearerTokenError) {
				status = ((BearerTokenError) error).getHttpStatus();
			}
		} else {
			wwwAuthenticate = BearerTokenErrorUtils.computeWWWAuthenticateHeaderValue(realmName);
		}

		response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
		response.setStatus(status.value());
	}

	public void setDefaultRealmName(String defaultRealmName) {
		this.defaultRealmName = defaultRealmName;
	}
}
