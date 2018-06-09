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

package org.springframework.security.oauth2.resourceserver.web;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.resourceserver.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An {@link AuthenticationEntryPoint} implementation used to commence authentication of protected resource requests
 * using {@link BearerTokenAuthenticationFilter}.
 * <p>
 * Uses information provided by {@link BearerTokenError} to set HTTP response status code and populate
 * {@code WWW-Authenticate} HTTP header.
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see BearerTokenError
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate
 * Response Header Field</a>
 */
public final class BearerTokenAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private String defaultRealmName;


	@Override
	public void commence(
			HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) {

		String wwwAuthenticate;
		String realmName = this.defaultRealmName;
		HttpStatus status = HttpStatus.UNAUTHORIZED;

		if (authException instanceof OAuth2AuthenticationException) {
			OAuth2Error error = ((OAuth2AuthenticationException) authException).getError();

			wwwAuthenticate = BearerTokenErrorUtils.computeWWWAuthenticateHeaderValue(realmName, error);

			if ( error instanceof BearerTokenError ) {
				status = ((BearerTokenError) error).getHttpStatus();
			}
		} else {
			wwwAuthenticate = BearerTokenErrorUtils.computeWWWAuthenticateHeaderValue(realmName);
		}

		response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
		response.setStatus(status.value());
	}

	public void setDefaultRealmName(String realmName) {
		this.defaultRealmName = realmName;
	}
}
