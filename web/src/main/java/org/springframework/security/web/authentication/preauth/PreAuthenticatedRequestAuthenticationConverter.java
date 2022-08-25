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

package org.springframework.security.web.authentication.preauth;

import javax.servlet.http.HttpServletRequest;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

public final class PreAuthenticatedRequestAuthenticationConverter implements AuthenticationConverter {
	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

	private final Converter<HttpServletRequest, Object> principal;
	private final Converter<HttpServletRequest, Object> credential;
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
	private boolean exceptionIfVariableMissing = false;

	public PreAuthenticatedRequestAuthenticationConverter(Converter<HttpServletRequest, Object> principal) {
		this(principal, (request) -> "N/A");
	}

	public PreAuthenticatedRequestAuthenticationConverter(Converter<HttpServletRequest, Object> principal, Converter<HttpServletRequest, Object> credential) {
		this.principal = principal;
		this.credential = credential;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		Object principal = this.principal.convert(request);
		if (principal != null) {
			Object credentials = this.credential.convert(request);
			PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, credentials);
			token.setDetails(this.authenticationDetailsSource.buildDetails(request));
			return token;
		}
		if (!this.exceptionIfVariableMissing) {
			throw new PreAuthenticatedCredentialsNotFoundException("principal request attribute not found in request.");
		}
		return null;
	}

	public void setExceptionIfVariableMissing(boolean exceptionIfVariableMissing) {
		this.exceptionIfVariableMissing = exceptionIfVariableMissing;
	}

	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public static Converter<HttpServletRequest, Object> createRequestAttributeConverter(String attributeName) {
		return (request) -> request.getAttribute(attributeName);
	}

	public static Converter<HttpServletRequest, String> createRequestHeaderConverter(String headerName) {
		return (request) -> request.getHeader(headerName);
	}
}
