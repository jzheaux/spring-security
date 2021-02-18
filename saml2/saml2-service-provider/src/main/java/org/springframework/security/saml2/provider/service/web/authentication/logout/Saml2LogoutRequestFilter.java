/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

// receiving SLO response means logout is done, redirect to entry point
public class Saml2LogoutRequestFilter extends OncePerRequestFilter {
	private final Saml2LogoutRequestHandler logoutRequestHandler;
	private final AuthenticationEntryPoint entryPoint;

	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/saml2/logout-request/{registrationId}");

	// verify logout response, do any cleanup
	// redirect to entry point

	public Saml2LogoutRequestFilter(Saml2LogoutRequestHandler logoutRequestHandler, AuthenticationEntryPoint entryPoint) {
		this.logoutRequestHandler = logoutRequestHandler;
		this.entryPoint = entryPoint;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {

	}
}
