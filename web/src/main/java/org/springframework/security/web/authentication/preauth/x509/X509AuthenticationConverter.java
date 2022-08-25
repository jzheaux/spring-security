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

package org.springframework.security.web.authentication.preauth.x509;

import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public final class X509AuthenticationConverter implements AuthenticationConverter {
	private final Log logger = LogFactory.getLog(getClass());

	private X509PrincipalExtractor principalExtractor = new SubjectDnX509PrincipalExtractor();

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource =
			new WebAuthenticationDetailsSource();

	@Override
	public Authentication convert(HttpServletRequest request) {
		X509Certificate certificate = extractClientCertificate(request);
		if (certificate == null) {
			return null;
		}
		Object principal = this.principalExtractor.extractPrincipal(certificate);
		if (principal == null) {
			return null;
		}
		PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(principal, certificate);
		token.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return token;
	}

	private X509Certificate extractClientCertificate(HttpServletRequest request) {
		X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
		if (certs != null && certs.length > 0) {
			this.logger.debug(LogMessage.format("X.509 client authentication certificate:%s", certs[0]));
			return certs[0];
		}
		this.logger.debug("No client certificate found in request.");
		return null;
	}

	public void setPrincipalExtractor(X509PrincipalExtractor principalExtractor) {
		this.principalExtractor = principalExtractor;
	}

	public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}
}
