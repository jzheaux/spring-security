/*
 * Copyright 2002-2021 the original author or authors.
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
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

public class Saml2AssertingPartyInitiatedLogoutSuccessHandler implements LogoutSuccessHandler {

	private final Saml2LogoutResponseResolver logoutResponseResolver;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public Saml2AssertingPartyInitiatedLogoutSuccessHandler(Saml2LogoutResponseResolver logoutResponseResolver) {
		this.logoutResponseResolver = logoutResponseResolver;
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException {
		if (!(authentication instanceof Saml2Authentication)) {
			return;
		}
		RelyingPartyRegistration registration = ((Saml2Authentication) authentication).getRegistration();
		if (request.getAttribute(Saml2RequestAttributeNames.LOGOUT_REQUEST_ID) == null) {
			return;
		}
		String logoutRequestId = (String) request.getAttribute(Saml2RequestAttributeNames.LOGOUT_REQUEST_ID);
		Saml2LogoutResponse logoutResponse = this.logoutResponseResolver.resolveLogoutResponse(request, registration)
				.inResponseTo(logoutRequestId).resolve();
		if (registration.getAssertingPartyDetails().getSingleLogoutServiceBinding() == Saml2MessageBinding.REDIRECT) {
			doRedirect(request, response, registration, logoutResponse);
		}
		else {
			doPost(request, response, registration, logoutResponse);
		}
	}

	private void doRedirect(HttpServletRequest request, HttpServletResponse response,
			RelyingPartyRegistration registration, Saml2LogoutResponse logoutResponse) throws IOException {
		String location = registration.getAssertingPartyDetails().getSingleLogoutServiceLocation();
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(location);
		addParameter("SAMLRequest", logoutResponse, uriBuilder);
		addParameter("SigAlg", logoutResponse, uriBuilder);
		addParameter("Signature", logoutResponse, uriBuilder);
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.build(true).toUriString());
	}

	private void addParameter(String name, Saml2LogoutResponse logoutResponse, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (StringUtils.hasText(logoutResponse.getParameter(name))) {
			builder.queryParam(UriUtils.encode(name, StandardCharsets.ISO_8859_1),
					UriUtils.encode(logoutResponse.getParameter(name), StandardCharsets.ISO_8859_1));
		}
	}

	private void doPost(HttpServletRequest request, HttpServletResponse response, RelyingPartyRegistration registration,
			Saml2LogoutResponse logoutResponse) throws IOException {
		String html = createSamlPostRequestFormData(logoutResponse, registration);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlPostRequestFormData(Saml2LogoutResponse logoutResponse,
			RelyingPartyRegistration registration) {
		String authenticationRequestUri = registration.getAssertingPartyDetails().getSingleLogoutServiceLocation();
		String samlRequest = logoutResponse.getSamlRequest();
		StringBuilder html = new StringBuilder();
		html.append("<!DOCTYPE html>\n");
		html.append("<html>\n").append("    <head>\n");
		html.append("        <meta charset=\"utf-8\" />\n");
		html.append("    </head>\n");
		html.append("    <body onload=\"document.forms[0].submit()\">\n");
		html.append("        <noscript>\n");
		html.append("            <p>\n");
		html.append("                <strong>Note:</strong> Since your browser does not support JavaScript,\n");
		html.append("                you must press the Continue button once to proceed.\n");
		html.append("            </p>\n");
		html.append("        </noscript>\n");
		html.append("        \n");
		html.append("        <form action=\"");
		html.append(authenticationRequestUri);
		html.append("\" method=\"post\">\n");
		html.append("            <div>\n");
		html.append("                <input type=\"hidden\" name=\"SAMLRequest\" value=\"");
		html.append(HtmlUtils.htmlEscape(samlRequest));
		html.append("\"/>\n");
		html.append("            </div>\n");
		html.append("            <noscript>\n");
		html.append("                <div>\n");
		html.append("                    <input type=\"submit\" value=\"Continue\"/>\n");
		html.append("                </div>\n");
		html.append("            </noscript>\n");
		html.append("        </form>\n");
		html.append("        \n");
		html.append("    </body>\n");
		html.append("</html>");
		return html.toString();
	}

}
