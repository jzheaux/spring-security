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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.LogoutResponseUnmarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlVerificationUtils.VerifierPartial;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

/**
 * A {@link AuthenticationManager} that authenticates a SAML 2.0 Logout Responses received from a SAML 2.0
 * Asserting Party.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class OpenSamlLogoutResponseAuthenticationManager implements AuthenticationManager {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final ParserPool parserPool;

	private final LogoutResponseUnmarshaller unmarshaller;

	/**
	 * Constructs a {@link OpenSamlLogoutRequestAuthenticationManager}
	 */
	public OpenSamlLogoutResponseAuthenticationManager() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.unmarshaller = (LogoutResponseUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
				.getUnmarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Saml2LogoutResponseAuthenticationToken token = (Saml2LogoutResponseAuthenticationToken) authentication;
		Saml2LogoutRequest logoutRequest = token.getLogoutRequest();
		Saml2LogoutResponse response = token.getLogoutResponse();
		RelyingPartyRegistration registration = token.getRelyingPartyRegistration();
		byte[] b = Saml2Utils.samlDecode(response.getSamlResponse());
		LogoutResponse logoutResponse = parse(inflateIfRequired(response, b));
		Saml2ResponseValidatorResult result = verifySignature(response, logoutResponse, registration)
				.concat(validateRequest(logoutResponse, registration))
				.concat(validateLogoutRequest(logoutResponse, logoutRequest.getId()));
		if (result.hasErrors()) {
			throw new BadCredentialsException(
					"Failed to validate LogoutResponse: " + result.getErrors().iterator().next());
		}
		return new OpenSamlLogoutResponseAuthentication(logoutResponse, registration);
	}

	private String inflateIfRequired(Saml2LogoutResponse response, byte[] b) {
		if (response.getBinding() == Saml2MessageBinding.REDIRECT) {
			return Saml2Utils.samlInflate(b);
		}
		return new String(b, StandardCharsets.UTF_8);
	}

	private LogoutResponse parse(String response) throws Saml2Exception {
		try {
			Document document = this.parserPool
					.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutResponse) this.unmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception("Failed to deserialize LogoutResponse", ex);
		}
	}

	private Saml2ResponseValidatorResult verifySignature(Saml2LogoutResponse response, LogoutResponse logoutResponse,
			RelyingPartyRegistration registration) {
		VerifierPartial partial = OpenSamlVerificationUtils.verifySignature(logoutResponse, registration);
		if (logoutResponse.isSigned()) {
			return partial.post(logoutResponse.getSignature());
		}
		return partial.redirect(response);
	}

	private Saml2ResponseValidatorResult validateRequest(LogoutResponse response,
			RelyingPartyRegistration registration) {
		Saml2ResponseValidatorResult result = Saml2ResponseValidatorResult.success();
		return result.concat(validateIssuer(response, registration)).concat(validateDestination(response, registration))
				.concat(validateStatus(response));
	}

	private Saml2ResponseValidatorResult validateIssuer(LogoutResponse response,
			RelyingPartyRegistration registration) {
		if (response.getIssuer() == null) {
			return Saml2ResponseValidatorResult
					.failure(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to find issuer in LogoutResponse"));
		}
		String issuer = response.getIssuer().getValue();
		if (!issuer.equals(registration.getAssertingPartyDetails().getEntityId())) {
			return Saml2ResponseValidatorResult.failure(
					new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
		}
		return Saml2ResponseValidatorResult.success();
	}

	private Saml2ResponseValidatorResult validateDestination(LogoutResponse response,
			RelyingPartyRegistration registration) {
		if (response.getDestination() == null) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to find destination in LogoutResponse"));
		}
		String destination = response.getDestination();
		if (!destination.equals(registration.getSingleLogoutServiceResponseLocation())) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to match destination to configured destination"));
		}
		return Saml2ResponseValidatorResult.success();
	}

	private Saml2ResponseValidatorResult validateStatus(LogoutResponse response) {
		if (response.getStatus() == null) {
			return Saml2ResponseValidatorResult.success();
		}
		if (response.getStatus().getStatusCode() == null) {
			return Saml2ResponseValidatorResult.success();
		}
		if (StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())) {
			return Saml2ResponseValidatorResult.success();
		}
		if (StatusCode.PARTIAL_LOGOUT.equals(response.getStatus().getStatusCode().getValue())) {
			return Saml2ResponseValidatorResult.success();
		}
		return Saml2ResponseValidatorResult
				.failure(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Response indicated logout failed"));
	}

	private Saml2ResponseValidatorResult validateLogoutRequest(LogoutResponse response, String id) {
		if (response.getInResponseTo() == null) {
			return Saml2ResponseValidatorResult.success();
		}
		if (response.getInResponseTo().equals(id)) {
			return Saml2ResponseValidatorResult.success();
		}
		return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE,
				"LogoutResponse InResponseTo doesn't match ID of associated LogoutRequest"));
	}

}
