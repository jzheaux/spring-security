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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.function.Consumer;
import java.util.function.Supplier;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestUnmarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.web.client.RestTemplate;

public class OpenSamlLogoutRequestDecoder implements Saml2LogoutRequestDecoder {
	static {
		OpenSamlInitializationService.initialize();
	}

	private Log logger = LogFactory.getLog(this.getClass());

	private static final XMLObjectProviderRegistry registry;
	private static final IssuerBuilder issuerBuilder;
	static {
		registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
	}

	private final LogoutRequestUnmarshaller requestUnmarshaller;
	private final ParserPool parserPool;

	private Converter<LogoutRequest, Saml2ResponseValidatorResult> logoutRequestVerifier;
	private Consumer<LogoutRequest> logoutRequestDecrypter;
	private Converter<LogoutRequest, Saml2ResponseValidatorResult> logoutRequestValidator;

	public OpenSamlLogoutRequestDecoder(
			Supplier<Collection<Saml2X509Credential>> verificationCredentials,
			Supplier<Collection<Saml2X509Credential>> decryptionCredentials,
			String issuer) {
		this(createDefaultLogoutRequestVerifier(verificationCredentials),
				createDefaultLogoutRequestDecrypter(decryptionCredentials),
				createDefaultLogoutRequestValidator(issuer));
	}

	public OpenSamlLogoutRequestDecoder(
			Converter<LogoutRequest, Saml2ResponseValidatorResult> logoutRequestVerifier,
			Consumer<LogoutRequest> logoutRequestDecrypter,
			Converter<LogoutRequest, Saml2ResponseValidatorResult> logoutRequestValidator) {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.requestUnmarshaller = (LogoutRequestUnmarshaller) registry.getUnmarshallerFactory()
				.getUnmarshaller(LogoutRequest.DEFAULT_ELEMENT_NAME);
		this.parserPool = registry.getParserPool();
		this.logoutRequestVerifier = logoutRequestVerifier;
		this.logoutRequestDecrypter = logoutRequestDecrypter;
		this.logoutRequestValidator = logoutRequestValidator;
	}

	@Override
	public Saml2LogoutRequest decode(String logoutRequest) {
		LogoutRequest request = parse(logoutRequest);
		Saml2ResponseValidatorResult result = this.logoutRequestVerifier.convert(request);
		if (request.isSigned()) {
			this.logoutRequestDecrypter.accept(request);
		}
		result = this.logoutRequestValidator.convert(request);
		// try and invalidate session indexes
		RestTemplate rest = new RestTemplate();

		return null;
	}

	public static OpenSamlLogoutRequestDecoder fromRelyingPartyRegistration(
			Supplier<RelyingPartyRegistration> relyingPartyRegistration) {
		return new OpenSamlLogoutRequestDecoder(
				(request) -> {
					Collection<Saml2X509Credential> credentials = relyingPartyRegistration.get()
							.getAssertingPartyDetails().getVerificationX509Credentials();
					return createDefaultLogoutRequestVerifier(() -> credentials).convert(request);
				},
				(request) -> {
					Collection<Saml2X509Credential> credentials = relyingPartyRegistration.get()
							.getDecryptionX509Credentials();
					createDefaultLogoutRequestDecrypter(() -> credentials).accept(request);
				},
				(request) -> {
					String issuer = relyingPartyRegistration.get().getAssertingPartyDetails().getEntityId();
					return createDefaultLogoutRequestValidator(issuer).convert(request);
				}
		);
	}

	private static Converter<LogoutRequest, Saml2ResponseValidatorResult> createDefaultLogoutRequestVerifier
			(Supplier<Collection<Saml2X509Credential>> credentials) {
		return null;
	}

	private static Consumer<LogoutRequest> createDefaultLogoutRequestDecrypter
			(Supplier<Collection<Saml2X509Credential>> credentials) {
		return null;
	}

	private static Converter<LogoutRequest, Saml2ResponseValidatorResult> createDefaultLogoutRequestValidator
			(String issuerValue) {
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerValue);
		return (request) -> {
			Saml2ResponseValidatorResult result = Saml2ResponseValidatorResult.success();
			if (!issuer.equals(request.getIssuer())) {
				result = result.concat(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "invalid issuer"));
			}
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authentication == null || !authentication.getName().equals(request.getNameID().getValue())) {
				result = result.concat(new Saml2Error(Saml2ErrorCodes.SUBJECT_NOT_FOUND, "invalid subject"));
			}
			return result;
		};
	}

	private LogoutRequest parse(String request) {
		try {
			Document document = this.parserPool
					.parse(new ByteArrayInputStream(request.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutRequest) this.requestUnmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex.getMessage(), ex);
		}
	}
}
