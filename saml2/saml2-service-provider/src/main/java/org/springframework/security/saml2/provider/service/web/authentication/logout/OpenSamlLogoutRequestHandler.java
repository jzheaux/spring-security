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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.metadata.criteria.role.impl.EvaluableProtocolRoleDescriptorCriterion;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.impl.LogoutRequestUnmarshaller;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.criteria.impl.EvaluableEntityIDCredentialCriterion;
import org.opensaml.security.credential.criteria.impl.EvaluableUsageCredentialCriterion;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.authentication.logout.LogoutHandler;


// received LogoutRequest from asserting party; process, throw exception if fail
public class OpenSamlLogoutRequestHandler implements LogoutHandler {
	private final ParserPool parserPool;
	private final LogoutRequestUnmarshaller unmarshaller;

	public OpenSamlLogoutRequestHandler() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.unmarshaller = (LogoutRequestUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
				.getUnmarshaller(LogoutRequest.DEFAULT_ELEMENT_NAME);
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		RelyingPartyRegistration registration = null;
		if (authentication instanceof Saml2Authentication) {
			registration = ((Saml2Authentication) authentication).getRegistration();
		}
		if (registration == null) {
			throw new Saml2Exception("A RelyingPartyRegistration is required in order to validate the LogoutRequest signature, but none was found");
		}
		String serialized = request.getParameter("SAMLRequest");
		LogoutRequest logoutRequest = parse(serialized);
		Saml2ResponseValidatorResult result = verifySignature(logoutRequest, registration);
		result.concat(validateRequest(logoutRequest, registration, authentication));
		if (result.hasErrors()) {
			throw new Saml2Exception("Failed to validate LogoutRequest: " + result.getErrors().iterator().next());
		}
	}

	private LogoutRequest parse(String request) throws Saml2Exception {
		try {
			Document document = this.parserPool
					.parse(new ByteArrayInputStream(request.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutRequest) this.unmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception("Failed to deserialize LogoutRequest", ex);
		}
	}

	private Saml2ResponseValidatorResult verifySignature(LogoutRequest request, RelyingPartyRegistration registration) {
		Collection<Saml2Error> errors = new ArrayList<>();
		String issuer = request.getIssuer().getValue();
		if (request.isSigned()) {
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			try {
				profileValidator.validate(request.getSignature());
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for SAML Response [" + request.getID() + "]: "));
			}

			try {
				CriteriaSet criteriaSet = new CriteriaSet();
				criteriaSet.add(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer)));
				criteriaSet.add(new EvaluableProtocolRoleDescriptorCriterion(
						new ProtocolCriterion(SAMLConstants.SAML20P_NS)));
				criteriaSet.add(new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
				if (!trustEngine(registration).validate(request.getSignature(), criteriaSet)) {
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
							"Invalid signature for SAML Response [" + request.getID() + "]"));
				}
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for SAML Response [" + request.getID() + "]: "));
			}
		}

		return Saml2ResponseValidatorResult.failure(errors);
	}

	private Saml2ResponseValidatorResult validateRequest(LogoutRequest request, RelyingPartyRegistration registration, Authentication authentication) {
		Saml2ResponseValidatorResult result = Saml2ResponseValidatorResult.success();
		result.concat(validateIssuer(request, registration));
		result.concat(validateDestination(request, registration));
		return result.concat(validateName(request, authentication));
	}

	private Saml2ResponseValidatorResult validateIssuer(LogoutRequest request, RelyingPartyRegistration registration) {
		if (request.getIssuer() == null) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to find issuer in LogoutResponse"));
		}
		String issuer = request.getIssuer().getValue();
		if (!issuer.equals(registration.getAssertingPartyDetails().getEntityId())) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
		}
		return Saml2ResponseValidatorResult.success();
	}

	private Saml2ResponseValidatorResult validateDestination(LogoutRequest request, RelyingPartyRegistration registration) {
		if (request.getDestination() == null) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION, "Failed to find destination in LogoutResponse"));
		}
		String destination = request.getDestination();
		if (!destination.equals(registration.getSingleLogoutServiceLocation())) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION, "Failed to match destination to configured destination"));
		}
		return Saml2ResponseValidatorResult.success();
	}

	private Saml2ResponseValidatorResult validateName(LogoutRequest request, Authentication authentication) {
		NameID nameId = request.getNameID();
		if (nameId == null) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.SUBJECT_NOT_FOUND, "Failed to find subject in LogoutRequest"));
		}
		String name = nameId.getValue();
		if (!name.equals(authentication.getName())) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_REQUEST, "Failed to match subject in LogoutRequest with currently logged in user"));
		}
		return Saml2ResponseValidatorResult.success();
	}

	private SignatureTrustEngine trustEngine(RelyingPartyRegistration registration) {
		Set<Credential> credentials = new HashSet<>();
		Collection<Saml2X509Credential> keys = registration.getAssertingPartyDetails()
				.getVerificationX509Credentials();
		for (Saml2X509Credential key : keys) {
			BasicX509Credential cred = new BasicX509Credential(key.getCertificate());
			cred.setUsageType(UsageType.SIGNING);
			cred.setEntityId(registration.getAssertingPartyDetails().getEntityId());
			credentials.add(cred);
		}
		CredentialResolver credentialsResolver = new CollectionCredentialResolver(credentials);
		return new ExplicitKeySignatureTrustEngine(credentialsResolver,
				DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
	}
}
