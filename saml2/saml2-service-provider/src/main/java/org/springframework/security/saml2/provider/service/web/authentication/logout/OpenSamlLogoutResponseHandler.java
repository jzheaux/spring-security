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
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.LogoutResponseUnmarshaller;
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
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.util.UriUtils;

/**
 * We initiated logout, and now its complete
 */
public final class OpenSamlLogoutResponseHandler implements LogoutHandler {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final ParserPool parserPool;

	private final LogoutResponseUnmarshaller unmarshaller;

	public OpenSamlLogoutResponseHandler() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.unmarshaller = (LogoutResponseUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
				.getUnmarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		String serialized = request.getParameter("SAMLResponse");
		if (serialized == null) {
			return;
		}
		byte[] b = Saml2Utils.samlDecode(serialized);
		serialized = Saml2Utils.samlInflate(b);
		RelyingPartyRegistration registration = null;
		if (authentication instanceof Saml2Authentication) {
			registration = ((Saml2Authentication) authentication).getRegistration();
		}
		if (registration == null) {
			throw new Saml2Exception(
					"A RelyingPartyRegistration is required in order to validate the LogoutResponse signature, but none was found");
		}
		LogoutResponse logoutResponse = parse(serialized);
		Saml2ResponseValidatorResult result = verifySignature(request, logoutResponse, registration);
		result.concat(validateRequest(logoutResponse, registration, authentication));
		if (result.hasErrors()) {
			throw new Saml2Exception("Failed to validate LogoutResponse: " + result.getErrors().iterator().next());
		}
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

	private Saml2ResponseValidatorResult verifySignature(HttpServletRequest request, LogoutResponse response,
			RelyingPartyRegistration registration) {
		if (response.isSigned()) {
			return verifyPostSignature(response, registration);
		}
		if (request.getParameter("SigAlg") == null) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE, "Failed to derive signature algorithm from request"));
		}
		if (request.getParameter("Signature") == null) {
			return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE, "Failed to derive signature from request"));
		}
		return verifyRedirectSignature(request, response, registration);
	}

	private Saml2ResponseValidatorResult verifyRedirectSignature(HttpServletRequest request, LogoutResponse logoutResponse,
			RelyingPartyRegistration registration) {
		Collection<Saml2Error> errors = new ArrayList<>();
		String algorithmUri = request.getParameter("SigAlg");
		byte[] signature = Saml2Utils.samlDecode(request.getParameter("Signature"));
		String query = "SAMLResponse=" + UriUtils.encode(request.getParameter("SAMLResponse"), StandardCharsets.ISO_8859_1) + "&" +
				"SigAlg=" + UriUtils.encode(algorithmUri, StandardCharsets.ISO_8859_1);
		byte[] content = query.getBytes(StandardCharsets.UTF_8);
		String issuer = logoutResponse.getIssuer().getValue();
		try {
			CriteriaSet criteriaSet = new CriteriaSet();
			criteriaSet.add(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer)));
			criteriaSet.add(
					new EvaluableProtocolRoleDescriptorCriterion(new ProtocolCriterion(SAMLConstants.SAML20P_NS)));
			criteriaSet.add(new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
			if (!trustEngine(registration).validate(signature, content, algorithmUri, criteriaSet, null)) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for SAML Response [" + logoutResponse.getID() + "]"));
			}
		}
		catch (Exception ex) {
			errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
					"Invalid signature for SAML Response [" + logoutResponse.getID() + "]: "));
		}
		return Saml2ResponseValidatorResult.failure(errors);
	}

	private Saml2ResponseValidatorResult verifyPostSignature(LogoutResponse response,
			RelyingPartyRegistration registration) {
		Collection<Saml2Error> errors = new ArrayList<>();
		String issuer = response.getIssuer().getValue();
		if (response.isSigned()) {
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			try {
				profileValidator.validate(response.getSignature());
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for SAML Response [" + response.getID() + "]: "));
			}

			try {
				CriteriaSet criteriaSet = new CriteriaSet();
				criteriaSet.add(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer)));
				criteriaSet.add(
						new EvaluableProtocolRoleDescriptorCriterion(new ProtocolCriterion(SAMLConstants.SAML20P_NS)));
				criteriaSet.add(new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
				if (!trustEngine(registration).validate(response.getSignature(), criteriaSet)) {
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
							"Invalid signature for SAML Response [" + response.getID() + "]"));
				}
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for SAML Response [" + response.getID() + "]: "));
			}
		}

		return Saml2ResponseValidatorResult.failure(errors);
	}

	private Saml2ResponseValidatorResult validateRequest(LogoutResponse response, RelyingPartyRegistration registration,
			Authentication authentication) {
		Saml2ResponseValidatorResult result = Saml2ResponseValidatorResult.success();
		result.concat(validateIssuer(response, registration));
		result.concat(validateDestination(response, registration));
		return result.concat(validateStatus(response));
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
		if (!StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())) {
			return Saml2ResponseValidatorResult
					.failure(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Response indicated logout failed"));
		}
		return Saml2ResponseValidatorResult.success();
	}

	private SignatureTrustEngine trustEngine(RelyingPartyRegistration registration) {
		Set<Credential> credentials = new HashSet<>();
		Collection<Saml2X509Credential> keys = registration.getAssertingPartyDetails().getVerificationX509Credentials();
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
