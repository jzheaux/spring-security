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

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import javax.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseMarshaller;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.security.impl.SAMLMetadataSignatureSigningParametersResolver;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.SignatureSigningParametersResolver;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

public class OpenSamlLogoutResponseResolver implements Saml2LogoutResponseResolver {
	static {
		OpenSamlInitializationService.initialize();
	}

	private final LogoutResponseMarshaller marshaller;
	private final LogoutResponseBuilder logoutResponseBuilder;
	private final IssuerBuilder issuerBuilder;
	private final StatusBuilder statusBuilder;
	private final StatusCodeBuilder statusCodeBuilder;

	/**
	 * Creates an {@link OpenSamlLogoutResponseResolver}
	 */
	public OpenSamlLogoutResponseResolver() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.marshaller = (LogoutResponseMarshaller) registry.getMarshallerFactory()
				.getMarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
		this.logoutResponseBuilder = (LogoutResponseBuilder) registry.getBuilderFactory()
				.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
		this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		this.statusBuilder = (StatusBuilder) registry.getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
		this.statusCodeBuilder = (StatusCodeBuilder) registry.getBuilderFactory().getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
	}

	@Override
	public OpenSamlLogoutResponseSpec resolveLogoutResponse(HttpServletRequest request, RelyingPartyRegistration registration) {
		return new OpenSamlLogoutResponseSpec(registration)
				.destination(registration.getAssertingPartyDetails().getSingleLogoutServiceResponseLocation())
				.issuer(registration.getEntityId())
				.status(StatusCode.SUCCESS);
	}

	public class OpenSamlLogoutResponseSpec implements Saml2LogoutResponseSpec<OpenSamlLogoutResponseSpec> {
		LogoutResponse logoutResponse;
		RelyingPartyRegistration registration;

		public OpenSamlLogoutResponseSpec(RelyingPartyRegistration registration) {
			this.logoutResponse = logoutResponseBuilder.buildObject();
			this.logoutResponse.setID("LR" + UUID.randomUUID());
			this.registration = registration;
		}

		@Override
		public OpenSamlLogoutResponseSpec destination(String destination) {
			this.logoutResponse.setDestination(destination);
			return this;
		}

		@Override
		public OpenSamlLogoutResponseSpec issuer(String issuer) {
			Issuer iss = issuerBuilder.buildObject();
			iss.setValue(issuer);
			this.logoutResponse.setIssuer(iss);
			return this;
		}

		@Override
		public OpenSamlLogoutResponseSpec inResponseTo(String inResponseTo) {
			this.logoutResponse.setInResponseTo(inResponseTo);
			return this;
		}

		@Override
		public OpenSamlLogoutResponseSpec status(String status) {
			StatusCode code = statusCodeBuilder.buildObject();
			code.setValue(status);
			Status s = statusBuilder.buildObject();
			s.setStatusCode(code);
			this.logoutResponse.setStatus(s);
			return this;
		}

		public OpenSamlLogoutResponseSpec response(Consumer<LogoutResponse> response) {
			response.accept(this.logoutResponse);
			return this;
		}

		@Override
		public Saml2LogoutResponse resolve() {
			if (this.registration.getAssertingPartyDetails().getSingleLogoutServiceBinding() == Saml2MessageBinding.POST) {
				String xml = serialize(sign(this.logoutResponse, this.registration));
				return Saml2LogoutResponse.builder()
						.samlRequest(Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8))).build();
			} else {
				String xml = serialize(this.logoutResponse);
				Saml2LogoutResponse.Builder result = Saml2LogoutResponse.builder();
				String deflatedAndEncoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
				result.samlRequest(deflatedAndEncoded);
				Map<String, String> parameters = new LinkedHashMap<>();
				parameters.put("SAMLRequest", deflatedAndEncoded);
				sign(parameters, this.registration);
				return result.parameters((params) -> params.putAll(parameters)).build();
			}
		}
	}

	private LogoutResponse sign(LogoutResponse logoutResponse, RelyingPartyRegistration relyingPartyRegistration) {
		SignatureSigningParameters parameters = resolveSigningParameters(relyingPartyRegistration);
		return sign(logoutResponse, parameters);
	}

	private LogoutResponse sign(LogoutResponse logoutResponse, SignatureSigningParameters parameters) {
		try {
			SignatureSupport.signObject(logoutResponse, parameters);
			return logoutResponse;
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	private void sign(Map<String, String> components, RelyingPartyRegistration relyingPartyRegistration) {
		SignatureSigningParameters parameters = resolveSigningParameters(relyingPartyRegistration);
		sign(components, parameters);
	}

	private void sign(Map<String, String> components, SignatureSigningParameters parameters) {
		Credential credential = parameters.getSigningCredential();
		String algorithmUri = parameters.getSignatureAlgorithm();
		components.put("SigAlg", algorithmUri);
		UriComponentsBuilder builder = UriComponentsBuilder.newInstance();
		for (Map.Entry<String, String> component : components.entrySet()) {
			builder.queryParam(component.getKey(), UriUtils.encode(component.getValue(), StandardCharsets.ISO_8859_1));
		}
		String queryString = builder.build(true).toString().substring(1);
		try {
			byte[] rawSignature = XMLSigningUtil.signWithURI(credential, algorithmUri,
					queryString.getBytes(StandardCharsets.UTF_8));
			String b64Signature = Saml2Utils.samlEncode(rawSignature);
			components.put("Signature", b64Signature);
		}
		catch (SecurityException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private String serialize(LogoutResponse logoutResponse) {
		try {
			Element element = this.marshaller.marshall(logoutResponse);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private SignatureSigningParameters resolveSigningParameters(RelyingPartyRegistration relyingPartyRegistration) {
		List<Credential> credentials = resolveSigningCredentials(relyingPartyRegistration);
		List<String> algorithms = relyingPartyRegistration.getAssertingPartyDetails().getSigningAlgorithms();
		List<String> digests = Collections.singletonList(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		String canonicalization = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
		SignatureSigningParametersResolver resolver = new SAMLMetadataSignatureSigningParametersResolver();
		CriteriaSet criteria = new CriteriaSet();
		BasicSignatureSigningConfiguration signingConfiguration = new BasicSignatureSigningConfiguration();
		signingConfiguration.setSigningCredentials(credentials);
		signingConfiguration.setSignatureAlgorithms(algorithms);
		signingConfiguration.setSignatureReferenceDigestMethods(digests);
		signingConfiguration.setSignatureCanonicalizationAlgorithm(canonicalization);
		criteria.add(new SignatureSigningConfigurationCriterion(signingConfiguration));
		try {
			SignatureSigningParameters parameters = resolver.resolveSingle(criteria);
			Assert.notNull(parameters, "Failed to resolve any signing credential");
			return parameters;
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	private List<Credential> resolveSigningCredentials(RelyingPartyRegistration relyingPartyRegistration) {
		List<Credential> credentials = new ArrayList<>();
		for (Saml2X509Credential x509Credential : relyingPartyRegistration.getSigningX509Credentials()) {
			X509Certificate certificate = x509Credential.getCertificate();
			PrivateKey privateKey = x509Credential.getPrivateKey();
			BasicCredential credential = CredentialSupport.getSimpleCredential(certificate, privateKey);
			credential.setEntityId(relyingPartyRegistration.getEntityId());
			credential.setUsageType(UsageType.SIGNING);
			credentials.add(credential);
		}
		return credentials;
	}
}
