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

package org.springframework.security.saml2.provider.service.authentication;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.xml.namespace.QName;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.w3c.dom.Element;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest.Builder;
import org.springframework.util.Assert;
import org.springframework.web.util.UriUtils;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getBuilderFactory;
import static org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getMarshallerFactory;
import static org.springframework.security.saml2.provider.service.authentication.Saml2Utils.samlDeflate;
import static org.springframework.security.saml2.provider.service.authentication.Saml2Utils.samlEncode;
import static org.springframework.util.StringUtils.hasText;

/**
 * @since 5.2
 */
public class OpenSamlAuthenticationRequestFactory implements Saml2AuthenticationRequestFactory {
	private final XMLObjectBuilder<AuthnRequest> authnRequestBuilder;
	private final XMLObjectBuilder<Issuer> issuerBuilder;

	private Clock clock = Clock.systemUTC();
	private String protocolBinding = SAMLConstants.SAML2_POST_BINDING_URI;
	private Converter<Saml2AuthenticationRequestContext, AuthnRequest> authenticationRequestContextConverter =
			this::createAuthnRequest;

	public OpenSamlAuthenticationRequestFactory() {
		this.authnRequestBuilder = getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		this.issuerBuilder = getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
	}

	private <T extends XMLObject> XMLObjectBuilder<T> getBuilder(QName qName) {
		return (XMLObjectBuilder<T>) getBuilderFactory().getBuilder(qName);
	}

	@Override
	@Deprecated
	public String createAuthenticationRequest(Saml2AuthenticationRequest request) {
		AuthnRequest authnRequest = createAuthnRequest(request.getIssuer(),
				request.getDestination(), request.getAssertionConsumerServiceUrl());
		return serialize(authnRequest, request.getCredentials());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2PostAuthenticationRequest createPostAuthenticationRequest(Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = this.authenticationRequestContextConverter.convert(context);
		String xml = context.getRelyingPartyRegistration().getProviderDetails().isSignAuthNRequest() ?
			serialize(authnRequest, context.getRelyingPartyRegistration().getSigningCredentials()) :
			serialize(authnRequest);

		return Saml2PostAuthenticationRequest.withAuthenticationRequestContext(context)
				.samlRequest(samlEncode(xml.getBytes(UTF_8)))
				.build();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2RedirectAuthenticationRequest createRedirectAuthenticationRequest(Saml2AuthenticationRequestContext context) {
		AuthnRequest authnRequest = this.authenticationRequestContextConverter.convert(context);
		String xml = serialize(authnRequest);
		Builder result = Saml2RedirectAuthenticationRequest.withAuthenticationRequestContext(context);
		String deflatedAndEncoded = samlEncode(samlDeflate(xml));
		result.samlRequest(deflatedAndEncoded)
				.relayState(context.getRelayState());

		if (context.getRelyingPartyRegistration().getProviderDetails().isSignAuthNRequest()) {
			List<Saml2X509Credential> signingCredentials = context.getRelyingPartyRegistration().getSigningCredentials();
			Map<String, String> signedParams = signQueryParameters(
					signingCredentials,
					deflatedAndEncoded,
					context.getRelayState()
			);
			result.samlRequest(signedParams.get("SAMLRequest"))
					.relayState(signedParams.get("RelayState"))
					.sigAlg(signedParams.get("SigAlg"))
					.signature(signedParams.get("Signature"));
		}

		return result.build();
	}

	private AuthnRequest createAuthnRequest(Saml2AuthenticationRequestContext context) {
		return createAuthnRequest(context.getIssuer(),
				context.getDestination(), context.getAssertionConsumerServiceUrl());
	}

	private AuthnRequest createAuthnRequest(String issuer, String destination, String assertionConsumerServiceUrl) {
		AuthnRequest auth = this.authnRequestBuilder.buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
		auth.setID("ARQ" + UUID.randomUUID().toString().substring(1));
		auth.setIssueInstant(new DateTime(this.clock.millis()));
		auth.setForceAuthn(Boolean.FALSE);
		auth.setIsPassive(Boolean.FALSE);
		auth.setProtocolBinding(protocolBinding);
		Issuer iss = this.issuerBuilder.buildObject(Issuer.DEFAULT_ELEMENT_NAME);
		iss.setValue(issuer);
		auth.setIssuer(iss);
		auth.setDestination(destination);
		auth.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
		return auth;
	}

	String serialize(XMLObject xmlObject) {
		final MarshallerFactory marshallerFactory = getMarshallerFactory();
		try {
			Element element = marshallerFactory.getMarshaller(xmlObject).marshall(xmlObject);
			return SerializeSupport.nodeToString(element);
		} catch (MarshallingException e) {
			throw new Saml2Exception(e);
		}
	}

	String serialize(AuthnRequest authnRequest, List<Saml2X509Credential> signingCredentials) {
		if (hasSigningCredential(signingCredentials) != null) {
			signAuthnRequest(authnRequest, signingCredentials);
		}
		return serialize(authnRequest);
	}

	/**
	 * Returns query parameter after creating a Query String signature
	 * All return values are unencoded and will need to be encoded prior to sending
	 * The methods {@link UriUtils#encode(String, Charset)} and {@link UriUtils#decode(String, Charset)}
	 * with the {@link StandardCharsets#ISO_8859_1} character set are used for all URL encoding/decoding.
	 * @param signingCredentials - credentials to be used for signature
	 * @return a map of unencoded query parameters with the following keys:
	 * {@code {SAMLRequest, RelayState (may be null)}, SigAlg, Signature}
	 *
	 */
	Map<String, String> signQueryParameters(
			List<Saml2X509Credential> signingCredentials,
			String samlRequest,
			String relayState) {
		Assert.notNull(samlRequest, "samlRequest cannot be null");
		String algorithmUri = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
		StringBuilder queryString = new StringBuilder();
		queryString
				.append("SAMLRequest")
				.append("=")
				.append(UriUtils.encode(samlRequest, StandardCharsets.ISO_8859_1))
				.append("&");
		if (hasText(relayState)) {
			queryString
					.append("RelayState")
					.append("=")
					.append(UriUtils.encode(relayState, StandardCharsets.ISO_8859_1))
					.append("&");
		}
		queryString
				.append("SigAlg")
				.append("=")
				.append(UriUtils.encode(algorithmUri, StandardCharsets.ISO_8859_1));

		try {
			byte[] rawSignature = XMLSigningUtil.signWithURI(
					getSigningCredential(signingCredentials, ""),
					algorithmUri,
					queryString.toString().getBytes(StandardCharsets.UTF_8)
			);
			String b64Signature = Saml2Utils.samlEncode(rawSignature);

			Map<String, String> result = new LinkedHashMap<>();
			result.put("SAMLRequest", samlRequest);
			if (hasText(relayState)) {
				result.put("RelayState", relayState);
			}
			result.put("SigAlg", algorithmUri);
			result.put("Signature", b64Signature);
			return result;
		}
		catch (SecurityException e) {
			throw new Saml2Exception(e);
		}
	}

	private void signAuthnRequest(AuthnRequest authnRequest, List<Saml2X509Credential> signingCredentials) {
		SignatureSigningParameters parameters = new SignatureSigningParameters();
		Credential credential = getSigningCredential(signingCredentials, authnRequest.getIssuer().getValue());
		parameters.setSigningCredential(credential);
		parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		try {
			SignatureSupport.signObject(authnRequest, parameters);
		} catch (MarshallingException | SignatureException | SecurityException e) {
			throw new Saml2Exception(e);
		}

	}

	private Saml2X509Credential hasSigningCredential(List<Saml2X509Credential> credentials) {
		for (Saml2X509Credential c : credentials) {
			if (c.isSigningCredential()) {
				return c;
			}
		}
		return null;
	}

	private Credential getSigningCredential(List<Saml2X509Credential> signingCredential,
			String localSpEntityId
	) {
		Saml2X509Credential credential = hasSigningCredential(signingCredential);
		if (credential == null) {
			throw new Saml2Exception("no signing credential configured");
		}
		BasicCredential cred = getBasicCredential(credential);
		cred.setEntityId(localSpEntityId);
		cred.setUsageType(UsageType.SIGNING);
		return cred;
	}

	private BasicX509Credential getBasicCredential(Saml2X509Credential credential) {
		return CredentialSupport.getSimpleCredential(
				credential.getCertificate(),
				credential.getPrivateKey()
		);
	}

	/**
	 * '
	 * Use this {@link Clock} with {@link Instant#now()} for generating
	 * timestamps
	 *
	 * @param clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	/**
	 * Sets the {@code protocolBinding} to use when generating authentication requests.
	 * Acceptable values are {@link SAMLConstants#SAML2_POST_BINDING_URI} and
	 * {@link SAMLConstants#SAML2_REDIRECT_BINDING_URI}
	 * The IDP will be reading this value in the {@code AuthNRequest} to determine how to
	 * send the Response/Assertion to the ACS URL, assertion consumer service URL.
	 *
	 * @param protocolBinding either {@link SAMLConstants#SAML2_POST_BINDING_URI} or
	 * {@link SAMLConstants#SAML2_REDIRECT_BINDING_URI}
	 * @throws IllegalArgumentException if the protocolBinding is not valid
	 */
	public void setProtocolBinding(String protocolBinding) {
		boolean isAllowedBinding = SAMLConstants.SAML2_POST_BINDING_URI.equals(protocolBinding) ||
				SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(protocolBinding);
		if (!isAllowedBinding) {
			throw new IllegalArgumentException("Invalid protocol binding: " + protocolBinding);
		}
		this.protocolBinding = protocolBinding;
	}

	public void setAuthenticationRequestContextConverter
			(Converter<Saml2AuthenticationRequestContext, AuthnRequest> authenticationRequestContextConverter) {
		this.authenticationRequestContextConverter = authenticationRequestContextConverter;
	}
}
