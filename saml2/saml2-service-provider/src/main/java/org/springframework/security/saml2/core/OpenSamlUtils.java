/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.saml2.core;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.metadata.criteria.role.impl.EvaluableProtocolRoleDescriptorCriterion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.security.impl.SAMLMetadataSignatureSigningParametersResolver;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.criteria.impl.EvaluableEntityIDCredentialCriterion;
import org.opensaml.security.credential.criteria.impl.EvaluableUsageCredentialCriterion;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.SignatureSigningParametersResolver;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

public final class OpenSamlUtils {

	private static final boolean useNewPackages = !ClassUtils
		.isPresent("net.shibboleth.utilities.java.support.xml.BasicParserPool", null)
			|| (!"4".equals(System.getProperty("spring.security.saml2.opensaml.version", "4"))
					&& ClassUtils.isPresent("net.shibboleth.shared.xml.impl.BasicParserPool", null));

	public static boolean useNewPackages() {
		return useNewPackages;
	}

	public static SerializationConfigurer serialize(XMLObject object) {
		Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
		try {
			return serialize(marshaller.marshall(object));
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

	public static SerializationConfigurer serialize(Element element) {
		return useNewPackages ? new OpenSaml5SerializationConfigurer(element)
				: new OpenSaml4SerializationConfigurer(element);
	}

	public static SignatureConfigurer sign(RelyingPartyRegistration registration) {
		return useNewPackages ? new OpenSaml5SignatureConfigurer(registration)
				: new OpenSaml4SignatureConfigurer(registration);
	}

	public static VerificationConfigurer verify(RequestAbstractType object, RelyingPartyRegistration registration) {
		return useNewPackages ? new OpenSaml5VerificationConfigurer(object, registration)
				: new OpenSaml4VerificationConfigurer(object, registration);
	}

	public static VerificationConfigurer verify(StatusResponseType object, RelyingPartyRegistration registration) {
		return useNewPackages ? new OpenSaml5VerificationConfigurer(object, registration)
				: new OpenSaml4VerificationConfigurer(object, registration);
	}

	private static <T> T cast(Object object) {
		return (T) object;
	}

	private OpenSamlUtils() {

	}

	public abstract static class SerializationConfigurer {

		Element element;

		boolean pretty;

		SerializationConfigurer(Element element) {
			this.element = element;
		}

		public SerializationConfigurer prettyPrint(boolean pretty) {
			this.pretty = pretty;
			return this;
		}

		public String serialize() {
			return doSerialize(this.element, this.pretty);
		}

		abstract String doSerialize(Element element, boolean pretty);

	}

	private static class OpenSaml4SerializationConfigurer extends SerializationConfigurer {

		OpenSaml4SerializationConfigurer(Element element) {
			super(element);
		}

		@Override
		String doSerialize(Element element, boolean pretty) {
			if (pretty) {
				return net.shibboleth.utilities.java.support.xml.SerializeSupport.prettyPrintXML(element);
			}
			return net.shibboleth.utilities.java.support.xml.SerializeSupport.nodeToString(element);
		}

	}

	private static class OpenSaml5SerializationConfigurer extends SerializationConfigurer {

		OpenSaml5SerializationConfigurer(Element element) {
			super(element);
		}

		@Override
		String doSerialize(Element element, boolean pretty) {
			if (pretty) {
				return SerializeSupport.prettyPrintXML(element);
			}
			return SerializeSupport.nodeToString(element);
		}

	}

	public abstract static class SignatureConfigurer {

		final RelyingPartyRegistration registration;

		final Map<String, String> components = new LinkedHashMap<>();

		SignatureConfigurer(RelyingPartyRegistration registration) {
			this.registration = registration;
		}

		public <O extends SignableXMLObject> O post(O object) {
			SignatureSigningParameters parameters = resolveSigningParameters(this.registration);
			try {
				SignatureSupport.signObject(object, parameters);
			}
			catch (Exception ex) {
				throw new Saml2Exception(ex);
			}
			return object;
		}

		public Map<String, String> redirect(Consumer<Map<String, String>> params) {
			SignatureSigningParameters parameters = resolveSigningParameters(this.registration);
			params.accept(this.components);
			Credential credential = parameters.getSigningCredential();
			String algorithmUri = parameters.getSignatureAlgorithm();
			this.components.put(Saml2ParameterNames.SIG_ALG, algorithmUri);
			UriComponentsBuilder builder = UriComponentsBuilder.newInstance();
			for (Map.Entry<String, String> component : this.components.entrySet()) {
				builder.queryParam(component.getKey(),
						UriUtils.encode(component.getValue(), StandardCharsets.ISO_8859_1));
			}
			String queryString = builder.build(true).toString().substring(1);
			try {
				byte[] rawSignature = XMLSigningUtil.signWithURI(credential, algorithmUri,
						queryString.getBytes(StandardCharsets.UTF_8));
				String b64Signature = Saml2Utils.samlEncode(rawSignature);
				this.components.put(Saml2ParameterNames.SIGNATURE, b64Signature);
			}
			catch (SecurityException ex) {
				throw new Saml2Exception(ex);
			}
			return this.components;
		}

		private SignatureSigningParameters resolveSigningParameters(RelyingPartyRegistration relyingPartyRegistration) {
			List<Credential> credentials = resolveSigningCredentials(relyingPartyRegistration);
			List<String> algorithms = relyingPartyRegistration.getAssertingPartyDetails().getSigningAlgorithms();
			List<String> digests = Collections.singletonList(SignatureConstants.ALGO_ID_DIGEST_SHA256);
			String canonicalization = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
			SignatureSigningParametersResolver resolver = new SAMLMetadataSignatureSigningParametersResolver();
			BasicSignatureSigningConfiguration signingConfiguration = new BasicSignatureSigningConfiguration();
			signingConfiguration.setSigningCredentials(credentials);
			signingConfiguration.setSignatureAlgorithms(algorithms);
			signingConfiguration.setSignatureReferenceDigestMethods(digests);
			signingConfiguration.setSignatureCanonicalizationAlgorithm(canonicalization);
			signingConfiguration.setKeyInfoGeneratorManager(buildSignatureKeyInfoGeneratorManager());
			Object criteria = criteria(new SignatureSigningConfigurationCriterion(signingConfiguration));
			try {
				SignatureSigningParameters parameters = resolver.resolveSingle(cast(criteria));
				Assert.notNull(parameters, "Failed to resolve any signing credential");
				return parameters;
			}
			catch (Exception ex) {
				throw new Saml2Exception(ex);
			}
		}

		private NamedKeyInfoGeneratorManager buildSignatureKeyInfoGeneratorManager() {
			final NamedKeyInfoGeneratorManager namedManager = new NamedKeyInfoGeneratorManager();

			namedManager.setUseDefaultManager(true);
			final KeyInfoGeneratorManager defaultManager = namedManager.getDefaultManager();

			// Generator for X509Credentials
			final X509KeyInfoGeneratorFactory x509Factory = new X509KeyInfoGeneratorFactory();
			x509Factory.setEmitEntityCertificate(true);
			x509Factory.setEmitEntityCertificateChain(true);

			defaultManager.registerFactory(x509Factory);

			return namedManager;
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

		abstract Object criteria(SignatureSigningConfigurationCriterion criterion);

	}

	private static class OpenSaml4SignatureConfigurer extends SignatureConfigurer {

		OpenSaml4SignatureConfigurer(RelyingPartyRegistration registration) {
			super(registration);
		}

		@Override
		Object criteria(SignatureSigningConfigurationCriterion criterion) {
			return new net.shibboleth.utilities.java.support.resolver.CriteriaSet(criterion);
		}

	}

	private static class OpenSaml5SignatureConfigurer extends SignatureConfigurer {

		OpenSaml5SignatureConfigurer(RelyingPartyRegistration registration) {
			super(registration);
		}

		@Override
		Object criteria(SignatureSigningConfigurationCriterion criterion) {
			return new CriteriaSet(cast(criterion));
		}

	}

	public abstract static class VerificationConfigurer {

		private final String id;

		private final Object criteria;

		private final SignatureTrustEngine trustEngine;

		VerificationConfigurer(StatusResponseType object, RelyingPartyRegistration registration) {
			this.id = object.getID();
			this.criteria = verificationCriteria(object.getIssuer());
			this.trustEngine = trustEngine(registration);
		}

		VerificationConfigurer(RequestAbstractType object, RelyingPartyRegistration registration) {
			this.id = object.getID();
			this.criteria = verificationCriteria(object.getIssuer());
			this.trustEngine = trustEngine(registration);
		}

		public Collection<Saml2Error> redirect(Saml2LogoutRequest request) {
			return redirect(new RedirectSignature(request));
		}

		public Collection<Saml2Error> redirect(Saml2LogoutResponse response) {
			return redirect(new RedirectSignature(response));
		}

		private Collection<Saml2Error> redirect(RedirectSignature signature) {
			if (signature.getAlgorithm() == null) {
				return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Missing signature algorithm for object [" + this.id + "]"));
			}
			if (!signature.hasSignature()) {
				return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Missing signature for object [" + this.id + "]"));
			}
			Collection<Saml2Error> errors = new ArrayList<>();
			String algorithmUri = signature.getAlgorithm();
			try {
				if (!this.trustEngine.validate(signature.getSignature(), signature.getContent(), algorithmUri,
						cast(this.criteria), null)) {
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
							"Invalid signature for object [" + this.id + "]"));
				}
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for object [" + this.id + "]: "));
			}
			return errors;
		}

		public Collection<Saml2Error> post(Signature signature) {
			Collection<Saml2Error> errors = new ArrayList<>();
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			try {
				profileValidator.validate(signature);
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for object [" + this.id + "]: "));
			}

			try {
				if (!this.trustEngine.validate(signature, cast(this.criteria))) {
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
							"Invalid signature for object [" + this.id + "]"));
				}
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for object [" + this.id + "]: "));
			}

			return errors;
		}

		private Object verificationCriteria(Issuer issuer) {
			return criteria(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer.getValue())),
					new EvaluableProtocolRoleDescriptorCriterion(new ProtocolCriterion(SAMLConstants.SAML20P_NS)),
					new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
		}

		private static SignatureTrustEngine trustEngine(RelyingPartyRegistration registration) {
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

		abstract Object criteria(EvaluableEntityIDCredentialCriterion entityId,
				EvaluableProtocolRoleDescriptorCriterion protocolRole, EvaluableUsageCredentialCriterion usage);

		private static class RedirectSignature {

			private final String algorithm;

			private final byte[] signature;

			private final byte[] content;

			RedirectSignature(Saml2LogoutRequest request) {
				this.algorithm = request.getParameter(Saml2ParameterNames.SIG_ALG);
				if (request.getParameter(Saml2ParameterNames.SIGNATURE) != null) {
					this.signature = Saml2Utils.samlDecode(request.getParameter(Saml2ParameterNames.SIGNATURE));
				}
				else {
					this.signature = null;
				}
				Map<String, String> queryParams = UriComponentsBuilder.newInstance()
					.query(request.getParametersQuery())
					.build(true)
					.getQueryParams()
					.toSingleValueMap();
				this.content = getContent(Saml2ParameterNames.SAML_REQUEST, request.getRelayState(), queryParams);
			}

			RedirectSignature(Saml2LogoutResponse response) {
				this.algorithm = response.getParameter(Saml2ParameterNames.SIG_ALG);
				if (response.getParameter(Saml2ParameterNames.SIGNATURE) != null) {
					this.signature = Saml2Utils.samlDecode(response.getParameter(Saml2ParameterNames.SIGNATURE));
				}
				else {
					this.signature = null;
				}
				Map<String, String> queryParams = UriComponentsBuilder.newInstance()
					.query(response.getParametersQuery())
					.build(true)
					.getQueryParams()
					.toSingleValueMap();
				this.content = getContent(Saml2ParameterNames.SAML_RESPONSE, response.getRelayState(), queryParams);
			}

			static byte[] getContent(String samlObject, String relayState, final Map<String, String> queryParams) {
				if (Objects.nonNull(relayState)) {
					return String
						.format("%s=%s&%s=%s&%s=%s", samlObject, queryParams.get(samlObject),
								Saml2ParameterNames.RELAY_STATE, queryParams.get(Saml2ParameterNames.RELAY_STATE),
								Saml2ParameterNames.SIG_ALG, queryParams.get(Saml2ParameterNames.SIG_ALG))
						.getBytes(StandardCharsets.UTF_8);
				}
				else {
					return String
						.format("%s=%s&%s=%s", samlObject, queryParams.get(samlObject), Saml2ParameterNames.SIG_ALG,
								queryParams.get(Saml2ParameterNames.SIG_ALG))
						.getBytes(StandardCharsets.UTF_8);
				}
			}

			byte[] getContent() {
				return this.content;
			}

			String getAlgorithm() {
				return this.algorithm;
			}

			byte[] getSignature() {
				return this.signature;
			}

			boolean hasSignature() {
				return this.signature != null;
			}

		}

	}

	private static class OpenSaml5VerificationConfigurer extends VerificationConfigurer {

		OpenSaml5VerificationConfigurer(StatusResponseType object, RelyingPartyRegistration registration) {
			super(object, registration);
		}

		OpenSaml5VerificationConfigurer(RequestAbstractType object, RelyingPartyRegistration registration) {
			super(object, registration);
		}

		@Override
		Object criteria(EvaluableEntityIDCredentialCriterion entityId,
				EvaluableProtocolRoleDescriptorCriterion protocolRole, EvaluableUsageCredentialCriterion usage) {
			return new CriteriaSet(cast(entityId), cast(protocolRole), cast(usage));
		}

	}

	private static class OpenSaml4VerificationConfigurer extends VerificationConfigurer {

		OpenSaml4VerificationConfigurer(StatusResponseType object, RelyingPartyRegistration registration) {
			super(object, registration);
		}

		OpenSaml4VerificationConfigurer(RequestAbstractType object, RelyingPartyRegistration registration) {
			super(object, registration);
		}

		@Override
		Object criteria(EvaluableEntityIDCredentialCriterion entityId,
				EvaluableProtocolRoleDescriptorCriterion protocolRole, EvaluableUsageCredentialCriterion usage) {
			return new net.shibboleth.utilities.java.support.resolver.CriteriaSet(entityId, protocolRole, usage);
		}

	}

}
