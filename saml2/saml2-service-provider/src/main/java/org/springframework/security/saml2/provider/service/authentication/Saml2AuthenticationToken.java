/*
 * Copyright 2002-2019 the original author or authors.
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

import java.util.Collections;
import java.util.List;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;

/**
 * Represents an incoming SAML 2.0 response containing an assertion that has not been validated.
 * {@link Saml2AuthenticationToken#isAuthenticated()} will always return false.
 * @since 5.2
 */
public class Saml2AuthenticationToken extends AbstractAuthenticationToken {

	private final RelyingPartyRegistration relyingPartyRegistration;
	private final String saml2Response;

	/**
	 * Construct a {@link Saml2AuthenticationToken} with the provided parameters
	 *
	 * <p>
	 * Note that the {@link RelyingPartyRegistration} should have any placeholders resolved to be included
	 * in this token. This can be achieved with {@link RelyingPartyRegistration#withRelyingPartyRegistration}:
	 *
	 * <pre>
	 * 	RelyingPartyRegistration resolved = withRelyingPartyRegistration(unresolved)
	 * 			.entityId(...)
	 * 			.assertionConsumerServiceLocation(...)
	 * 			.build();
	 * 	Saml2AuthenticationToken token = new Saml2AuthenticationToken(resolved, saml2Response);
	 * </pre>
	 *
	 * @param relyingPartyRegistration The {@link RelyingPartyRegistration} associated with this token
	 * @param saml2Response The serialized SAML 2.0 Response associated with this token
	 * @since 5.4
	 */
	public Saml2AuthenticationToken(RelyingPartyRegistration relyingPartyRegistration, String saml2Response) {
		super(Collections.emptyList());
		Assert.isTrue(isResolved(relyingPartyRegistration.getAssertionConsumerServiceLocation()),
				"relyingPartyRegistration must have its placeholders resolved for inclusion in this token");
		Assert.isTrue(isResolved(relyingPartyRegistration.getEntityId()),
				"relyingPartyRegistration must have its placeholders resolved for inclusion in this token");
		this.relyingPartyRegistration = relyingPartyRegistration;
		this.saml2Response = saml2Response;
	}

	private static boolean isResolved(String template) {
		if (template.contains("{registrationId}")) {
			return false;
		}
		if (template.contains("{baseUrl}")) {
			return false;
		}
		if (template.contains("{baseScheme}")) {
			return false;
		}
		if (template.contains("{baseHost}")) {
			return false;
		}
		if (template.contains("{basePort}")) {
			return false;
		}
		return true;
	}

	/**
	 * Creates an authentication token from an incoming SAML 2 Response object
	 * @param saml2Response inflated and decoded XML representation of the SAML 2 Response
	 * @param recipientUri the URL that the SAML 2 Response was received at. Used for validation
	 * @param idpEntityId the entity ID of the asserting entity
	 * @param localSpEntityId the configured local SP, the relying party, entity ID
	 * @param credentials the credentials configured for signature verification and decryption
	 * @deprecated Use {@link Saml2AuthenticationToken(RelyingPartyRegistration, String)} instead
	 */
	@Deprecated
	public Saml2AuthenticationToken(String saml2Response,
									String recipientUri,
									String idpEntityId,
									String localSpEntityId,
									List<Saml2X509Credential> credentials) {
		this(RelyingPartyRegistration.withRegistrationId(localSpEntityId)
				.entityId(localSpEntityId)
				.credentials(c -> c.addAll(credentials))
				.assertionConsumerServiceLocation(recipientUri)
				.providerDetails(ap -> ap.entityId(idpEntityId))
				.build(),
			saml2Response);
	}

	/**
	 * Get the {@link RelyingPartyRegistration} associated with this authentication token
	 *
	 * @return the {@link RelyingPartyRegistration} associated with this authentication token
	 * @since 5.4
	 */
	public RelyingPartyRegistration getRelyingPartyRegistration() {
		return this.relyingPartyRegistration;
	}

	/**
	 * Returns the decoded and inflated SAML 2.0 Response XML object as a string
	 * @return decoded and inflated XML data as a {@link String}
	 */
	@Override
	public Object getCredentials() {
		return getSaml2Response();
	}

	/**
	 * Always returns null.
	 * @return null
	 */
	@Override
	public Object getPrincipal() {
		return null;
	}

	/**
	 * Returns inflated and decoded XML representation of the SAML 2 Response
	 * @return inflated and decoded XML representation of the SAML 2 Response
	 */
	public String getSaml2Response() {
		return this.saml2Response;
	}

	/**
	 * Returns the URI that the SAML 2 Response object came in on
	 * @return URI as a string
	 * @deprecated Use {@link #getRelyingPartyRegistration().getAssertionConsumerServiceUrlTemplate()} instead
	 */
	@Deprecated
	public String getRecipientUri() {
		return this.relyingPartyRegistration.getAssertionConsumerServiceLocation();
	}

	/**
	 * Returns the configured entity ID of the receiving relying party, SP
	 * @return an entityID for the configured local relying party
	 * @deprecated Use {@link #getRelyingPartyRegistration().getEntityId()} instead
	 */
	@Deprecated
	public String getLocalSpEntityId() {
		return this.relyingPartyRegistration.getEntityId();
	}

	/**
	 * Returns all the credentials associated with the relying party configuraiton
	 * @return
	 * @deprecated Use {@link #getRelyingPartyRegistration()} instead
	 */
	@Deprecated
	public List<Saml2X509Credential> getX509Credentials() {
		return this.relyingPartyRegistration.getCredentials();
	}

	/**
	 * @return false
	 */
	@Override
	public boolean isAuthenticated() {
		return false;
	}

	/**
	 * The state of this object cannot be changed. Will always throw an exception
	 * @param authenticated ignored
	 * @throws {@link IllegalArgumentException}
	 */
	@Override
	public void setAuthenticated(boolean authenticated) {
		throw new IllegalArgumentException();
	}

	/**
	 * Returns the configured IDP, asserting party, entity ID
	 * @return a string representing the entity ID
	 * @deprecated Use {@link #getRelyingPartyRegistration().getProviderDetails.getEntityId()} instead
	 */
	@Deprecated
	public String getIdpEntityId() {
		return this.relyingPartyRegistration.getProviderDetails().getEntityId();
	}
}
