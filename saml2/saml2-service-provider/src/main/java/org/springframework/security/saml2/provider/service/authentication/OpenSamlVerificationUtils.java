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

package org.springframework.security.saml2.provider.service.authentication;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

/**
 * Utility methods for verifying SAML component signatures with OpenSAML
 *
 * For internal use only.
 *
 * @author Josh Cummings
 */

final class OpenSamlVerificationUtils {

	static SignatureTrustEngine trustEngine(RelyingPartyRegistration registration) {
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

	private OpenSamlVerificationUtils() {

	}

}
