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

import org.junit.jupiter.api.Test;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialsConversionServiceTests {

	private final CredentialsConversionService converters = CredentialsConversionService.getInstance();

	@Test
	void roundTrip() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Saml2X509CredentialSource signing = new Saml2X509CredentialCollectionSource(
				registration.getSigningX509Credentials());
		byte[] bytes = this.converters.convert(signing, byte[].class);
		Saml2X509CredentialSource restored = this.converters.convert(bytes, Saml2X509CredentialSource.class);
		assertThat(signing.getCredentials()).hasSize(restored.getCredentials().size());
	}

}
