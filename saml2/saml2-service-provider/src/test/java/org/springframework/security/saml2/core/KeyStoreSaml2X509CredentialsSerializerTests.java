/*
 * Copyright 2002-2025 the original author or authors.
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

import java.util.Collection;

import org.junit.jupiter.api.Test;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;

class KeyStoreSaml2X509CredentialsSerializerTests {

	char[] password = "password".toCharArray();

	KeyStoreSaml2X509CredentialsSerializer serializer = new KeyStoreSaml2X509CredentialsSerializer(this.password);

	KeyStoreSaml2X509CredentialsDeserializer deserializer = new KeyStoreSaml2X509CredentialsDeserializer(this.password);

	@Test
	void roundTrip() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Collection<Saml2X509Credential> signing = registration.getSigningX509Credentials();
		byte[] bytes = this.serializer.convert(signing);
		Collection<Saml2X509Credential> restored = this.deserializer.convert(bytes);
		assertThat(signing).hasSize(restored.size());
	}

}
