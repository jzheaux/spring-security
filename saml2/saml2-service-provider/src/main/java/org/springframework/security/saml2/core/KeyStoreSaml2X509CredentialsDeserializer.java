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

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import org.jspecify.annotations.Nullable;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.function.ThrowingFunction;

/**
 * A deserialization strategy for SAML 2.0 Credentials that reads them from an in-memory
 * PCKS#12 {@link KeyStore}. This decrypts private keys previously encrypted by
 * {@link KeyStore}.
 *
 * @author Josh Cummings
 * @since 7.0
 */
public final class KeyStoreSaml2X509CredentialsDeserializer
		implements Converter<byte[], Collection<Saml2X509Credential>> {

	private static final String KEY_USAGE_OID = "2.5.29.15";

	private final char[] password;

	public KeyStoreSaml2X509CredentialsDeserializer(char[] password) {
		this.password = password;
	}

	@Override
	public @Nullable Collection<Saml2X509Credential> convert(byte[] source) {
		if (source == null) {
			return null;
		}
		ThrowingFunction<byte[], Collection<Saml2X509Credential>> function = (bytes) -> {
			KeyStore keys = KeyStore.getInstance("PKCS12");
			keys.load(new ByteArrayInputStream(bytes), this.password);
			Enumeration<String> aliaes = keys.aliases();
			Collection<Saml2X509Credential> credentials = new HashSet<>();
			while (aliaes.hasMoreElements()) {
				String alias = aliaes.nextElement();
				KeyStore.PasswordProtection password = new KeyStore.PasswordProtection(this.password);
				KeyStore.Entry entry = keys.getEntry(alias, password);
				Saml2X509Credential credential = convert(entry);
				credentials.add(credential);
			}
			return credentials;
		};
		return function.apply(source);
	}

	private Saml2X509Credential convert(KeyStore.Entry source) {
		Set<Saml2X509Credential.Saml2X509CredentialType> types = new HashSet<>();
		for (KeyStore.Entry.Attribute attribute : source.getAttributes()) {
			if (attribute.getName().equals(KEY_USAGE_OID)) {
				types.add(Saml2X509Credential.Saml2X509CredentialType.valueOf(attribute.getValue()));
			}
		}
		if (source instanceof KeyStore.TrustedCertificateEntry entry) {
			return new Saml2X509Credential(null, (X509Certificate) entry.getTrustedCertificate(), types);
		}
		if (source instanceof KeyStore.PrivateKeyEntry entry) {
			return new Saml2X509Credential(entry.getPrivateKey(), (X509Certificate) entry.getCertificate(), types);
		}
		return null;
	}

}
