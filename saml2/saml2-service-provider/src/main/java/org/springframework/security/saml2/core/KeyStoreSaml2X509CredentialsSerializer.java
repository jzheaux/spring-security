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

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PKCS12Attribute;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.jspecify.annotations.Nullable;

import org.springframework.core.convert.converter.Converter;
import org.springframework.util.function.ThrowingFunction;

/**
 * A serialization strategy for SAML 2.0 Credentials that writes them to an in-memory
 * PCKS#12 {@link KeyStore}. This is handy since {@link KeyStore} will encrypt private
 * keys, simplifying persisting them.
 *
 * @author Josh Cummings
 * @since 7.0
 */
public final class KeyStoreSaml2X509CredentialsSerializer
		implements Converter<Collection<Saml2X509Credential>, byte[]> {

	private static final String KEY_USAGE_OID = "2.5.29.15";

	private final char[] password;

	public KeyStoreSaml2X509CredentialsSerializer(char[] password) {
		this.password = password;
	}

	@Override
	public byte @Nullable [] convert(Collection<Saml2X509Credential> source) {
		if (source == null) {
			return null;
		}
		ThrowingFunction<Collection<Saml2X509Credential>, byte[]> function = (credentials) -> {
			KeyStore keys = KeyStore.getInstance("PKCS12");
			keys.load(null);
			for (Saml2X509Credential credential : credentials) {
				String alias = UUID.randomUUID().toString();
				keys.setEntry(alias, convert(credential), new KeyStore.PasswordProtection(this.password));
			}
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			keys.store(outputStream, this.password);
			return outputStream.toByteArray();
		};
		return function.apply(source);
	}

	KeyStore.Entry convert(Saml2X509Credential source) {
		X509Certificate certificate = source.getCertificate();
		PrivateKey privateKey = source.getPrivateKey();
		Set<KeyStore.Entry.Attribute> attributes = new HashSet<>();
		for (Saml2X509Credential.Saml2X509CredentialType type : source.getCredentialTypes()) {
			attributes.add(new PKCS12Attribute(KEY_USAGE_OID, type.name()));
		}
		// @formatter:off
		return (privateKey != null) ?
				new KeyStore.PrivateKeyEntry(privateKey, new Certificate[] { certificate }, attributes) :
				new KeyStore.TrustedCertificateEntry(certificate, attributes);
		// @formatter:on
	}

}
