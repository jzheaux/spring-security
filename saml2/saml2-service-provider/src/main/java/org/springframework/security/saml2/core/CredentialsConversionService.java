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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.PKCS12Attribute;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.jspecify.annotations.Nullable;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.util.function.ThrowingFunction;

public final class CredentialsConversionService extends GenericConversionService {

	private static final CredentialsConversionService INSTANCE = new CredentialsConversionService();

	private CredentialsConversionService() {
		addDefaultConverters(this);
	}

	public static CredentialsConversionService getInstance() {
		return INSTANCE;
	}

	public static void addDefaultConverters(ConverterRegistry registry) {
		registry.addConverter(new CredentialsToKeyStoreConverter());
		registry.addConverter(new KeyStoreToCredentialsConverter());
	}

	private static final class CredentialsToKeyStoreConverter implements Converter<Saml2X509CredentialSource, byte[]> {

		private final Saml2X509CredentialToKeyStoreEntryConverter converter = new Saml2X509CredentialToKeyStoreEntryConverter();

		@Override
		public byte @Nullable [] convert(Saml2X509CredentialSource source) {
			ThrowingFunction<Saml2X509CredentialSource, byte[]> function = (credentials) -> {
				KeyStore keys = KeyStore.getInstance("PKCS12");
				keys.load(null);
				for (Saml2X509Credential credential : credentials.getCredentials()) {
					String alias = UUID.randomUUID().toString();
					keys.setEntry(alias, this.converter.convert(credential),
							new KeyStore.PasswordProtection("placeholder".toCharArray()));
				}
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
				keys.store(outputStream, "placeholder".toCharArray());
				return outputStream.toByteArray();
			};
			return function.apply(source);
		}

	}

	private static final class KeyStoreToCredentialsConverter implements Converter<byte[], Saml2X509CredentialSource> {

		private final KeyStoreEntryToSaml2X509CredentialConverter converter = new KeyStoreEntryToSaml2X509CredentialConverter();

		@Override
		public @Nullable Saml2X509CredentialSource convert(byte[] source) {
			ThrowingFunction<byte[], Saml2X509CredentialSource> function = (bytes) -> {
				KeyStore keys = KeyStore.getInstance("PKCS12");
				keys.load(new ByteArrayInputStream(bytes), "placeholder".toCharArray());
				Enumeration<String> aliaes = keys.aliases();
				Collection<Saml2X509Credential> credentials = new HashSet<>();
				while (aliaes.hasMoreElements()) {
					String alias = aliaes.nextElement();
					Saml2X509Credential credential = this.converter
						.convert(keys.getEntry(alias, new KeyStore.PasswordProtection("placeholder".toCharArray())));
					credentials.add(credential);
				}
				return new Saml2X509CredentialCollectionSource(credentials);
			};
			return function.apply(source);
		}

	}

	private static final class Saml2X509CredentialToKeyStoreEntryConverter
			implements Converter<Saml2X509Credential, KeyStore.Entry> {

		@Override
		public KeyStore.Entry convert(Saml2X509Credential source) {
			X509Certificate certificate = source.getCertificate();
			PrivateKey privateKey = source.getPrivateKey();
			Set<KeyStore.Entry.Attribute> attributes = new HashSet<>();
			attributes.add(new PKCS12Attribute("2.5.29.15", source.getCredentialTypes().iterator().next().name()));
			if (privateKey == null) {
				return new KeyStore.TrustedCertificateEntry(certificate, attributes);
			}
			return new KeyStore.PrivateKeyEntry(privateKey, new Certificate[] { certificate }, attributes);
		}

	}

	private static final class KeyStoreEntryToSaml2X509CredentialConverter
			implements Converter<KeyStore.Entry, Saml2X509Credential> {

		@Override
		public Saml2X509Credential convert(KeyStore.Entry source) {
			Set<Saml2X509Credential.Saml2X509CredentialType> types = new HashSet<>();
			for (KeyStore.Entry.Attribute attribute : source.getAttributes()) {
				if (attribute.getName().equals("2.5.29.15")) {
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

}
