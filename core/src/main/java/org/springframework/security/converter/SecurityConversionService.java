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

package org.springframework.security.converter;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.function.Function;

import org.jspecify.annotations.Nullable;

import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.util.function.ThrowingFunction;

/**
 * A {@link ConversionService} providing type conversion for security primitives
 *
 * @author Josh Cummings
 * @since 7.0
 * @see GenericConversionService
 */
public final class SecurityConversionService extends GenericConversionService {

	private static final SecurityConversionService sharedInstance = new SecurityConversionService();

	private SecurityConversionService() {
		addConverters(this);
	}

	/**
	 * Returns a shared instance of {@code ClaimConversionService}.
	 * @return a shared instance of {@code ClaimConversionService}
	 */
	public static SecurityConversionService getSharedInstance() {
		return sharedInstance;
	}

	/**
	 * Adds the converters that provide type conversion for claim values to the provided
	 * {@link ConverterRegistry}.
	 * @param converterRegistry the registry of converters to add to
	 */
	public static void addConverters(ConverterRegistry converterRegistry) {
		Converter<byte[], String> bytesToString = new ByteArrayToStringConverter();
		Converter<InputStream, X509Certificate> isToX509 = new InputStreamToX509CertificateConverter();
		Converter<String, X509Certificate> stringToX509 = new ResourceConverterAdapter<>(isToX509);
		Converter<byte[], X509Certificate> bytesToX509 = bytesToString.andThen(stringToX509);
		Converter<X509Certificate, byte[]> x509ToBytes = SecurityConversionService::encode;

		Converter<InputStream, RSAPublicKey> isToPublic = RsaKeyConverters.x509();
		Converter<String, RSAPublicKey> stringToPublic = new ResourceConverterAdapter<>(isToPublic);
		Converter<byte[], RSAPublicKey> bytesToPublic = bytesToString.andThen(stringToPublic);
		Converter<RSAPublicKey, byte[]> publicToBytes = SecurityConversionService::encode;

		Converter<InputStream, RSAPrivateKey> isToPrivate = RsaKeyConverters.pkcs8();
		Converter<String, RSAPrivateKey> stringToPrivate = new ResourceConverterAdapter<>(isToPrivate);
		Converter<byte[], RSAPrivateKey> bytesToPrivate = bytesToString.andThen(stringToPrivate);
		Converter<RSAPrivateKey, byte[]> privateToBytes = SecurityConversionService::encode;

		converterRegistry.addConverter(InputStream.class, X509Certificate.class, isToX509);
		converterRegistry.addConverter(String.class, X509Certificate.class, stringToX509);
		converterRegistry.addConverter(byte[].class, X509Certificate.class, bytesToX509);
		converterRegistry.addConverter(X509Certificate.class, byte[].class, x509ToBytes);
		converterRegistry.addConverter(InputStream.class, RSAPublicKey.class, isToPublic);
		converterRegistry.addConverter(String.class, RSAPublicKey.class, stringToPublic);
		converterRegistry.addConverter(byte[].class, RSAPublicKey.class, bytesToPublic);
		converterRegistry.addConverter(RSAPublicKey.class, byte[].class, publicToBytes);
		converterRegistry.addConverter(InputStream.class, RSAPrivateKey.class, isToPrivate);
		converterRegistry.addConverter(String.class, RSAPrivateKey.class, stringToPrivate);
		converterRegistry.addConverter(byte[].class, RSAPrivateKey.class, bytesToPrivate);
		converterRegistry.addConverter(RSAPrivateKey.class, byte[].class, privateToBytes);
	}

	private static byte[] encode(X509Certificate key) {
		Function<X509Certificate, byte[]> x509Encoded = ThrowingFunction.of(X509Certificate::getEncoded);
		String data = Base64.getEncoder().encodeToString(x509Encoded.apply(key));
		String cert = RsaKeyConverters.X509_CERT_HEADER + "\n" + data + "\n" + RsaKeyConverters.X509_CERT_FOOTER;
		return cert.getBytes(StandardCharsets.UTF_8);
	}

	private static byte[] encode(RSAPublicKey key) {
		String data = Base64.getEncoder().encodeToString(key.getEncoded());
		String pub = RsaKeyConverters.X509_PEM_HEADER + "\n" + data + "\n" + RsaKeyConverters.X509_PEM_FOOTER;
		return pub.getBytes(StandardCharsets.UTF_8);
	}

	private static byte[] encode(RSAPrivateKey key) {
		String data = Base64.getEncoder().encodeToString(key.getEncoded());
		String priv = RsaKeyConverters.PKCS8_PEM_HEADER + "\n" + data + "\n" + RsaKeyConverters.PKCS8_PEM_FOOTER;
		return priv.getBytes(StandardCharsets.UTF_8);
	}

	private static final class ByteArrayToStringConverter implements Converter<byte[], String> {

		@Override
		public @Nullable String convert(byte[] source) {
			if (source == null) {
				return null;
			}
			return new String(source, StandardCharsets.UTF_8);
		}

	}

}
