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

package org.springframework.security.converter;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;

import org.springframework.core.convert.ConversionFailedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link RsaKeyConverters}
 */
public class SecurityConversionServiceTests {

	// @formatter:off
	private static final String PKCS8_PRIVATE_KEY_DATA = """
			MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCMk7CKSTfu3QoV
			HoPVXxwZO+qweztd36cVWYqGOZinrOR2crWFu50AgR2CsdIH0+cqo7F4Vx7/3O8i
			RpYYZPe2VoO5sumzJt8P6fS80/TAKjhJDAqgZKRJTgGN8KxCM6p/aJli1ZeDBqiV
			v7vJJe+ZgJuPGRS+HMNa/wPxEkqqXsglcJcQV1ZEtfKXSHB7jizKpRL38185SyAC
			pwyjvBu6Cmm1URfhQo88mf239ONh4dZ2HoDfzN1q6Ssu4F4hgutxr9B0DVLDP5u+
			WFrm3nsJ76zf99uJ+ntMUHJ+bY+gOjSlVWIVBIZeAaEGKCNWRk/knjvjbijpvm3U
			acGlgdL3AgMBAAECggEACxxxS7zVyu91qI2s5eSKmAQAXMqgup6+2hUluc47nqUv
			uZz/c/6MPkn2Ryo+65d4IgqmMFjSfm68B/2ER5FTcvoLl1Xo2twrrVpUmcg3BClS
			IZPuExdhVNnxjYKEWwcyZrehyAoR261fDdcFxLRW588efIUC+rPTTRHzAc7sT+Ln
			t/uFeYNWJm3LaegOLoOmlMAhJ5puAWSN1F0FxtRf/RVgzbLA9QC975SKHJsfWCSr
			IZyPsdeaqomKaF65l8nfqlE0Ua2L35gIOGKjUwb7uUE8nI362RWMtYdoi3zDDyoY
			hSFbgjylCHDM0u6iSh6KfqOHtkYyJ8tUYgVWl787wQKBgQDYO3wL7xuDdD101Lyl
			AnaDdFB9fxp83FG1cWr+t7LYm9YxGfEUsKHAJXN6TIayDkOOoVwIl+Gz0T3Z06Bm
			eBGLrB9mrVA7+C7NJwu5gTMlzP6HxUR9zKJIQ/VB1NUGM77LSmvOFbHc9Q0+z8EH
			X5WO516a3Z7lNtZJcCoPOtu2rwKBgQCmbj41Fh+SSEUApCEKms5ETRpe7LXQlJgx
			yW7zcJNNuIb1C3vBLPxjiOTMgYKOeMg5rtHTGLT43URHLh9ArjawasjSAr4AM3J4
			xpoi/sKGDdiKOsuDWIGfzdYL8qyTHSdpZLQsCTMRiRYgAHZFPgNa7SLZRfZicGlr
			GHN1rJW6OQKBgEjiM/upyrJSWeypUDSmUeAZMpA6aWkwsfHgmtnkfUn5rQa74cDB
			kKO9e+D7LmOR3z+SL/1NhGwh2SE07dncGr3jdGodfO/ZxZyszozmeaECKcEFwwJM
			GV8WWPKplGwUwPiwywmZ0mvRxXcoe73KgBS88+xrSwWjqDL0tZiQlEJNAoGATkei
			GMQMG3jEg9Wu+NbxV6zQT3+U0MNjhl9RQU1c63x0dcNt9OFc4NAdlZcAulRTENaK
			OHjxffBM0hH+fySx8m53gFfr2BpaqDX5f6ZGBlly1SlsWZ4CchCVsc71nshipi7I
			k8HL9F5/OpQdDNprJ5RMBNfkWE65Nrcsb1e6oPkCgYAxwgdiSOtNg8PjDVDmAhwT
			Mxj0Dtwi2fAqQ76RVrrXpNp3uCOIAu4CfruIb5llcJ3uak0ZbnWri32AxSgk80y3
			EWiRX/WEDu5znejF+5O3pI02atWWcnxifEKGGlxwkcMbQdA67MlrJLFaSnnGpNXo
			yPfcul058SOqhafIZQMEKQ==""";
	// @formatter:on

	// @formatter:off
	private static final String PKCS8_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n"
			+ PKCS8_PRIVATE_KEY_DATA + "\n"
			+ "-----END PRIVATE KEY-----";
	// @formatter:on

	// @formatter:off
	private static final String PKCS1_PRIVATE_KEY = """
			-----BEGIN RSA PRIVATE KEY-----
			MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw
			33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW
			+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB
			AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS
			3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp
			uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE
			2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0
			GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K
			Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY
			6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5
			fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523
			Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP
			FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==
			-----END RSA PRIVATE KEY-----""";
	// @formatter:on

	// @formatter:off
	private static final String X509_PUBLIC_KEY_DATA = """
			MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd
			UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs
			HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D
			o2kQ+X5xK9cipRgEKwIDAQAB""";
	// @formatter:on

	// @formatter:off
	private static final String X509_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
			+ X509_PUBLIC_KEY_DATA + "\n"
			+ "-----END PUBLIC KEY-----";
	// @formatter:on

	// @formatter:off
	private static final String X509_CERTIFICATE_DATA = """
			MIIBqDCCARECBgF5zJA6MjANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDEw9TaGF6
			aW4gU2FkYWthdGgwHhcNMjEwNjAxMTE1MTE0WhcNMjEwNTE3MjAwOTI1WjAaMRgw
			FgYDVQQDEw9TaGF6aW4gU2FkYWthdGgwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
			AoGBAKsKpS6sliNSri3koOAgzS7Nz2cpl0tGpNP3GPuUYVMP4MA0LJ2+blxjxUcn
			oIajtaf9HljFetKVjyARp1zjZ3Oxm//lfmyqqI5KDUjqe5J2rdtbdFCH9FXUEoGD
			mu2ameR9lAfxtaGI58DGS9uJ5hvGJoIvLiaDUfv1qZ+kIwG7AgMBAAEwDQYJKoZI
			hvcNAQELBQADgYEAWdIIi4cGPod5O/V7K0QSTXZRLRIKFQ7qhn5XTNlMUnFnwp7c
			8O8EsOiCKAZeVvgRnurFkxAlVnpxmdktZ9j+mv2mrMGKJxYkZcBkFh++DRixpY8N
			zBLbxZJ9kcOHWWDA602FMbNIEL1OiHrfggsPk3sckSaSg4d7UoP9T6+uqq8=""";

	// @formatter:on

	// @formatter:off
	private static final String X509_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
			+ X509_CERTIFICATE_DATA + "\n"
			+ "-----END CERTIFICATE-----";
	// @formatter:on

	private static final String MALFORMED_X509_KEY = "malformed";

	private final SecurityConversionService converters = SecurityConversionService.getSharedInstance();

	@Test
	public void rsaPrivateKeyWhenConvertingPkcs8PrivateKeyThenOk() {
		RSAPrivateKey key = this.converters.convert(toInputStream(PKCS8_PRIVATE_KEY), RSAPrivateKey.class);
		assertThat(key).isInstanceOf(RSAPrivateCrtKey.class);
		assertThat(key.getModulus().bitLength()).isEqualTo(2048);
	}

	@Test
	public void rsaPrivateKeyWhenRoundTripThenOk() {
		RSAPrivateKey cert = this.converters.convert(toInputStream(PKCS8_PRIVATE_KEY), RSAPrivateKey.class);
		byte[] bytes = this.converters.convert(cert, byte[].class);
		assertThat(cert).isEqualTo(this.converters.convert(bytes, RSAPrivateKey.class));
	}

	@Test
	public void rsaPrivateKeyWhenConvertingPkcs1PrivateKeyThenIllegalArgumentException() {
		assertThatExceptionOfType(ConversionFailedException.class)
			.isThrownBy(() -> this.converters.convert(toInputStream(PKCS1_PRIVATE_KEY), RSAPrivateKey.class));
	}

	@Test
	public void rsaPublicKeyWhenConvertingX509PublicKeyThenOk() {
		RSAPublicKey key = this.converters.convert(toInputStream(X509_PUBLIC_KEY), RSAPublicKey.class);
		assertThat(key.getModulus().bitLength()).isEqualTo(1024);
	}

	@Test
	public void rsaPublicKeyWhenConvertingX509CertificateThenOk() {
		RSAPublicKey key = this.converters.convert(toInputStream(X509_CERTIFICATE), RSAPublicKey.class);
		assertThat(key.getModulus().bitLength()).isEqualTo(1024);
	}

	@Test
	public void rsaPublicKeyWhenRoundTripThenOk() {
		RSAPublicKey cert = this.converters.convert(toInputStream(X509_PUBLIC_KEY), RSAPublicKey.class);
		byte[] bytes = this.converters.convert(cert, byte[].class);
		assertThat(cert).isEqualTo(this.converters.convert(bytes, RSAPublicKey.class));
	}

	@Test
	public void rsaPublicKeyWhenConvertingDerEncodedX509PublicKeyThenIllegalArgumentException() {
		assertThatExceptionOfType(ConversionFailedException.class)
			.isThrownBy(() -> this.converters.convert(toInputStream(MALFORMED_X509_KEY), RSAPublicKey.class));
	}

	@Test
	public void x509CertificateWhenConvertingX509CertificateThenOk() {
		X509Certificate cert = this.converters.convert(toInputStream(X509_CERTIFICATE), X509Certificate.class);
		assertThat(cert.getSerialNumber().longValue()).isEqualTo(1622634674738L);
	}

	@Test
	public void x509CertificateWhenRoundTripThenOk() {
		X509Certificate cert = this.converters.convert(toInputStream(X509_CERTIFICATE), X509Certificate.class);
		byte[] bytes = this.converters.convert(cert, byte[].class);
		assertThat(cert).isEqualTo(this.converters.convert(bytes, X509Certificate.class));
	}

	@Test
	public void x509CertificateWhenConvertingDerEncodedX509PublicKeyThenIllegalArgumentException() {
		assertThatExceptionOfType(ConversionFailedException.class)
			.isThrownBy(() -> this.converters.convert(toInputStream(MALFORMED_X509_KEY), X509Certificate.class));
	}

	private static InputStream toInputStream(String string) {
		return new ByteArrayInputStream(string.getBytes(StandardCharsets.UTF_8));
	}

}
