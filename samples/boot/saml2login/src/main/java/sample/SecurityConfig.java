/*
 * Copyright 2002-2020 the original author or authors.
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

package sample;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.joda.time.DateTime;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlLogoutRequestHandler;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlLogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlLogoutResponseHandler;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlLogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2AssertingPartyInitiatedLogoutSuccessHandler;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {
	@Bean
	RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
		RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
				.fromMetadataLocation("https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/metadata.php")
				.registrationId("one")
				.singleLogoutServiceLocation("/saml2/logout/one")
				.singleLogoutServiceResponseLocation("/saml2/logout/one")
				.signingX509Credentials((signing) -> signing.add(getSigningCredential()))
				.build();
		return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
	}

	@Bean
	SecurityFilterChain web(HttpSecurity http, LogoutSuccessHandler successHandler, Saml2LogoutRequestResolver requestResolver) throws Exception {
		LogoutSuccessHandler redirect = new SimpleUrlLogoutSuccessHandler();
		http
			.authorizeRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.saml2Login(withDefaults())
			.logout((logout) -> logout
				.logoutRequestMatcher(new AntPathRequestMatcher("/saml2/logout/one", "GET"))
				.addLogoutHandler(new OpenSamlLogoutRequestHandler())
				.addLogoutHandler(new OpenSamlLogoutResponseHandler())
				.logoutSuccessHandler((request, response, authentication) -> {
					successHandler.onLogoutSuccess(request, response, authentication);
					redirect.onLogoutSuccess(request, response, authentication);
				})
			)
			.addFilterAfter(new Saml2RelyingPartyInitiatedLogoutFilter(requestResolver), LogoutFilter.class);

		return http.build();
	}

	@Bean
	Saml2AssertingPartyInitiatedLogoutSuccessHandler logoutSuccessHandler(Saml2LogoutResponseResolver requestResolver) {
		return new Saml2AssertingPartyInitiatedLogoutSuccessHandler(requestResolver);
	}

	@Bean
	Saml2LogoutRequestResolver requestResolver() {
		OpenSamlLogoutRequestResolver delegate = new OpenSamlLogoutRequestResolver();
		return (request, registration, authentication) ->
				delegate.resolveLogoutRequest(request, registration, authentication)
						// consider this pattern for a post-processor
						.request((logoutRequest) -> logoutRequest.setIssueInstant(DateTime.now()));
	}

	@Bean
	Saml2LogoutResponseResolver responseResolver() {
		OpenSamlLogoutResponseResolver delegate = new OpenSamlLogoutResponseResolver();
		return (request, registration) -> delegate.resolveLogoutResponse(request, registration)
				// consider this pattern for a post-processor
				.response((logoutResponse) -> logoutResponse.setIssueInstant(DateTime.now()));
	}

	private Saml2X509Credential getSigningCredential() {
		String key = "-----BEGIN PRIVATE KEY-----\n" +
				"MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANG7v8QjQGU3MwQE\n" +
				"VUBxvH6Uuiy/MhZT7TV0ZNjyAF2ExA1gpn3aUxx6jYK5UnrpxRRE/KbeLucYbOhK\n" +
				"cDECt77Rggz5TStrOta0BQTvfluRyoQtmQ5Nkt6Vqg7O2ZapFt7k64Sal7AftzH6\n" +
				"Q2BxWN1y04bLdDrH4jipqRj/2qEFAgMBAAECgYEAj4ExY1jjdN3iEDuOwXuRB+Nn\n" +
				"x7pC4TgntE2huzdKvLJdGvIouTArce8A6JM5NlTBvm69mMepvAHgcsiMH1zGr5J5\n" +
				"wJz23mGOyhM1veON41/DJTVG+cxq4soUZhdYy3bpOuXGMAaJ8QLMbQQoivllNihd\n" +
				"vwH0rNSK8LTYWWPZYIECQQDxct+TFX1VsQ1eo41K0T4fu2rWUaxlvjUGhK6HxTmY\n" +
				"8OMJptunGRJL1CUjIb45Uz7SP8TPz5FwhXWsLfS182kRAkEA3l+Qd9C9gdpUh1uX\n" +
				"oPSNIxn5hFUrSTW1EwP9QH9vhwb5Vr8Jrd5ei678WYDLjUcx648RjkjhU9jSMzIx\n" +
				"EGvYtQJBAMm/i9NR7IVyyNIgZUpz5q4LI21rl1r4gUQuD8vA36zM81i4ROeuCly0\n" +
				"KkfdxR4PUfnKcQCX11YnHjk9uTFj75ECQEFY/gBnxDjzqyF35hAzrYIiMPQVfznt\n" +
				"YX/sDTE2AdVBVGaMj1Cb51bPHnNC6Q5kXKQnj/YrLqRQND09Q7ParX0CQQC5NxZr\n" +
				"9jKqhHj8yQD6PlXTsY4Occ7DH6/IoDenfdEVD5qlet0zmd50HatN2Jiqm5ubN7CM\n" +
				"INrtuLp4YHbgk1mi\n" +
				"-----END PRIVATE KEY-----";
		String certificate = "-----BEGIN CERTIFICATE-----\n" +
				"MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
				"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
				"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
				"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
				"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
				"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
				"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
				"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
				"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
				"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
				"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
				"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
				"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
				"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B\n" +
				"-----END CERTIFICATE-----";
		PrivateKey pk = RsaKeyConverters.pkcs8().convert(new ByteArrayInputStream(key.getBytes()));
		X509Certificate cert = x509Certificate(certificate);
		return Saml2X509Credential.signing(pk, cert);
	}

	private X509Certificate x509Certificate(String source) {
		try {
			final CertificateFactory factory = CertificateFactory.getInstance("X.509");
			return (X509Certificate) factory.generateCertificate(
					new ByteArrayInputStream(source.getBytes(StandardCharsets.UTF_8))
			);
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}
}
