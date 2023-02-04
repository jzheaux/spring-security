/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.annotation.PreDestroy;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimNames;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.TestOidcLogoutTokens;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringTestContextExtension.class)
public class OAuth2LogoutConfigurerTests {

	@Autowired
	private MockMvc mvc;

	@Autowired
	private MockWebServer web;

	@Autowired
	private ClientRegistration registration;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	void logoutWhenDefaultsThenRemotelyInvalidatesSessions() throws Exception {
		this.spring.register(WebServerConfig.class, OidcController.class, DefaultConfig.class).autowire();
		MockMvcDispatcher dispatcher = (MockMvcDispatcher) this.web.getDispatcher();
		this.mvc.perform(get("/compute-logout-token")).andExpect(status().isUnauthorized());
		String registrationId = this.registration.getRegistrationId();
		MvcResult result = this.mvc.perform(get("/oauth2/authorization/" + registrationId))
				.andExpect(status().isFound()).andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession();
		String redirectUrl = result.getResponse().getRedirectedUrl();
		String state = UriComponentsBuilder.fromHttpUrl(redirectUrl).build(true).getQueryParams().getFirst("state");
		OidcController.nonce = UriComponentsBuilder.fromHttpUrl(redirectUrl).build(true).getQueryParams()
				.getFirst("nonce");
		state = UriUtils.decode(state, "UTF-8");
		result = this.mvc.perform(get("/login/oauth2/code/" + registrationId).param("code", "code")
				.param("state", state).session(session)).andExpect(status().isFound()).andReturn();
		session = (MockHttpSession) result.getRequest().getSession();
		dispatcher.registerSession(session);
		String logoutToken = this.mvc.perform(get("/compute-logout-token").session(session)).andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();
		this.mvc.perform(post(this.web.url("/oauth2/" + registrationId + "/logout").toString()).param("logout_token",
				logoutToken)).andExpect(status().isOk());
		this.mvc.perform(get("/compute-logout-token").session(session)).andExpect(status().isUnauthorized());
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	@Import(RegistrationConfig.class)
	static class DefaultConfig {

		@Bean
		SecurityFilterChain filters(HttpSecurity http, ClientRegistration registration) throws Exception {
			http.authorizeHttpRequests(
					(authorize) -> authorize.requestMatchers("/jwks").permitAll().anyRequest().authenticated())
					.httpBasic(Customizer.withDefaults()).oauth2Login(Customizer.withDefaults())
					.oauth2Logout((oauth2) -> oauth2.backchannel((backchannel) -> {
					})).oauth2ResourceServer(
							(oauth2) -> oauth2.jwt().jwkSetUri(registration.getProviderDetails().getJwkSetUri()));

			return http.build();
		}

		@Bean
		UserDetailsService users(ClientRegistration registration) {
			return new InMemoryUserDetailsManager(User.withUsername(registration.getClientId())
					.password("{noop}" + registration.getClientSecret()).authorities("APP").build());
		}

	}

	@Configuration
	static class RegistrationConfig {

		@Autowired
		MockWebServer web;

		@Bean
		ClientRegistration registration() {
			String issuer = this.web.url("/").toString();
			return TestClientRegistrations.clientRegistration().issuerUri(issuer).jwkSetUri(issuer + "jwks")
					.tokenUri(issuer + "token").userInfoUri(issuer + "user").scope("openid").build();
		}

		@Bean
		ClientRegistrationRepository registrations(ClientRegistration registration) {
			return new InMemoryClientRegistrationRepository(registration);
		}

	}

	@RestController
	static class OidcController {

		private static final RSAKey key = key();

		private static final JWKSource<SecurityContext> jwks = jwks(key);

		private static RSAKey key() {
			try {
				KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
				return new RSAKey.Builder((RSAPublicKey) pair.getPublic()).privateKey(pair.getPrivate()).build();
			}
			catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

		private static JWKSource<SecurityContext> jwks(RSAKey key) {
			try {
				return new ImmutableJWKSet<>(new JWKSet(key));
			}
			catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

		private final String username = "user";

		private final String sessionId = "session-id";

		static String nonce;

		JwtEncoder encoder = new NimbusJwtEncoder(jwks);

		@Autowired
		ClientRegistration registration;

		ObjectMapper mapper = new ObjectMapper();

		@PostMapping("/token")
		String accessToken() throws Exception {
			JwtEncoderParameters parameters = JwtEncoderParameters
					.from(JwtClaimsSet.builder().id("id").subject(this.username)
							.issuer(this.registration.getProviderDetails().getIssuerUri()).issuedAt(Instant.now())
							.expiresAt(Instant.now().plusSeconds(86400)).claim("scope", "openid").build());
			String token = this.encoder.encode(parameters).getTokenValue();
			return this.mapper.writeValueAsString(Map.of("access_token", token, "expires_in", 86400, "token_type",
					"BEARER", "scopes", "openid", "id_token", idToken()));
		}

		@GetMapping("/user")
		Map<String, Object> userinfo() {
			return Map.of("sub", this.username, "id", this.username);
		}

		String idToken() {
			OidcIdToken token = TestOidcIdTokens.idToken().issuer(this.registration.getProviderDetails().getIssuerUri())
					.subject(this.username).expiresAt(Instant.now().plusSeconds(86400))
					.audience(List.of(this.registration.getClientId())).nonce(nonce)
					.claim(LogoutTokenClaimNames.SID, this.sessionId).build();
			JwtEncoderParameters parameters = JwtEncoderParameters
					.from(JwtClaimsSet.builder().claims((claims) -> claims.putAll(token.getClaims())).build());
			return this.encoder.encode(parameters).getTokenValue();
		}

		@GetMapping("/jwks")
		String jwks() {
			return new JWKSet(key).toString();
		}

		@GetMapping("/compute-logout-token")
		String logoutToken(@AuthenticationPrincipal OidcUser user) {
			OidcLogoutToken token = TestOidcLogoutTokens.withUser(user)
					.audience(List.of(this.registration.getClientId())).build();
			JwtEncoderParameters parameters = JwtEncoderParameters
					.from(JwtClaimsSet.builder().claims((claims) -> claims.putAll(token.getClaims())).build());
			return this.encoder.encode(parameters).getTokenValue();
		}

	}

	@Configuration
	static class WebServerConfig {

		private final MockWebServer server = new MockWebServer();

		@Bean
		MockWebServer web(ObjectProvider<MockMvc> mvc) {
			this.server.setDispatcher(new MockMvcDispatcher(mvc));
			return this.server;
		}

		@PreDestroy
		void shutdown() throws IOException {
			this.server.shutdown();
		}

	}

	private static class MockMvcDispatcher extends Dispatcher {

		private final Map<String, MockHttpSession> session = new ConcurrentHashMap<>();

		private final ObjectProvider<MockMvc> mvcProvider;

		private MockMvc mvc;

		MockMvcDispatcher(ObjectProvider<MockMvc> mvc) {
			this.mvcProvider = mvc;
		}

		@Override
		public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
			this.mvc = this.mvcProvider.getObject();
			String method = request.getMethod();
			String path = request.getPath();
			String csrf = request.getHeader("X-CSRF-TOKEN");
			MockHttpSession session = session(request);
			MockHttpServletRequestBuilder builder;
			if ("GET".equals(method)) {
				builder = get(path);
			}
			else {
				builder = post(path).content(request.getBody().readUtf8());
				if (csrf != null) {
					builder.header("X-CSRF-TOKEN", csrf);
				}
				else {
					builder.with(csrf());
				}
			}
			for (Map.Entry<String, List<String>> header : request.getHeaders().toMultimap().entrySet()) {
				builder.header(header.getKey(), header.getValue().iterator().next());
			}
			MockHttpServletResponse mvcResponse = perform(builder.session(session)).andReturn().getResponse();
			return toMockResponse(mvcResponse);
		}

		void registerSession(MockHttpSession session) {
			this.session.put(session.getId(), session);
		}

		private MockHttpSession session(RecordedRequest request) {
			String cookieHeaderValue = request.getHeader("Cookie");
			if (cookieHeaderValue == null) {
				return new MockHttpSession();
			}
			String[] cookies = cookieHeaderValue.split(";");
			for (String cookie : cookies) {
				String[] parts = cookie.split("=");
				if ("JSESSIONID".equals(parts[0])) {
					return this.session.computeIfAbsent(parts[1],
							(k) -> new MockHttpSession(new MockServletContext(), parts[1]));
				}
			}
			return new MockHttpSession();
		}

		private ResultActions perform(MockHttpServletRequestBuilder builder) {
			try {
				return this.mvc.perform(builder);
			}
			catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

		private MockResponse toMockResponse(MockHttpServletResponse mvcResponse) {
			MockResponse response = new MockResponse();
			response.setResponseCode(mvcResponse.getStatus());
			for (String name : mvcResponse.getHeaderNames()) {
				response.addHeader(name, mvcResponse.getHeaderValue(name));
			}
			response.setBody(getContentAsString(mvcResponse));
			return response;
		}

		private String getContentAsString(MockHttpServletResponse response) {
			try {
				return response.getContentAsString();
			}
			catch (Exception ex) {
				throw new RuntimeException(ex);
			}
		}

	}

}
