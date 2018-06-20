/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample.provider;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import javax.annotation.PreDestroy;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * This is a miminal mock server that serves as a placeholder for a real Authorization Server (AS).
 *
 * For the sample to work, the AS used must support a JWK endpoint.
 *
 * For the integration tests to work, the AS used must be able to issue a token
 * with the following characteristics:
 *
 * - The token has the "message:read" scope
 * - The token has a "sub" of "subject"
 * - The token is signed by a RS256 private key whose public key counterpart is served from the JWK endpoint of the AS.
 *
 * There is also a test that verifies insufficient scope. In that case, the token should have the following characteristics:
 *
 * - The token is missing the "message:read" scope
 * - The token is signed by a RS256 private key whose public key counterpart is served from the JWK endpoint of the AS.
 */
public class MockProvider implements EnvironmentPostProcessor {
	private MockWebServer server = new MockWebServer();

	private static final MockResponse JWKS_RESPONSE = response(
			"{\"keys\":[{\"p\":\"5ECt_n5S09C-E4iX5leaXrwCZDOKbSNQq0EMQoPPIv4r07-2aJ6l6-W_Q3iBo2x3WVKojrq141mrXoA8cXYxa-yyXQg7XjzMs29st3oNLJLtqZJhJ9sXMh51zVi9Kz79RgnLXEWJNk103b1aaRUhFgbWy_nqfXC106KxwbpvrcM\",\"kty\":\"RSA\",\"q\":\"vUGYYo2J4qQ61oEZYR1i6-0n0vfHsQUS806GWK5erjZEtT3zS3uhtFATdnjIEI5wfuB-MslHL6GV2mQJEDKRY_RSoQCJiRSCVb4nlDAJd_rGG8jB-I_HUWRlXptbnmL5qvSrNpCMpydPfp1GONM_q_9gAJD-Jmvidtfqne5aMk0\",\"d\":\"eZIVUgUHD6NlVWZylLf4hnvwTjQYUA6gNarDXrwAZX-8T2nkhhbCNSPB2zrZ8-0AnTFf2OknLmgSHo8cDFCF3gqWvDagmqjZHmiS4e3QOhu_XP42bhnbdvMTViSspZduVvVd80Kox9Crw-aybXNz7Sor7dF2nwohcTGW_isiLhjkoJKjHMX7c6oBFOoj0yXnW3_SO22CjcP5vgSvPahFw51ScKH1hATxwZr2PHflYu4T6iipWHzasQ1UDQEbqWShmXW_TB2UOUUZvO4RtHKUcmyGFUpk_a9LN3M9FpJ67WCmZIYsCRml_UKwK-n6NtJwjQPffGBkpgtNmoC4velygQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"sample\",\"qi\":\"zQsHuFQ7-A77f9047mF0ZV5elcVXmTMJ_Jzx7kSNv0sVqA-B-GGJKlaAP85ZBUqiy8Xk_OjaM-3a_b67REnP3Qx4sDLeJwNrGpTcah1cTQ5qQIkvqPL7UTU4f6zBqewfU2_3obcGcFg-JxI4-_NiZXm6E1S4XnuWAFDTlN1LRo4\",\"dp\":\"bvD5IQ9pVsbI_FmR60V9JLqhNu7OQ4m8teBiAxpp3YpI5xzxnhwubWA3_KVf7XzU7bd9chJSQfTdlIsj1coq71gWwZ00rfNDU5u-7dcG_DlWBuu9CVA2EAg6HdsZ5yEwnZA5JdoufRRcz0Iv5Y99i2U7ld0dGmdkGT-kwpLJoV0\",\"dq\":\"nR79LSzGwbOI6ZbKhDbKboY4Xsy5K7zDq92QacVx8344cqPY_dzJNhKY5e2GY0BuIterzewOvnuPFn2gjKL-05X-l44DoRu2zQqOf1eWNNasbFqytvJfDrKj-fRPDuKq1oRENIuzSf63360gpIK1RM1CXZYCedFtdS7yqGU-2q0\",\"n\":\"qL48v1clgFw-Evm145pmh8nRYiNt72Gupsshn7Qs8dxEydCRp1DPOV_PahPk1y2nvldBNIhfNL13JOAiJ6BTiF-2ICuICAhDArLMnTH61oL1Hepq8W1xpa9gxsnL1P51thvfmiiT4RTW57koy4xIWmIp8ZXXfYgdH2uHJ9R0CQBuYKe7nEOObjxCFWC8S30huOfW2cYtv0iB23h6w5z2fDLjddX6v_FXM7ktcokgpm3_XmvT_-bL6_GGwz9k6kJOyMTubecr-WT__le8ikY66zlplYXRQh6roFfFCL21Pt8xN5zrk-0AMZUnmi8F2S2ztSBmAVJ7H71ELXsURBVZpw\"}]}",
			200
	);

	private static final MockResponse NO_SCOPES_RESPONSE = response(
			"{\"access_token\":\"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0IiwiZXhwIjozMTA2MzMzNTQ4LCJqdGkiOiIxZTJlYzUyYi03Y2MyLTRiN2UtYTc3Mi02YzgxZTUxNDBkNmEifQ.comtVXyp4xElRUiPqoHOcDqlO2Pibhn6XrFiLzXNuscTOq1OtxcRdWyq3sLEOsH9va9G1hlYVMNrJQlsWHAI0i30bAYhnPCveP-KAG05UsuCDVXnsr1qytkgnc38MfmcEf_A5r6Q9asNvZhr7Aly9zo7XSs1XQJNhg1RH7c6a7WB6-XjD1Q8b_vTu-7IJtpyufYHh7me96R4fMYf3VHdbBYNCM0EgeVDqJc6OH24r0Kag7eCzYd_w34hj9tQsNVXdl6_7zT6FPhVGZYOMB2zpYEAdAcJQNkny8Rui3cmhQBGBg2gveRhawJ4sPNJaG_nz4FUcBqVQSOqspQBs7q9zQ\",\"token_type\":\"bearer\",\"expires_in\":\"1576800000\",\"scope\":\"\"}",
			200
	);

	private static final MockResponse MESSAGE_READ_SCOPE_RESPONSE = response(
			"{\"access_token\":\"eyJhbGciOiJSUzI1NiJ9.eyJzY29wZSI6Im1lc3NhZ2U6cmVhZCIsImV4cCI6MzEwNjMyODEzMSwianRpIjoiOGY5ZjFiYzItOWVlMi00NTJkLThhMGEtODg3YmE4YmViYjYzIn0.CM_KulSsIrNXW1x6NFeN5VwKQiIW-LIAScJzakRFDox8Ql7o4WOb0ubY3CjWYnglwqYzBvH9McCFqVrUtzdfODY5tyEEJSxWndIGExOi2osrwRPsY3AGzNa23GMfC9I03BFP1IFCq4ZfL-L6yVcIjLke-rA40UG-r-oA7r-N_zsLc5poO7Azf29IQgQF0GSRp4AKQprYHF5Q-Nz9XkILMDz9CwPQ9cbdLCC9smvaGmEAjMUr-C1QgM-_ulb42gWtRDLorW_eArg8g-fmIP0_w82eNWCBjLTy-WaDMACnDVrrUVsUMCqx6jS6h8_uejKly2NFuhyueIHZTTySqCZoTA\",\"token_type\":\"bearer\",\"expires_in\":\"1576800000\",\"scope\":\"message:read\"}",
			200);

	private static final MockResponse NOT_FOUND_RESPONSE = response(
			"{ \"message\" : \"Heyo, to hit this mock server you should either GET /.well-known/jwks.json or POST /token\" }",
			404
	);

	public MockProvider() throws IOException {
		Dispatcher dispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
				if ( "/.well-known/jwks.json".equals(request.getPath()) ) {
					return JWKS_RESPONSE;
				}

				if ( "/token".equals(request.getPath()) ) {
					String body = request.getBody().readUtf8();
					if ( body.contains("scope=message:read") ) {
						return MESSAGE_READ_SCOPE_RESPONSE;
					} else {
						return NO_SCOPES_RESPONSE;
					}
				}

				return NOT_FOUND_RESPONSE;
			}
		};

		this.server.setDispatcher(dispatcher);
	}

	@Override
	public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
		Map issuers = Binder.get(environment)
				.bind("spring.security.oauth2.resourceserver.issuer", Map.class)
				.orElse(Collections.emptyMap());

		if ( issuers.isEmpty() || issuers.containsKey("mock") ) {
			Integer port = Integer.parseInt(environment.getProperty("sample.server.mock.port", "0"));

			try {
				this.server.start(port);
			} catch (IOException e) {
				throw new IllegalStateException(e);
			}

			Map<String, Object> properties = new HashMap<>();
			String url = this.server.url("/.well-known/jwks.json").toString();
			properties.put("spring.security.oauth2.resourceserver.issuer.mock.jwk-set-uri", url);

			MapPropertySource propertySource = new MapPropertySource("mock", properties);
			environment.getPropertySources().addFirst(propertySource);
		}
	}

	@PreDestroy
	public void shutdown() throws IOException {
		this.server.shutdown();
	}

	private static MockResponse response(String body, int status) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setResponseCode(status)
				.setBody(body);
	}
}
