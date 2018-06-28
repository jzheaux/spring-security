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
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import javax.annotation.PreDestroy;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
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
			"{\"keys\":[{\"p\":\"2p-ViY7DE9ZrdWQb544m0Jp7Cv03YCSljqfim9pD4ALhObX0OrAznOiowTjwBky9JGffMwDBVSfJSD9TSU7aH2sbbfi0bZLMdekKAuimudXwUqPDxrrg0BCyvCYgLmKjbVT3zcdylWSog93CNTxGDPzauu-oc0XPNKCXnaDpNvE\",\"kty\":\"RSA\",\"q\":\"sP_QYavrpBvSJ86uoKVGj2AGl78CSsAtpf1ybSY5TwUlorXSdqapRbY69Y271b0aMLzlleUn9ZTBO1dlKV2_dw_lPADHVia8z3pxL-8sUhIXLsgj4acchMk4c9YX-sFh07xENnyZ-_TXm3llPLuL67HUfBC2eKe800TmCYVWc9U\",\"d\":\"bn1nFxCQT4KLTHqo8mo9HvHD0cRNRNdWcKNnnEQkCF6tKbt-ILRyQGP8O40axLd7CoNVG9c9p_-g4-2kwCtLJNv_STLtwfpCY7VN5o6-ZIpfTjiW6duoPrLWq64Hm_4LOBQTiZfUPcLhsuJRHbWqakj-kV_YbUyC2Ocf_dd8IAQcSrAU2SCcDebhDCWwRUFvaa9V5eq0851S9goaA-AJz-JXyePH6ZFr8JxmWkWxYZ5kdcMD-sm9ZbxE0CaEk32l4fE4hR-L8x2dDtjWA-ahKCZ091z-gV3HWtR2JOjvxoNRjxUo3UxaGiFJHWNIl0EYUJZu1Cb-5wIlEI7wPx5mwQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"one\",\"qi\":\"qS0OK48M2CIAA6_4Wdw4EbCaAfcTLf5Oy9t5BOF_PFUKqoSpZ6JsT5H0a_4zkjt-oI969v78OTlvBKbmEyKO-KeytzHBAA5CsLmVcz0THrMSg6oXZqu66MPnvWoZN9FEN5TklPOvBFm8Bg1QZ3k-YMVaM--DLvhaYR95_mqaz50\",\"dp\":\"Too2NozLGD1XrXyhabZvy1E0EuaVFj0UHQPDLSpkZ_2g3BK6Art6T0xmE8RYtmqrKIEIdlI3IliAvyvAx_1D7zWTTRaj-xlZyqJFrnXWL7zj8UxT8PkB-r2E-ILZ3NAi1gxIWezlBTZ8M6NfObDFmbTc_3tJkN_raISo8z_ziIE\",\"dq\":\"U0yhSkY5yOsa9YcMoigGVBWSJLpNHtbg5NypjHrPv8OhWbkOSq7WvSstBkFk5AtyFvvfZLMLIkWWxxGzV0t6f1MoxBtttLrYYyCxwihiiGFhLbAdSuZ1wnxcqA9bC7UVECvrQmVTpsMs8UupfHKbQBpZ8OWAqrnuYNNtG4_4Bt0\",\"n\":\"lygtuZj0lJjqOqIWocF8Bb583QDdq-aaFg8PesOp2-EDda6GqCpL-_NZVOflNGX7XIgjsWHcPsQHsV9gWuOzSJ0iEuWvtQ6eGBP5M6m7pccLNZfwUse8Cb4Ngx3XiTlyuqM7pv0LPyppZusfEHVEdeelou7Dy9k0OQ_nJTI3b2E1WBoHC58CJ453lo4gcBm1efURN3LIVc1V9NQY_ESBKVdwqYyoJPEanURLVGRd6cQKn6YrCbbIRHjqAyqOE-z3KmgDJnPriljfR5XhSGyM9eqD9Xpy6zu_MAeMJJfSArp857zLPk-Wf5VP9STAcjyfdBIybMKnwBYr2qHMT675hQ\"}]}",
			200
	);

	private static final MockResponse NO_SCOPES_RESPONSE = response(
			"{\"access_token\":\"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0IiwiZXhwIjo0NjgzODA1MTI4fQ.ULEPdHG-MK5GlrTQMhgqcyug2brTIZaJIrahUeq9zaiwUSdW83fJ7W1IDd2Z3n4a25JY2uhEcoV95lMfccHR6y_2DLrNvfta22SumY9PEDF2pido54LXG6edIGgarnUbJdR4rpRe_5oRGVa8gDx8FnuZsNv6StSZHAzw5OsuevSTJ1UbJm4UfX3wiahFOQ2OI6G-r5TB2rQNdiPHuNyzG5yznUqRIZ7-GCoMqHMaC-1epKxiX8gYXRROuUYTtcMNa86wh7OVDmvwVmFioRcR58UWBRoO1XQexTtOQq_t8KYsrPZhb9gkyW8x2bAQF-d0J0EJY8JslaH6n4RBaZISww\",\"token_type\":\"bearer\",\"expires_in\":\"3153600000\",\"scope\":\"\"}",
			200
	);

	private static final MockResponse MESSAGE_READ_SCOPE_RESPONSE = response(
			"{\"access_token\":\"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0Iiwic2NvcGUiOiJtZXNzYWdlOnJlYWQiLCJleHAiOjQ2ODM4MDUxNDF9.h-j6FKRFdnTdmAueTZCdep45e6DPwqM68ZQ8doIJ1exi9YxAlbWzOwId6Bd0L5YmCmp63gGQgsBUBLzwnZQ8kLUgUOBEC3UzSWGRqMskCY9_k9pX0iomX6IfF3N0PaYs0WPC4hO1s8wfZQ-6hKQ4KigFi13G9LMLdH58PRMK0pKEvs3gCbHJuEPw-K5ORlpdnleUTQIwINafU57cmK3KocTeknPAM_L716sCuSYGvDl6xUTXO7oPdrXhS_EhxLP6KxrpI1uD4Ea_5OWTh7S0Wx5LLDfU6wBG1DowN20d374zepOIEkR-Jnmr_QlR44vmRqS5ncrF-1R0EGcPX49U6A\",\"token_type\":\"bearer\",\"expires_in\":\"3153600000\",\"scope\":\"message:read\"}",
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
		String uri = environment.getProperty("sample.jwk-set-uri", "mock://localhost:0");

		if ( uri.startsWith("mock://") ) {
			try {
				this.server.start(new URI(uri).getPort());
			} catch (IOException | URISyntaxException e ) {
				throw new IllegalStateException(e);
			}

			Map<String, Object> properties = new HashMap<>();
			String url = this.server.url("/.well-known/jwks.json").toString();
			properties.put("sample.jwk-set-uri", url);

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
