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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

@ConfigurationProperties("sample.provider")
public class SampleTokenProvider {
	String tokenUri;
	Map<String, String> tokenBody;
	String clientId;
	String clientPassword;
	Container container;

	RestTemplate rest = new RestTemplate();

	public String requestToken() {
		HttpHeaders headers = new HttpHeaders();

		String creds = this.clientId + ":";
		if (StringUtils.hasText(this.clientPassword)) {
			creds += this.clientPassword;
		}

		String authorization = Base64.getEncoder().encodeToString(creds.getBytes());

		headers.add("Authorization", "Basic " + authorization);
		headers.add("Content-Type", "application/x-www-form-urlencoded");

		String body = this.tokenBody.entrySet().stream()
				.map(entry -> entry.getKey() + "=" + entry.getValue())
				.collect(Collectors.joining("&"));

		HttpEntity<String> request = new HttpEntity<>(body, headers);

		ResponseEntity<Map> response = this.rest.postForEntity(
				this.tokenUri,
				request, Map.class );

		return (String) response.getBody().get("access_token");
	}

	public String getTokenUri() {
		return tokenUri;
	}

	public void setTokenUri(String tokenUri) {
		this.tokenUri = tokenUri;
	}

	public Map<String, String> getTokenBody() {
		return tokenBody;
	}

	public void setTokenBody(Map<String, String> tokenBody) {
		this.tokenBody = tokenBody;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientPassword() {
		return clientPassword;
	}

	public void setClientPassword(String clientPassword) {
		this.clientPassword = clientPassword;
	}

	public Container getContainer() {
		return container;
	}

	public void setContainer(Container container) {
		this.container = container;
	}
}
