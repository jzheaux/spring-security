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

package org.springframework.security.web.session;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

public final class BackchannelSessionInformationExpiredStrategy implements SessionInformationExpiredStrategy {

	private RestOperations rest = new RestTemplate();

	private String logoutEndpointName = "/logout";

	private String clientSessionCookieName = "JSESSIONID";

	@Override
	public void onExpiredSessionDetected(SessionInformationExpiredEvent event) {
		SessionInformation information = event.getSessionInformation();
		HttpHeaders headers = new HttpHeaders();
		headers.add("Cookie", this.clientSessionCookieName + "=" + information.getSessionId());
		this.rest.postForEntity(this.logoutEndpointName, headers, Object.class);
	}

	public void setRestOperations(RestOperations rest) {
		Assert.notNull(rest, "rest cannot be null");
		this.rest = rest;
	}

	public void setLogoutEndpointName(String logoutEndpointName) {
		Assert.hasText(logoutEndpointName, "logoutEndpointName cannot be empty");
		this.logoutEndpointName = logoutEndpointName;
	}

	public void setClientSessionCookieName(String clientSessionCookieName) {
		Assert.hasText(clientSessionCookieName, "clientSessionCookieName cannot be empty");
		this.clientSessionCookieName = clientSessionCookieName;
	}

}
