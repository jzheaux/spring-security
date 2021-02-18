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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

public class Saml2LogoutResponse {
	private final Map<String, String> parameters;

	private Saml2LogoutResponse(Map<String, String> parameters) {
		this.parameters = Collections.unmodifiableMap(new HashMap<>(parameters));
	}

	public String getSamlRequest() {
		return this.parameters.get("SAMLRequest");
	}

	public String getParameter(String name) {
		return this.parameters.get(name);
	}

	public Map<String, String> getParameters() {
		return this.parameters;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {
		private Map<String, String> parameters = new HashMap<>();

		public Builder samlRequest(String samlRequest) {
			this.parameters.put("SAMLRequest", samlRequest);
			return this;
		}

		public Builder parameters(Consumer<Map<String, String>> parametersConsumer) {
			parametersConsumer.accept(this.parameters);
			return this;
		}

		public Saml2LogoutResponse build() {
			return new Saml2LogoutResponse(this.parameters);
		}
	}
}
