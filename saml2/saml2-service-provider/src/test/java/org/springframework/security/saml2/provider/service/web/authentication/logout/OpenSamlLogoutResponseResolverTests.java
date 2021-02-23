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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;

public class OpenSamlLogoutResponseResolverTests {

	@Test
	public void resolveWhenAuthenticatedThenSuccess() {
		OpenSamlLogoutResponseResolver resolver = new OpenSamlLogoutResponseResolver();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		HttpServletRequest request = new MockHttpServletRequest();
		request.setAttribute(Saml2RequestAttributeNames.LOGOUT_REQUEST_ID, "logout_request_id");
		String serialized = resolver.resolveLogoutResponse(request, registration).resolve().getSamlResponse();
		Saml2MessageBinding binding = registration.getAssertingPartyDetails().getSingleLogoutServiceBinding();
		LogoutResponse logoutResponse = getLogoutResponse(serialized, binding);
		assertThat(logoutResponse.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.SUCCESS);
	}

	private LogoutResponse getLogoutResponse(String samlRequest, Saml2MessageBinding binding) {
		if (binding == Saml2MessageBinding.REDIRECT) {
			samlRequest = Saml2Utils.samlInflate(Saml2Utils.samlDecode(samlRequest));
		}
		else {
			samlRequest = new String(Saml2Utils.samlDecode(samlRequest), StandardCharsets.UTF_8);
		}
		try {
			Document document = XMLObjectProviderRegistrySupport.getParserPool()
					.parse(new ByteArrayInputStream(samlRequest.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutResponse) XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(element)
					.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

}
