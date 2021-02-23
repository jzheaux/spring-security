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

import java.util.ArrayList;
import java.util.HashMap;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.junit.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.w3c.dom.Element;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;

public class OpenSamlLogoutRequestHandlerTests {

	@Test
	public void handleWhenAuthenticatedThenSavesRequestId() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		TestOpenSamlObjects.signed(logoutRequest, TestSaml2X509Credentials.assertingPartySigningCredential(),
				registration.getAssertingPartyDetails().getEntityId());
		Saml2Authentication authentication = new Saml2Authentication(
				new DefaultSaml2AuthenticatedPrincipal(logoutRequest.getNameID().getValue(), new HashMap<>()),
				"response", new ArrayList<>(), registration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("SAMLRequest", Saml2Utils.samlEncode(Saml2Utils.samlDeflate(serialize(logoutRequest))));
		OpenSamlLogoutRequestHandler handler = new OpenSamlLogoutRequestHandler();
		handler.logout(request, null, authentication);
		String id = (String) request.getAttribute(Saml2RequestAttributeNames.LOGOUT_REQUEST_ID);
		assertThat(id).isEqualTo(logoutRequest.getID());
	}

	private String serialize(XMLObject object) {
		try {
			Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
			Element element = marshaller.marshall(object);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

}
