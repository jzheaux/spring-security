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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseUnmarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;

public class OpenSamlLogoutResponseDecoder implements Saml2LogoutResponseDecoder {
	static {
		OpenSamlInitializationService.initialize();
	}

	private Log logger = LogFactory.getLog(this.getClass());

	private final LogoutResponseUnmarshaller responseUnmarshaller;

	private final ParserPool parserPool;

	private final Issuer issuer;

	public OpenSamlLogoutResponseDecoder(String issuer) {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.responseUnmarshaller = (LogoutResponseUnmarshaller) registry.getUnmarshallerFactory()
				.getUnmarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
		this.parserPool = registry.getParserPool();
		this.issuer = ((IssuerBuilder) registry.getBuilderFactory()
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME)).buildObject();
		this.issuer.setValue(issuer);
	}

	@Override
	public Saml2LogoutResponse decode(String logoutResponse) {
		LogoutResponse response = parse(logoutResponse);
		if (!this.issuer.equals(response.getIssuer())) {
			return null;//Saml2LogoutResponse.failure();
		}
		StatusCode code = response.getStatus().getStatusCode();
		if (!code.getValue().equals(StatusCode.SUCCESS)) {
			return null;//Saml2LogoutResponse.failure(code.getValue());
		}
		return null;//Saml2LogoutResponse.success();
	}

	private LogoutResponse parse(String response) {
		try {
			Document document = this.parserPool
					.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutResponse) this.responseUnmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex.getMessage(), ex);
		}
	}
}
