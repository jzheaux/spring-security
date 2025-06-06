/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication;

import java.io.Serial;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnStatement;

import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * An OpenSAML-based implementation of {@link Saml2ResponseAssertionAccessor}
 *
 * @author Josh Cummings
 * @since 7.0
 */
public class OpenSamlResponseAssertionAccessor implements Saml2ResponseAssertionAccessor {

	@Serial
	private static final long serialVersionUID = -7505233045395024212L;

	private final String responseValue;

	private final String nameId;

	private final List<String> sessionIndexes;

	private final Map<String, List<Object>> attributes;

	public OpenSamlResponseAssertionAccessor(String responseValue, Assertion assertion) {
		Assert.notNull(responseValue, "response value cannot be null");
		Assert.notNull(assertion, "assertion cannot be null");
		this.responseValue = responseValue;
		this.nameId = calculateNameId(assertion);
		this.sessionIndexes = calculateSessionIndexes(assertion);
		this.attributes = calculateAssertionAttributes(assertion);
	}

	public OpenSamlResponseAssertionAccessor(String responseValue, String nameId, List<String> sessionIndexes,
			Map<String, List<Object>> attributes) {
		Assert.notNull(responseValue, "response value cannot be null");
		Assert.notNull(nameId, "nameId cannot be null");
		Assert.notNull(sessionIndexes, "sessionIndexes cannot be null");
		Assert.notNull(attributes, "attributes cannot be null");
		this.responseValue = responseValue;
		this.nameId = nameId;
		this.sessionIndexes = sessionIndexes;
		this.attributes = attributes;
	}

	private String calculateNameId(Assertion assertion) {
		if (assertion.getSubject() == null) {
			return null;
		}
		if (assertion.getSubject().getNameID() == null) {
			return null;
		}
		return assertion.getSubject().getNameID().getValue();
	}

	private static List<String> calculateSessionIndexes(Assertion assertion) {
		List<String> sessionIndexes = new ArrayList<>();
		for (AuthnStatement statement : assertion.getAuthnStatements()) {
			sessionIndexes.add(statement.getSessionIndex());
		}
		return sessionIndexes;
	}

	private static Map<String, List<Object>> calculateAssertionAttributes(Assertion assertion) {
		MultiValueMap<String, Object> attributeMap = new LinkedMultiValueMap<>();
		for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
			for (Attribute attribute : attributeStatement.getAttributes()) {
				List<Object> attributeValues = new ArrayList<>();
				for (XMLObject xmlObject : attribute.getAttributeValues()) {
					Object attributeValue = getXmlObjectValue(xmlObject);
					if (attributeValue != null) {
						attributeValues.add(attributeValue);
					}
				}
				attributeMap.addAll(attribute.getName(), attributeValues);
			}
		}
		return new LinkedHashMap<>(attributeMap);
	}

	private static Object getXmlObjectValue(XMLObject xmlObject) {
		if (xmlObject instanceof XSAny) {
			return ((XSAny) xmlObject).getTextContent();
		}
		if (xmlObject instanceof XSString) {
			return ((XSString) xmlObject).getValue();
		}
		if (xmlObject instanceof XSInteger) {
			return ((XSInteger) xmlObject).getValue();
		}
		if (xmlObject instanceof XSURI) {
			return ((XSURI) xmlObject).getURI();
		}
		if (xmlObject instanceof XSBoolean) {
			XSBooleanValue xsBooleanValue = ((XSBoolean) xmlObject).getValue();
			return (xsBooleanValue != null) ? xsBooleanValue.getValue() : null;
		}
		if (xmlObject instanceof XSDateTime) {
			return ((XSDateTime) xmlObject).getValue();
		}
		return xmlObject;
	}

	@Override
	public String getNameId() {
		return this.nameId;
	}

	@Override
	public List<String> getSessionIndexes() {
		return this.sessionIndexes;
	}

	@Override
	public Map<String, List<Object>> getAttributes() {
		return this.attributes;
	}

	@Override
	public String getResponseValue() {
		return this.responseValue;
	}

}
