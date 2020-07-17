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

package org.springframework.security.saml2.provider.service.web;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Base64;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.authentication.AuthenticationConverter;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.security.saml2.core.Saml2ErrorCodes.RELYING_PARTY_REGISTRATION_NOT_FOUND;

public class Saml2WebSsoAuthenticationConverter implements AuthenticationConverter {
	private final Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver;

	public Saml2WebSsoAuthenticationConverter(
			Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver) {

		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		RelyingPartyRegistration relyingPartyRegistration = resolveRelyingPartyRegistration(request);
		String saml2Response = request.getParameter("SAMLResponse");
		byte[] b = samlDecode(saml2Response);
		String responseXml = inflateIfRequired(request, b);
		return new Saml2AuthenticationToken(relyingPartyRegistration, responseXml);
	}

	private String inflateIfRequired(HttpServletRequest request, byte[] b) {
		if (HttpMethod.GET.matches(request.getMethod())) {
			return samlInflate(b);
		}
		else {
			return new String(b, UTF_8);
		}
	}

	private RelyingPartyRegistration resolveRelyingPartyRegistration(HttpServletRequest request) {
		try {
			return this.relyingPartyRegistrationResolver.convert(request);
		} catch (Exception e) {
			Saml2Error saml2Error = new Saml2Error(RELYING_PARTY_REGISTRATION_NOT_FOUND,
					"Failed to find relying party registration");
			throw new Saml2AuthenticationException(saml2Error, e);
		}
	}

	private static Base64 BASE64 = new Base64(0, new byte[]{'\n'});

	static byte[] samlDecode(String s) {
		return BASE64.decode(s);
	}

	static String samlInflate(byte[] b) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			InflaterOutputStream iout = new InflaterOutputStream(out, new Inflater(true));
			iout.write(b);
			iout.finish();
			return new String(out.toByteArray(), UTF_8);
		}
		catch (IOException e) {
			throw new Saml2Exception("Unable to inflate string", e);
		}
	}
}
