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

package org.springframework.security.oauth2.client.jackson2;

import java.io.IOException;
import java.util.Collection;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

/**
 * A JsonDeserializer for {@link DefaultOidcUser}.
 *
 * @author Ahmed Nabil
 * @since 6.3
 * @see DefaultOidcUser
 * @see DefaultOidcUserMixin
 */
public class DefaultOidcUserDeserializer extends JsonDeserializer<DefaultOidcUser> {

	@Override
	public DefaultOidcUser deserialize(JsonParser parser, DeserializationContext context)
			throws IOException, JacksonException {
		ObjectMapper mapper = (ObjectMapper) parser.getCodec();
		JsonNode defaultOidcUserNode = mapper.readTree(parser);
		Collection<? extends GrantedAuthority> authorities = JsonNodeUtils.findValue(defaultOidcUserNode, "authorities",
				JsonNodeUtils.GRANTED_AUTHORITY_COLLECTION, mapper);
		OidcIdToken idToken = JsonNodeUtils.findValueByPath(defaultOidcUserNode, "idToken", OidcIdToken.class, mapper);
		OidcUserInfo userInfo = JsonNodeUtils.findValueByPath(defaultOidcUserNode, "userInfo", OidcUserInfo.class,
				mapper);
		String nameAttributeKey = JsonNodeUtils.findValueByPath(defaultOidcUserNode, "nameAttributeKey", String.class,
				mapper);
		String name = JsonNodeUtils.findValueByPath(defaultOidcUserNode, "name", String.class, mapper);
		return (name != null) ? new DefaultOidcUser(idToken, userInfo, authorities, name)
				: new DefaultOidcUser(authorities, idToken, userInfo, nameAttributeKey);
	}

}
