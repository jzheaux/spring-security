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
import java.util.Map;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

/**
 * A JsonDeserializer for {@link DefaultOAuth2User}.
 *
 * @author Ahmed Nabil
 * @since 6.3
 * @see DefaultOAuth2User
 * @see DefaultOAuth2UserMixin
 */
public class DefaultOAuth2UserDeserializer extends JsonDeserializer<DefaultOAuth2User> {

	@Override
	public DefaultOAuth2User deserialize(JsonParser parser, DeserializationContext context)
			throws IOException, JacksonException {
		ObjectMapper mapper = (ObjectMapper) parser.getCodec();
		JsonNode defaultOAuth2UserNode = mapper.readTree(parser);
		Collection<? extends GrantedAuthority> authorities = JsonNodeUtils.findValue(defaultOAuth2UserNode,
				"authorities", JsonNodeUtils.GRANTED_AUTHORITY_COLLECTION, mapper);
		Map<String, Object> attributes = JsonNodeUtils.findValue(defaultOAuth2UserNode, "attributes",
				JsonNodeUtils.STRING_OBJECT_MAP, mapper);
		String name = JsonNodeUtils.findStringValue(defaultOAuth2UserNode, "name");
		if (name != null) {
			return new DefaultOAuth2User(attributes, authorities, name);
		}
		String nameAttributeKey = JsonNodeUtils.findStringValue(defaultOAuth2UserNode, "nameAttributeKey");
		return new DefaultOAuth2User(authorities, attributes, nameAttributeKey);
	}

}
