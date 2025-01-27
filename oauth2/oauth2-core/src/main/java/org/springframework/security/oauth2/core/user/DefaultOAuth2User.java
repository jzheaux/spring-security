/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.core.user;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

/**
 * The default implementation of an {@link OAuth2User}.
 *
 * <p>
 * User attribute names are <b>not</b> standardized between providers and therefore it is
 * required to supply the <i>key</i> for the user's &quot;name&quot; attribute to one of
 * the constructors. The <i>key</i> will be used for accessing the &quot;name&quot; of the
 * {@code Principal} (user) via {@link #getAttributes()} and returning it from
 * {@link #getName()}.
 *
 * @author Joe Grandja
 * @author Eddú Meléndez
 * @author Park Hyojong
 * @since 5.0
 * @see OAuth2User
 */
public class DefaultOAuth2User implements OAuth2User, Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final Set<GrantedAuthority> authorities;

	private final Map<String, Object> attributes;

	private final String nameAttributeKey;

	/**
	 * Constructs a {@code DefaultOAuth2User} using the provided parameters.
	 * @param authorities the authorities granted to the user
	 * @param attributes the attributes about the user
	 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
	 * {@link #getAttributes()}
	 */
	public DefaultOAuth2User(Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes,
			String nameAttributeKey) {
		Assert.notEmpty(attributes, "attributes cannot be empty");
		Assert.hasText(nameAttributeKey, "nameAttributeKey cannot be empty");
		Assert.notNull(attributes.get(nameAttributeKey),
				"Attribute value for '" + nameAttributeKey + "' cannot be null");
		this.authorities = (authorities != null)
				? Collections.unmodifiableSet(new LinkedHashSet<>(this.sortAuthorities(authorities)))
				: Collections.unmodifiableSet(new LinkedHashSet<>(AuthorityUtils.NO_AUTHORITIES));
		this.attributes = Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
		this.nameAttributeKey = nameAttributeKey;
	}

	/**
	 * Constructs a copy of the given {@code DefaultOidcUser}
	 *
	 * @param copy the instance to copy
	 * @since 6.5
	 */
	public DefaultOAuth2User(DefaultOAuth2User copy) {
		this(copy.authorities, copy.attributes, copy.nameAttributeKey);
	}

	@Override
	public String getName() {
		return this.getAttribute(this.nameAttributeKey).toString();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	private Set<GrantedAuthority> sortAuthorities(Collection<? extends GrantedAuthority> authorities) {
		SortedSet<GrantedAuthority> sortedAuthorities = new TreeSet<>(
				Comparator.comparing(GrantedAuthority::getAuthority));
		sortedAuthorities.addAll(authorities);
		return sortedAuthorities;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		DefaultOAuth2User that = (DefaultOAuth2User) obj;
		if (!this.getName().equals(that.getName())) {
			return false;
		}
		if (!this.getAuthorities().equals(that.getAuthorities())) {
			return false;
		}
		return this.getAttributes().equals(that.getAttributes());
	}

	@Override
	public int hashCode() {
		int result = this.getName().hashCode();
		result = 31 * result + this.getAuthorities().hashCode();
		result = 31 * result + this.getAttributes().hashCode();
		return result;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("Name: [");
		sb.append(this.getName());
		sb.append("], Granted Authorities: [");
		sb.append(getAuthorities());
		sb.append("], User Attributes: [");
		sb.append(getAttributes());
		sb.append("]");
		return sb.toString();
	}

	/**
	 * Return a builder in order to construct a copy of this object.
	 *
	 * @return a {@link Builder} for copying
	 * @since 6.5
	 */
	public Builder<?> mutate() {
		return new Builder<>(this);
	}

	/**
	 * A builder for {@link DefaultOAuth2User}.
	 *
	 * @since 6.5
	 */
	public static class Builder<B extends Builder<B>> {

		protected String nameAttributeKey = OAuth2ParameterNames.USERNAME;

		private Map<String, Object> attributes;

		protected Collection<? extends GrantedAuthority> authorities = AuthorityUtils.NO_AUTHORITIES;

		protected Builder() {
		}

		private Builder(DefaultOAuth2User user) {
			this.nameAttributeKey = user.nameAttributeKey;
			this.attributes = user.getAttributes();
			this.authorities = user.getAuthorities();
		}

		/**
		 * Sets the key used to access the user's &quot;name&quot; from the user
		 * attributes if no &quot;name&quot; is provided.
		 * @param nameAttributeKey the key used to access the user's &quot;name&quot; from
		 * the user attributes.
		 * @return the {@link Builder}
		 */
		public B nameAttributeKey(String nameAttributeKey) {
			this.nameAttributeKey = nameAttributeKey;
			return (B) this;
		}

		/**
		 * Sets the attributes about the user.
		 * @param attributes the attributes about the user
		 * @return the {@link Builder}
		 */
		public B attributes(Map<String, Object> attributes) {
			this.attributes = attributes;
			return (B) this;
		}

		/**
		 * Sets the authorities granted to the user.
		 * @param authorities the authorities granted to the user
		 * @return the {@link Builder}
		 */
		public B authorities(Collection<? extends GrantedAuthority> authorities) {
			Assert.notNull(authorities, "authorities cannot be null");
			this.authorities = authorities;
			return (B) this;
		}

		/**
		 * Builds a new {@link DefaultOAuth2User}.
		 * @return a {@link DefaultOAuth2User}
		 */
		public DefaultOAuth2User build() {
			return new DefaultOAuth2User(this.authorities, this.attributes, this.nameAttributeKey);
		}

	}

}
