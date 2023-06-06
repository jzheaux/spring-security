/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core.session;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * Represents a record of a session within the Spring Security framework.
 * <p>
 * This is primarily used for concurrent session support.
 * <p>
 * Sessions have three states: active, expired, and destroyed. A session can that is
 * invalidated by <code>session.invalidate()</code> or via Servlet Container management is
 * considered "destroyed". An "expired" session, on the other hand, is a session that
 * Spring Security wants to end because it was selected for removal for some reason
 * (generally as it was the least recently used session and the maximum sessions for the
 * user were reached). An "expired" session is removed as soon as possible by a
 * <code>Filter</code>.
 *
 * @author Ben Alex
 */
public class SessionInformation implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private Date lastRequest;

	private final Object principal;

	private final String sessionId;

	private final Map<String, Object> attributes;

	private boolean expired = false;

	public SessionInformation(Object principal, String sessionId, Map<String, Object> attributes) {
		this(principal, sessionId, new Date(), attributes);
	}

	public SessionInformation(Object principal, String sessionId, Date lastRequest) {
		this(principal, sessionId, lastRequest, new HashMap<>());
	}

	private SessionInformation(Object principal, String sessionId, Date lastRequest, Map<String, Object> attributes) {
		Assert.notNull(principal, "Principal required");
		Assert.hasText(sessionId, "SessionId required");
		Assert.notNull(lastRequest, "LastRequest required");
		Assert.notNull(lastRequest, "Attributes required");
		this.principal = principal;
		this.sessionId = sessionId;
		this.lastRequest = lastRequest;
		this.attributes = attributes;
	}

	public void expireNow() {
		this.expired = true;
	}

	public Date getLastRequest() {
		return this.lastRequest;
	}

	public Object getPrincipal() {
		return this.principal;
	}

	public String getSessionId() {
		return this.sessionId;
	}

	public boolean isExpired() {
		return this.expired;
	}

	@SuppressWarnings("unchecked")
	public <T> T getAttribute(String name) {
		return (T) this.attributes.get(name);
	}

	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	/**
	 * Refreshes the internal lastRequest to the current date and time.
	 */
	public void refreshLastRequest() {
		this.lastRequest = new Date();
	}

}
