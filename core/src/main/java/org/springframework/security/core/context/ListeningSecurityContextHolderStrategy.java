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

package org.springframework.security.core.context;

import java.util.Arrays;
import java.util.Collection;

import org.springframework.util.Assert;

/**
 * An API for notifying when the {@link SecurityContext} changes.
 *
 * Note that this does not notify when the underlying authentication changes. To get
 * notified about authentication changes, ensure that you are using {@link #setContext}
 * when changing the authentication like so:
 *
 * <pre>
 *	SecurityContext context = SecurityContextHolder.createEmptyContext();
 *	context.setAuthentication(authentication);
 *	SecurityContextHolder.setContext(context);
 * </pre>
 *
 * To add a listener to the existing {@link SecurityContextHolder}, you can do:
 *
 * <pre>
 *  SecurityContextHolderStrategy original = SecurityContextHolder.getContextHolderStrategy();
 *  SecurityContextChangedListener listener = new YourListener();
 *  SecurityContextHolderStrategy strategy = new ListeningSecurityContextHolderStrategy(original, listener);
 *  SecurityContextHolder.setContextHolderStrategy(strategy);
 * </pre>
 *
 * NOTE: Any object that you supply to the {@link SecurityContextHolder} is now part of
 * the static context and as such will not get garbage collected. To remove the reference,
 * {@link SecurityContextHolder#setContextHolderStrategy reset the strategy} like so:
 *
 * <pre>
 *   SecurityContextHolder.setContextHolderStrategy(original);
 * </pre>
 *
 * This will then allow {@code YourListener} and its members to be garbage collected.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class ListeningSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	private final Collection<SecurityContextChangedListener> listeners;

	private final SecurityContextHolderStrategy delegate;

	/**
	 * Construct a {@link ListeningSecurityContextHolderStrategy} based on a
	 * {@link ThreadLocalSecurityContextHolderStrategy}
	 * @param listeners the listeners that should be notified when the
	 * {@link SecurityContext} is {@link #setContext(SecurityContext) set} or
	 * {@link #clearContext() cleared}
	 * @since 5.7
	 */
	public ListeningSecurityContextHolderStrategy(
			Collection<SecurityContextChangedListener> listeners) {
		this(new ThreadLocalSecurityContextHolderStrategy(), listeners);
	}

	/**
	 * Construct a {@link ListeningSecurityContextHolderStrategy}
	 * @param listeners the listeners that should be notified when the
	 * {@link SecurityContext} is {@link #setContext(SecurityContext) set} or
	 * {@link #clearContext() cleared}
	 * @param delegate the underlying {@link SecurityContextHolderStrategy}
	 */
	public ListeningSecurityContextHolderStrategy(SecurityContextHolderStrategy delegate,
			Collection<SecurityContextChangedListener> listeners) {
		Assert.notNull(delegate, "securityContextHolderStrategy cannot be null");
		Assert.notNull(listeners, "securityContextChangedListeners cannot be null");
		Assert.notEmpty(listeners, "securityContextChangedListeners cannot be empty");
		Assert.noNullElements(listeners, "securityContextChangedListeners cannot contain null elements");
		this.delegate = delegate;
		this.listeners = listeners;
	}

	/**
	 * Construct a {@link ListeningSecurityContextHolderStrategy}
	 * @param listeners the listeners that should be notified when the
	 * {@link SecurityContext} is {@link #setContext(SecurityContext) set} or
	 * {@link #clearContext() cleared}
	 * @param delegate the underlying {@link SecurityContextHolderStrategy}
	 */
	public ListeningSecurityContextHolderStrategy(SecurityContextHolderStrategy delegate,
			SecurityContextChangedListener... listeners) {
		Assert.notNull(delegate, "securityContextHolderStrategy cannot be null");
		Assert.notNull(listeners, "securityContextChangedListeners cannot be null");
		Assert.notEmpty(listeners, "securityContextChangedListeners cannot be empty");
		Assert.noNullElements(listeners, "securityContextChangedListeners cannot contain null elements");
		this.delegate = delegate;
		this.listeners = Arrays.asList(listeners);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void clearContext() {
		SecurityContext from = getContext();
		this.delegate.clearContext();
		publish(from, null);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SecurityContext getContext() {
		return this.delegate.getContext();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setContext(SecurityContext context) {
		SecurityContext from = getContext();
		this.delegate.setContext(context);
		publish(from, context);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SecurityContext createEmptyContext() {
		return this.delegate.createEmptyContext();
	}

	private void publish(SecurityContext previous, SecurityContext current) {
		if (previous == current) {
			return;
		}
		SecurityContextChangedEvent event = new SecurityContextChangedEvent(previous, current);
		for (SecurityContextChangedListener listener : this.listeners) {
			listener.securityContextChanged(event);
		}
	}

}
