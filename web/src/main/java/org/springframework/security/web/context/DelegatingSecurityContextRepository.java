/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.context;

import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;

/**
 * @author Steve Riesenberg
 * @since 5.8
 */
class DelegatingSecurityContextRepository implements SecurityContextRepository {

	private final List<SecurityContextRepository> delegates;

	public DelegatingSecurityContextRepository(SecurityContextRepository... delegates) {
		this(Arrays.asList(delegates));
	}

	public DelegatingSecurityContextRepository(List<SecurityContextRepository> delegates) {
		this.delegates = delegates;
	}

	@Override
	public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
		return loadContext(requestResponseHolder.getRequest()).get();
	}

	@Override
	public Supplier<SecurityContext> loadContext(HttpServletRequest request) {
		Supplier<SecurityContext> supplier = null;
		for (SecurityContextRepository delegate : this.delegates) {
			if (supplier == null) {
				supplier = delegate.loadContext(request);
			}
			else {
				Supplier<SecurityContext> current = delegate.loadContext(request);
				supplier = new DelegatingSupplier(current, supplier);
			}
		}
		return supplier;
	}

	@Override
	public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
		throw new UnsupportedOperationException("saveContext() should be called directly on the desired SecurityContextRepository.");
	}

	@Override
	public boolean containsContext(HttpServletRequest request) {
		for (SecurityContextRepository delegate : this.delegates) {
			if (delegate.containsContext(request)) {
				return true;
			}
		}
		return false;
	}

	static class DelegatingSupplier implements Supplier<SecurityContext> {

		private final Supplier<SecurityContext> current;

		private final Supplier<SecurityContext> previous;

		DelegatingSupplier(Supplier<SecurityContext> current, Supplier<SecurityContext> previous) {
			this.current = current;
			this.previous = previous;
		}

		@Override
		public SecurityContext get() {
			SecurityContext securityContext = this.previous.get();
			if (!securityContext.isGenerated()) {
				return securityContext;
			}
			return this.current.get();
		}
	}

}
