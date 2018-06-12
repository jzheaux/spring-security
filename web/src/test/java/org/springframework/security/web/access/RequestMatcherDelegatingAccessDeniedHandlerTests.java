/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.access;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RequestMatcherDelegatingAccessDeniedHandlerTests {
	private RequestMatcherDelegatingAccessDeniedHandler delegator;
	private LinkedHashMap<RequestMatcher, AccessDeniedHandler> deniedHandlers;
	private AccessDeniedHandler accessDeniedHandler;
	private HttpServletRequest request = new MockHttpServletRequest();

	@Before
	public void before() {
		accessDeniedHandler = mock(AccessDeniedHandler.class);
		deniedHandlers = new LinkedHashMap<>();
	}

	@Test
	public void handleWhenNothingMatchesThenOnlyDefaultHandlerInvoked() throws Exception {
		AccessDeniedHandler handler = mock(AccessDeniedHandler.class);
		RequestMatcher matcher = mock(RequestMatcher.class);
		when(matcher.matches(request)).thenReturn(false);
		deniedHandlers.put(matcher, handler);
		delegator = new RequestMatcherDelegatingAccessDeniedHandler(deniedHandlers, accessDeniedHandler);

		delegator.handle(request, null, null);

		verify(accessDeniedHandler).handle(request, null, null);
		verify(handler, never()).handle(request, null, null);
	}

	@Test
	public void handleWhenFirstMatchesThenOnlyFirstInvoked() throws Exception {
		AccessDeniedHandler firstHandler = mock(AccessDeniedHandler.class);
		RequestMatcher firstMatcher = mock(RequestMatcher.class);
		AccessDeniedHandler secondHandler = mock(AccessDeniedHandler.class);
		RequestMatcher secondMatcher = mock(RequestMatcher.class);
		when(firstMatcher.matches(request)).thenReturn(true);
		deniedHandlers.put(firstMatcher, firstHandler);
		deniedHandlers.put(secondMatcher, secondHandler);
		delegator = new RequestMatcherDelegatingAccessDeniedHandler(deniedHandlers, accessDeniedHandler);

		delegator.handle(request, null, null);

		verify(firstHandler).handle(request, null, null);
		verify(secondHandler, never()).handle(request, null, null);
		verify(accessDeniedHandler, never()).handle(request, null, null);
		verify(secondMatcher, never()).matches(request);
	}

	@Test
	public void handleWhenSecondMatchesThenOnlySecondInvoked() throws Exception {
		AccessDeniedHandler firstHandler = mock(AccessDeniedHandler.class);
		RequestMatcher firstMatcher = mock(RequestMatcher.class);
		AccessDeniedHandler secondHandler = mock(AccessDeniedHandler.class);
		RequestMatcher secondMatcher = mock(RequestMatcher.class);
		when(firstMatcher.matches(request)).thenReturn(false);
		when(secondMatcher.matches(request)).thenReturn(true);
		deniedHandlers.put(firstMatcher, firstHandler);
		deniedHandlers.put(secondMatcher, secondHandler);
		delegator = new RequestMatcherDelegatingAccessDeniedHandler(deniedHandlers, accessDeniedHandler);

		delegator.handle(request, null, null);

		verify(secondHandler).handle(request, null, null);
		verify(firstHandler, never()).handle(request, null, null);
		verify(accessDeniedHandler, never()).handle(request, null, null);
	}
}
