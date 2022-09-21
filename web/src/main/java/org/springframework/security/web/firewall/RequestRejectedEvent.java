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

package org.springframework.security.web.firewall;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.event.FailureEvent;
import org.springframework.security.event.SecurityEvent;

public class RequestRejectedEvent extends SecurityEvent implements FailureEvent<RequestRejectedException> {

	private final RequestRejectedException exception;

	public RequestRejectedEvent(HttpServletRequest request, RequestRejectedException exception) {
		super(request);
		this.exception = exception;
	}

	public RequestRejectedException getError() {
		return this.exception;
	}

}
