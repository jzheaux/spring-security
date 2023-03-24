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

package org.springframework.security.web.server;

import java.util.ArrayList;
import java.util.List;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.ObservationTextPublisher;
import io.micrometer.observation.contextpropagation.ObservationThreadLocalAccessor;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link ObservationWebFilterChainDecorator}
 */
public class ObservationWebFilterChainDecoratorTests {

	@Test
	void decorateWhenDefaultsThenObserves() {
		AccumulatingObservationHandler handler = new AccumulatingObservationHandler();
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(new ObservationTextPublisher());
		ObservationWebFilterChainDecorator decorator = new ObservationWebFilterChainDecorator(registry);
		WebFilter mock = mock(WebFilter.class);
		given(mock.filter(any(), any())).willReturn(Mono.empty());
		WebFilterChain chain = mock(WebFilterChain.class);
		given(chain.filter(any())).willReturn(Mono.empty());
		WebFilterChain decorated = decorator.decorate(chain, List.of((e, c) -> {
			return c.filter(e).then(Mono.deferContextual((context) -> {
				Observation parentObservation = context.getOrDefault(ObservationThreadLocalAccessor.KEY, null);
				Observation observation = Observation.createNotStarted("custom", registry).parentObservation(parentObservation).start();
				return Mono.just("3")
						.doOnSuccess((v) -> observation.stop())
						.doOnCancel(observation::stop)
						.doOnError((t) -> {
							observation.error(t);
							observation.stop();
						}).then(Mono.empty());
			}));
		}));
		Observation http = Observation.start("http", registry);
		try {
			decorated.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/").build()))
					.contextWrite(context -> context.put(ObservationThreadLocalAccessor.KEY, http))
					.block();
		} finally {
			http.stop();
		}
	}

	@Test
	void decorateWhenNoopThenDoesNotObserve() {
		ObservationHandler<?> handler = mock(ObservationHandler.class);
		given(handler.supportsContext(any())).willReturn(true);
		ObservationRegistry registry = ObservationRegistry.NOOP;
		registry.observationConfig().observationHandler(handler);
		ObservationWebFilterChainDecorator decorator = new ObservationWebFilterChainDecorator(registry);
		WebFilterChain chain = mock(WebFilterChain.class);
		given(chain.filter(any())).willReturn(Mono.empty());
		WebFilterChain decorated = decorator.decorate(chain);
		decorated.filter(MockServerWebExchange.from(MockServerHttpRequest.get("/").build())).block();
		verifyNoInteractions(handler);
	}

	private static class AccumulatingObservationHandler implements ObservationHandler<Observation.Context> {
		List<Event> contexts = new ArrayList<>();

		@Override
		public boolean supportsContext(Observation.Context context) {
			return true;
		}

		@Override
		public void onStart(Observation.Context context) {
			this.contexts.add(new Event("start", context));
		}

		@Override
		public void onError(Observation.Context context) {
			this.contexts.add(new Event("error", context));
		}

		@Override
		public void onEvent(Observation.Event event, Observation.Context context) {
			this.contexts.add(new Event("event", context));
		}

		@Override
		public void onScopeOpened(Observation.Context context) {
			this.contexts.add(new Event("opened", context));
		}

		@Override
		public void onScopeClosed(Observation.Context context) {
			this.contexts.add(new Event("closed", context));
		}

		@Override
		public void onScopeReset(Observation.Context context) {
			this.contexts.add(new Event("reset", context));
		}

		@Override
		public void onStop(Observation.Context context) {
			this.contexts.add(new Event("stop", context));
		}

		private static class Event {
			final String name;
			final Observation.Context context;

			public Event(String name, Observation.Context context) {
				this.name = name;
				this.context = context;
			}
		}
	}

}
