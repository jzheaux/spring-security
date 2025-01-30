package org.springframework.security.web.authorization;

import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

public class AuthorizationManagerRequestMatcherRegistry {

	private RequestMatcherDelegatingAuthorizationManager.Builder builder = RequestMatcherDelegatingAuthorizationManager.builder();

	public Condition allow() {
		return new Condition(this.builder, (a, c) -> new AuthorizationDecision(true));
	}

	public Condition allow(AuthorizationManager<RequestAuthorizationContext> manager) {
		return new Condition(this.builder, manager);
	}

	public Condition deny() {
		return new Condition(this.builder, (a, c) -> new AuthorizationDecision(false));
	}

	public Condition deny(AuthorizationManager<RequestAuthorizationContext> manager) {
		return new Condition(this.builder, manager);
	}

	public static class Condition {
		private final AuthorizationManager<RequestAuthorizationContext> manager;

		private final RequestMatcherDelegatingAuthorizationManager.Builder builder;

		Condition(RequestMatcherDelegatingAuthorizationManager.Builder builder, AuthorizationManager<RequestAuthorizationContext> manager) {
			this.builder = builder;
			this.manager = manager;
		}

		void anyRequest() {
			this.builder.add(AnyRequestMatcher.INSTANCE, this.manager);
		}

		void requests(HttpMethod method, String... patterns) {
			for (String pattern : patterns) {
				this.builder.add(pathPattern(method, pattern), this.manager);
			}
		}

		void requests(String... patterns) {
			requests(null, patterns);
		}

		void requests(RequestMatcher... matchers) {
			for (RequestMatcher matcher : matchers) {
				this.builder.add(matcher, this.manager);
			}
		}
	}

}
