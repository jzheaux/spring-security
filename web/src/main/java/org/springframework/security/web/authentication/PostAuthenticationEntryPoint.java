package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FormPostRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

public final class PostAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private final String entryPointUri;

	private final Map<String, Function<Authentication, String>> params;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private RedirectStrategy redirectStrategy = new FormPostRedirectStrategy();

	public PostAuthenticationEntryPoint(String entryPointUri, Map<String, Function<Authentication, String>> params) {
		this.entryPointUri = entryPointUri;
		this.params = params;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		Authentication authentication = getAuthentication(authException);
		Assert.notNull(authentication, "could not find authentication in order to perform post");
		Map<String, String> params = this.params.entrySet()
			.stream()
			.collect(Collectors.toMap(Map.Entry::getKey, (entry) -> entry.getValue().apply(authentication)));
		CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		if (csrf != null) {
			params.put(csrf.getParameterName(), csrf.getToken());
		}
		String entryPointUrl = UriComponentsBuilder.fromPath(this.entryPointUri)
			.build(false)
			.expand(params)
			.toUriString();
		this.redirectStrategy.sendRedirect(request, response, entryPointUrl);
	}

	private Authentication getAuthentication(AuthenticationException authException) {
		Authentication authentication = authException.getAuthenticationRequest();
		if (authentication != null && authentication.isAuthenticated()) {
			return authentication;
		}
		authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (authentication != null && authentication.isAuthenticated()) {
			return authentication;
		}
		return null;
	}

	private static final class Root {

		private final Authentication authentication;

		private Root(Authentication authentication) {
			this.authentication = authentication;
		}

		public Authentication getAuthentication() {
			return this.authentication;
		}

	}

}
