package org.springframework.security.oauth2.client.oidc.web.authentication.logout;

import java.io.IOException;
import java.util.Collection;
import java.util.function.Function;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.oidc.authentication.logout.InMemoryOidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutTokenDecoder;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcProviderSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

public class OidcBackchannelLogoutFilter extends OncePerRequestFilter {
	private static final String ERROR_MESSAGE = "{ \"error\" : \"%s\", \"error_description\" : \"%s\" }";

	private final ClientRegistrationRepository clients;

	private final Function<ClientRegistration, OidcLogoutTokenDecoder> clientLogoutTokenDecoder;

	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/oauth2/{registrationId}/logout");

	private OidcProviderSessionRegistry providerSessionRegistry = new InMemoryOidcProviderSessionRegistry();

	private RestOperations rest = new RestTemplate();

	private String logoutEndpointName = "/logout";

	private String clientSessionCookieName = "JSESSIONID";

	public OidcBackchannelLogoutFilter(ClientRegistrationRepository clients, OidcLogoutTokenDecoder logoutTokenDecoder) {
		this.clients = clients;
		this.clientLogoutTokenDecoder = (registration) -> logoutTokenDecoder;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
		if (!result.isMatch()) {
			filterChain.doFilter(request, response);
			return;
		}
		String token = request.getParameter("logout_token");
		if (token == null) {
			filterChain.doFilter(request, response);
			return;
		}
		String registrationId = result.getVariables().get("registrationId");
		ClientRegistration registration = this.clients.findByRegistrationId(registrationId);
		try {
			OidcLogoutTokenDecoder logoutTokenDecoder = this.clientLogoutTokenDecoder.apply(registration);
			OidcLogoutToken logoutToken = logoutTokenDecoder.decode(token);
			Collection<String> sessions = this.providerSessionRegistry.getClientSessions(logoutToken);
			for (String session : sessions) {
				HttpHeaders headers = new HttpHeaders();
				headers.add("Cookie", this.clientSessionCookieName + "=" + session);
				this.rest.postForEntity(this.logoutEndpointName, headers, Object.class);
			}
		} catch (OAuth2AuthenticationException ex) {
			String message = String.format(ERROR_MESSAGE, "invalid_request", ex.getMessage());
			response.sendError(400, message);
		}
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	public void setProviderSessionRegistry(OidcProviderSessionRegistry providerSessionRegistry) {
		Assert.notNull(providerSessionRegistry, "providerSessionRegistry cannot be null");
		this.providerSessionRegistry = providerSessionRegistry;
	}

	public void setRestOperations(RestOperations rest) {
		Assert.notNull(rest, "rest cannot be null");
		this.rest = rest;
	}

	public void setLogoutEndpointName(String logoutEndpointName) {
		Assert.hasText(logoutEndpointName, "logoutEndpointName cannot be empty");
		this.logoutEndpointName = logoutEndpointName;
	}

	public void setClientSessionCookieName(String clientSessionCookieName) {
		Assert.hasText(clientSessionCookieName, "clientSessionCookieName cannot be empty");
		this.clientSessionCookieName = clientSessionCookieName;
	}
}
