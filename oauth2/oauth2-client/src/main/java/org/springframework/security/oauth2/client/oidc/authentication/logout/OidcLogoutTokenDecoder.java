package org.springframework.security.oauth2.client.oidc.authentication.logout;

public interface OidcLogoutTokenDecoder {
	OidcLogoutToken decode(String token);
}
