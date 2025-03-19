package org.springframework.security.oauth2.core;

import java.util.Map;

/**
 * An interface that associates a token with a collection of named claims
 *
 * @author Josh Cummings
 * @since 6.5
 */
public interface OAuth2TokenClaims extends OAuth2Token {
	Map<String, Object> getClaims();
}
