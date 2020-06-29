package sample;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;

@Configuration
public class SecurityConfig {
	@Autowired
	AuthnRequestBuilder authnRequestBuilder;

	@Autowired
	IssuerBuilder issuerBuilder;

	@Bean
	Saml2AuthenticationRequestFactory authenticationRequestFactory() {
		OpenSamlAuthenticationRequestFactory factory = new OpenSamlAuthenticationRequestFactory();
		factory.setAuthenticationRequestContextConverter(context -> {
			Issuer issuer = issuerBuilder.buildObject();
			issuer.setValue(context.getIssuer());

			AuthnRequest authnRequest = this.authnRequestBuilder.buildObject();
			authnRequest.setIssuer(issuer);
			authnRequest.setDestination(context.getDestination());
			authnRequest.setAssertionConsumerServiceURL(context.getAssertionConsumerServiceUrl());

			authnRequest.setForceAuthn(true);

			return authnRequest;
		});
		return factory;
	}
}
