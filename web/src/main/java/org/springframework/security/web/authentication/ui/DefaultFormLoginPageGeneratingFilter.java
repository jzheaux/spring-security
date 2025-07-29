/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.authentication.ui;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * For internal use with namespace configuration in the case where a user doesn't
 * configure a login page. The configuration code will insert this filter in the chain
 * instead.
 *
 * Will only work if a redirect is used to the login page.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class DefaultFormLoginPageGeneratingFilter extends GenericFilterBean {

	public static final String DEFAULT_LOGIN_PAGE_URL = "/login/form";

	public static final String ERROR_PARAMETER_NAME = "error";

	private String loginPageUrl;

	private String logoutSuccessUrl;

	private String failureUrl;

	private String authenticationUrl;

	private String usernameParameter;

	private String passwordParameter;

	private String rememberMeParameter;

	private Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs = (request) -> Collections.emptyMap();

	private Function<HttpServletRequest, Map<String, String>> resolveHeaders = (request) -> Collections.emptyMap();

	public DefaultFormLoginPageGeneratingFilter() {
	}

	public DefaultFormLoginPageGeneratingFilter(UsernamePasswordAuthenticationFilter authFilter) {
		this.loginPageUrl = DEFAULT_LOGIN_PAGE_URL;
		this.logoutSuccessUrl = DEFAULT_LOGIN_PAGE_URL + "?logout";
		this.failureUrl = DEFAULT_LOGIN_PAGE_URL + "?" + ERROR_PARAMETER_NAME;
		if (authFilter != null) {
			initAuthFilter(authFilter);
		}
	}

	private void initAuthFilter(UsernamePasswordAuthenticationFilter authFilter) {
		this.usernameParameter = authFilter.getUsernameParameter();
		this.passwordParameter = authFilter.getPasswordParameter();
		if (authFilter.getRememberMeServices() instanceof AbstractRememberMeServices rememberMeServices) {
			this.rememberMeParameter = rememberMeServices.getParameter();
		}
	}

	/**
	 * Sets a Function used to resolve a Map of the hidden inputs where the key is the
	 * name of the input and the value is the value of the input. Typically this is used
	 * to resolve the CSRF token.
	 * @param resolveHiddenInputs the function to resolve the inputs
	 */
	public void setResolveHiddenInputs(Function<HttpServletRequest, Map<String, String>> resolveHiddenInputs) {
		Assert.notNull(resolveHiddenInputs, "resolveHiddenInputs cannot be null");
		this.resolveHiddenInputs = resolveHiddenInputs;
	}

	/**
	 * Sets a Function used to resolve a Map of the HTTP headers where the key is the name
	 * of the header and the value is the value of the header. Typically, this is used to
	 * resolve the CSRF token.
	 * @param resolveHeaders the function to resolve the headers
	 */
	public void setResolveHeaders(Function<HttpServletRequest, Map<String, String>> resolveHeaders) {
		Assert.notNull(resolveHeaders, "resolveHeaders cannot be null");
		this.resolveHeaders = resolveHeaders;
	}

	public void setLogoutSuccessUrl(String logoutSuccessUrl) {
		this.logoutSuccessUrl = logoutSuccessUrl;
	}

	public String getLoginPageUrl() {
		return this.loginPageUrl;
	}

	public void setLoginPageUrl(String loginPageUrl) {
		this.loginPageUrl = loginPageUrl;
	}

	public void setFailureUrl(String failureUrl) {
		this.failureUrl = failureUrl;
	}

	public void setAuthenticationUrl(String authenticationUrl) {
		this.authenticationUrl = authenticationUrl;
	}

	public void setUsernameParameter(String usernameParameter) {
		this.usernameParameter = usernameParameter;
	}

	public void setPasswordParameter(String passwordParameter) {
		this.passwordParameter = passwordParameter;
	}

	public void setRememberMeParameter(String rememberMeParameter) {
		this.rememberMeParameter = rememberMeParameter;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		boolean loginError = isErrorPage(request);
		boolean logoutSuccess = isLogoutSuccess(request);
		if (isLoginUrlRequest(request) || loginError || logoutSuccess) {
			String loginPageHtml = generateLoginPageHtml(request, loginError, logoutSuccess);
			response.setContentType("text/html;charset=UTF-8");
			response.setContentLength(loginPageHtml.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(loginPageHtml);
			return;
		}
		chain.doFilter(request, response);
	}

	private String generateLoginPageHtml(HttpServletRequest request, boolean loginError, boolean logoutSuccess) {
		String errorMsg = "Invalid credentials";
		String contextPath = request.getContextPath();

		return HtmlTemplates.fromTemplate(LOGIN_PAGE_TEMPLATE)
			.withRawHtml("contextPath", contextPath)
			.withRawHtml("formLogin", renderFormLogin(request, loginError, logoutSuccess, contextPath, errorMsg))
			.render();
	}

	private String renderFormLogin(HttpServletRequest request, boolean loginError, boolean logoutSuccess,
			String contextPath, String errorMsg) {
		String hiddenInputs = this.resolveHiddenInputs.apply(request)
			.entrySet()
			.stream()
			.map((inputKeyValue) -> renderHiddenInput(inputKeyValue.getKey(), inputKeyValue.getValue()))
			.collect(Collectors.joining("\n"));

		return HtmlTemplates.fromTemplate(LOGIN_FORM_TEMPLATE)
			.withValue("loginUrl", contextPath + this.authenticationUrl)
			.withRawHtml("errorMessage", renderError(loginError, errorMsg))
			.withRawHtml("logoutMessage", renderSuccess(logoutSuccess))
			.withValue("usernameParameter", this.usernameParameter)
			.withValue("passwordParameter", this.passwordParameter)
			.withRawHtml("rememberMeInput", renderRememberMe(this.rememberMeParameter))
			.withRawHtml("hiddenInputs", hiddenInputs)
			.render();
	}

	private String renderHiddenInput(String name, String value) {
		return HtmlTemplates.fromTemplate(HIDDEN_HTML_INPUT_TEMPLATE)
			.withValue("name", name)
			.withValue("value", value)
			.render();
	}

	private String renderRememberMe(String paramName) {
		if (paramName == null) {
			return "";
		}
		return HtmlTemplates
			.fromTemplate("<p><input type='checkbox' name='{{paramName}}'/> Remember me on this computer.</p>")
			.withValue("paramName", paramName)
			.render();
	}

	private boolean isLogoutSuccess(HttpServletRequest request) {
		return this.logoutSuccessUrl != null && matches(request, this.logoutSuccessUrl);
	}

	private boolean isLoginUrlRequest(HttpServletRequest request) {
		return matches(request, this.loginPageUrl);
	}

	private boolean isErrorPage(HttpServletRequest request) {
		return matches(request, this.failureUrl);
	}

	private String renderError(boolean isError, String message) {
		if (!isError) {
			return "";
		}
		return HtmlTemplates.fromTemplate(ALERT_TEMPLATE).withValue("message", message).render();
	}

	private String renderSuccess(boolean isLogoutSuccess) {
		if (!isLogoutSuccess) {
			return "";
		}
		return "<div class=\"alert alert-success\" role=\"alert\">You have been signed out</div>";
	}

	private boolean matches(HttpServletRequest request, String url) {
		if (!"GET".equals(request.getMethod()) || url == null) {
			return false;
		}
		String uri = request.getRequestURI();
		int pathParamIndex = uri.indexOf(';');
		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}
		if (request.getQueryString() != null) {
			uri += "?" + request.getQueryString();
		}
		if ("".equals(request.getContextPath())) {
			return uri.equals(url);
		}
		return uri.equals(request.getContextPath() + url);
	}

	private static final String LOGIN_PAGE_TEMPLATE = """
			<!DOCTYPE html>
			<html lang="en">
			  <head>
			    <meta charset="utf-8">
			    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
			    <meta name="description" content="">
			    <meta name="author" content="">
			    <title>Please sign in</title>
			    <link href="{{contextPath}}/default-ui.css" rel="stylesheet" />{{javaScript}}
			  </head>
			  <body>
			    <div class="content">
			{{formLogin}}
			    </div>
			  </body>
			</html>""";

	private static final String LOGIN_FORM_TEMPLATE = """
			      <form class="login-form" method="post" action="{{loginUrl}}">
			        <h2>Please sign in</h2>
			{{errorMessage}}{{logoutMessage}}
			        <p>
			          <label for="username" class="screenreader">Username</label>
			          <input type="text" id="username" name="{{usernameParameter}}" placeholder="Username" required autofocus>
			        </p>
			        <p>
			          <label for="password" class="screenreader">Password</label>
			          <input type="password" id="password" name="{{passwordParameter}}" placeholder="Password" {{autocomplete}}required>
			        </p>
			{{rememberMeInput}}
			{{hiddenInputs}}
			        <button type="submit" class="primary">Sign in</button>
			      </form>""";

	private static final String HIDDEN_HTML_INPUT_TEMPLATE = """
			<input name="{{name}}" type="hidden" value="{{value}}" />
			""";

	private static final String ALERT_TEMPLATE = """
			<div class="alert alert-danger" role="alert">{{message}}</div>""";

}
