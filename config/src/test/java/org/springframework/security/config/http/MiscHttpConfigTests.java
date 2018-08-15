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

package org.springframework.security.config.http;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Iterator;
import java.util.List;
import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import org.assertj.core.api.iterable.Extractor;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.stubbing.Answer;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.security.BeanNameCollectingPostProcessor;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


/**
 *
 * @author Luke Taylor
 * @author Rob Winch
 */
public class MiscHttpConfigTests {
	private static final String CONFIG_LOCATION_PREFIX =
			"classpath:org/springframework/security/config/http/MiscHttpConfigTests";

	@Autowired
	MockMvc mvc;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	public void configureWhenUsingMinimalConfigurationThenParses() {
		this.spring.configLocations(xml("MinimalConfiguration")).autowire();
	}

	@Test
	public void configureWhenUsingAutoConfigThenSetsUpCorrectFilterList() {
		this.spring.configLocations(xml("AutoConfig")).autowire();
		assertThatFiltersMatchExpectedAutoConfigList();
	}

	@Test
	public void configureWhenUsingSecurityNoneThenNoFiltersAreSetUp() {
		this.spring.configLocations(xml("NoSecurityForPattern")).autowire();
		assertThat(getFilters("/unprotected")).isEmpty();
	}

	@Test
	public void requestWhenUsingDebugFilterAndPatternIsNotConfigureForSecurityThenRespondsOk()
			throws Exception {

		this.spring.configLocations(xml("NoSecurityForPattern")).autowire();

		this.mvc.perform(get("/unprotected"))
			.andExpect(status().isNotFound());

		this.mvc.perform(get("/nomatch"))
				.andExpect(status().isNotFound());
	}

	@Test
	public void requestWhenHttpPatternUsesRegexMatchingThenMatchesAccordingly()
			throws Exception {

		this.spring.configLocations(xml("RegexSecurityPattern")).autowire();

		this.mvc.perform(get("/protected"))
				.andExpect(status().isUnauthorized());

		this.mvc.perform(get("/unprotected"))
				.andExpect(status().isNotFound());
	}

	@Test
	public void requestWhenHttpPatternUsesCiRegexMatchingThenMatchesAccordingly()
			throws Exception {

		this.spring.configLocations(xml("CiRegexSecurityPattern")).autowire();

		this.mvc.perform(get("/ProTectEd"))
				.andExpect(status().isUnauthorized());

		this.mvc.perform(get("/UnProTectEd"))
				.andExpect(status().isNotFound());
	}

	@Test
	public void requestWhenHttpPatternUsesCustomRequestMatcherThenMatchesAccordingly()
			throws Exception {

		this.spring.configLocations(xml("CustomRequestMatcher")).autowire();

		this.mvc.perform(get("/protected"))
				.andExpect(status().isUnauthorized());

		this.mvc.perform(get("/unprotected"))
				.andExpect(status().isNotFound());
	}

	/**
	 * SEC-1152
	 */
	@Test
	public void requestWhenUsingMinimalConfigurationThenHonorsAnonymousEndpoints()
			throws Exception {

		this.spring.configLocations(xml("AnonymousEndpoints")).autowire();

		this.mvc.perform(get("/protected"))
				.andExpect(status().isUnauthorized());

		this.mvc.perform(get("/unprotected"))
				.andExpect(status().isNotFound());

		assertThat(getFilter(AnonymousAuthenticationFilter.class)).isNotNull();
	}

	@Test
	public void requestWhenAnonymousIsDisabledThenRejectsAnonymousEndpoints()
			throws Exception {

		this.spring.configLocations(xml("AnonymousDisabled")).autowire();

		this.mvc.perform(get("/protected"))
				.andExpect(status().isUnauthorized());

		this.mvc.perform(get("/unprotected"))
				.andExpect(status().isUnauthorized());

		assertThat(getFilter(AnonymousAuthenticationFilter.class)).isNull();
	}

	@Test
	public void requestWhenAnonymousUsesCustomAttributesThenRespondsWithThoseAttributes()
			throws Exception {

		this.spring.configLocations(xml("AnonymousCustomAttributes")).autowire();

		this.mvc.perform(get("/protected")
				.with(httpBasic("user", "password")))
				.andExpect(status().isForbidden());

		this.mvc.perform(get("/protected"))
				.andExpect(status().isOk())
				.andExpect(content().string("josh"));

		this.mvc.perform(get("/customKey"))
				.andExpect(status().isOk())
				.andExpect(content().string(String.valueOf("myCustomKey".hashCode())));
	}

	@Test
	public void requestWhenAnonymousUsesMultipleGrantedAuthoritiesThenRespondsWithThoseAttributes()
			throws Exception {

		this.spring.configLocations(xml("AnonymousMultipleAuthorities")).autowire();

		this.mvc.perform(get("/protected")
				.with(httpBasic("user", "password")))
				.andExpect(status().isForbidden());

		this.mvc.perform(get("/protected"))
				.andExpect(status().isOk())
				.andExpect(content().string("josh"));

		this.mvc.perform(get("/customKey"))
				.andExpect(status().isOk())
				.andExpect(content().string(String.valueOf("myCustomKey".hashCode())));
	}

	@Test
	public void requestWhenInterceptUrlMatchesMethodThenSecuresAccordingly()
			throws Exception {

		this.spring.configLocations(xml("InterceptUrlMethod")).autowire();

		this.mvc.perform(get("/protected")
				.with(httpBasic("user", "password")))
				.andExpect(status().isOk());

		this.mvc.perform(post("/protected")
				.with(httpBasic("user", "password")))
				.andExpect(status().isForbidden());

		this.mvc.perform(post("/protected")
				.with(httpBasic("poster", "password")))
				.andExpect(status().isOk());

		this.mvc.perform(delete("/protected")
				.with(httpBasic("poster", "password")))
				.andExpect(status().isForbidden());

		this.mvc.perform(delete("/protected")
				.with(httpBasic("admin", "password")))
				.andExpect(status().isOk());
	}

	@Test
	public void requestWhenInterceptUrlMatchesMethodAndRequiresHttpsThenSecuresAccordingly()
			throws Exception {

		this.spring.configLocations(xml("InterceptUrlMethodRequiresHttps")).autowire();

		this.mvc.perform(post("/protected").with(csrf()))
				.andExpect(status().isOk());

		this.mvc.perform(get("/protected")
				.secure(true)
				.with(httpBasic("user", "password")))
				.andExpect(status().isForbidden());

		this.mvc.perform(get("/protected")
				.secure(true)
				.with(httpBasic("admin", "password")))
				.andExpect(status().isOk());
	}

	@Test
	public void requestWhenInterceptUrlMatchesAnyPatternAndRequiresHttpsThenSecuresAccordingly()
			throws Exception {

		this.spring.configLocations(xml("InterceptUrlMethodRequiresHttpsAny")).autowire();

		this.mvc.perform(post("/protected").with(csrf()))
				.andExpect(status().isOk());

		this.mvc.perform(get("/protected")
				.secure(true)
				.with(httpBasic("user", "password")))
				.andExpect(status().isForbidden());

		this.mvc.perform(get("/protected")
				.secure(true)
				.with(httpBasic("admin", "password")))
				.andExpect(status().isOk());
	}

	@Test
	public void configureWhenOncePerRequestIsFalseThenFilterSecurityInterceptorExercisedForForwards() {
		this.spring.configLocations(xml("OncePerRequest")).autowire();

		FilterSecurityInterceptor filterSecurityInterceptor = getFilter(FilterSecurityInterceptor.class);
		assertThat(filterSecurityInterceptor.isObserveOncePerRequest()).isFalse();
	}

	@Test
	public void requestWhenCustomHttpBasicEntryPointRefThenInvokesOnCommence()
			throws Exception {

		this.spring.configLocations(xml("CustomHttpBasicEntryPointRef")).autowire();

		AuthenticationEntryPoint entryPoint = this.spring.getContext().getBean(AuthenticationEntryPoint.class);

		this.mvc.perform(get("/protected"))
			.andExpect(status().isOk());

		verify(entryPoint).commence(
				any(HttpServletRequest.class), any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	@Test
	public void configureWhenInterceptUrlWithRequiresChannelThenAddedChannelFilterToChain() {
		this.spring.configLocations(xml("InterceptUrlMethodRequiresHttpsAny")).autowire();
		assertThat(getFilter(ChannelProcessingFilter.class)).isNotNull();
	}

	@Test
	public void getWhenPortsMappedThenRedirectedAccordingly() throws Exception {
		this.spring.configLocations(xml("PortsMappedInterceptUrlMethodRequiresAny")).autowire();

		this.mvc.perform(get("http://localhost:9080/protected"))
				.andExpect(redirectedUrl("https://localhost:9443/protected"));
	}

	@Test
	public void configureWhenCustomFiltersThenAddedToChainInCorrectOrder() {
		System.setProperty("customFilterRef", "userFilter");
		this.spring.configLocations(xml("CustomFilters")).autowire();

		List<Filter> filters = getFilters("/");

		Class<?> userFilterClass = this.spring.getContext().getBean("userFilter").getClass();

		assertThat(filters)
				.extracting((Extractor<Filter, Class<?>>) filter -> filter.getClass())
				.containsSubsequence(
						userFilterClass, userFilterClass,
						SecurityContextPersistenceFilter.class, LogoutFilter.class,
						userFilterClass);
	}

	@Test
	public void configureWhenTwoFiltersWithSameOrderThenException() {
		assertThatCode(() -> this.spring.configLocations(xml("CollidingFilters")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenUsingX509ThenAddsX509FilterCorrectly() {
		this.spring.configLocations(xml("X509")).autowire();

		assertThat(getFilters("/"))
				.extracting((Extractor<Filter, Class<?>>) filter -> filter.getClass())
				.containsSubsequence(
						CsrfFilter.class, X509AuthenticationFilter.class, ExceptionTranslationFilter.class);
	}


	@Test
	public void getWhenUsingX509AndPropertyPlaceholderThenSubjectPrincipalRegexIsConfigured() throws Exception {
		System.setProperty("subject_principal_regex", "OU=(.*?)(?:,|$)");
		this.spring.configLocations(xml("X509")).autowire();

		this.mvc.perform(get("/protected")
				.with(x509("classpath:org/springframework/security/config/http/MiscHttpConfigTests-certificate.pem")))
				.andExpect(status().isOk());
	}

	@Test
	public void configureWhenUsingInvalidLogoutSuccessUrlThenThrowsException() {
		assertThatCode(() -> this.spring.configLocations(xml("InvalidLogoutSuccessUrl")).autowire())
				.isInstanceOf(BeanCreationException.class);
	}

	@Test
	public void logoutWhenSpecifyingCookiesToDeleteThenSetCookieAdded() throws Exception {
		this.spring.configLocations(xml("DeleteCookies")).autowire();

		MvcResult result =
				this.mvc.perform(post("/logout").with(csrf())).andReturn();

		List<String> values = result.getResponse().getHeaders("Set-Cookie");
		assertThat(values.size()).isEqualTo(2);
		assertThat(values).extracting(value -> value.split("=")[0]).contains("JSESSIONID", "mycookie");
	}

	@Test
	public void logoutWhenSpecifyingSuccessHandlerRefThenResponseHandledAccordingly() throws Exception {
		this.spring.configLocations(xml("LogoutSuccessHandlerRef")).autowire();

		this.mvc.perform(post("/logout").with(csrf()))
				.andExpect(redirectedUrl("/logoutSuccessEndpoint"));
	}

	@Test
	public void getWhenUnauthenticatedThenUsesConfiguredRequestCache() throws Exception {
		this.spring.configLocations(xml("RequestCache")).autowire();

		RequestCache requestCache = this.spring.getContext().getBean(RequestCache.class);

		this.mvc.perform(get("/"));

		verify(requestCache).saveRequest(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void getWhenUnauthenticatedThenUsesConfiguredAuthenticationEntryPoint() throws Exception {
		this.spring.configLocations(xml("EntryPoint")).autowire();

		AuthenticationEntryPoint entryPoint = this.spring.getContext().getBean(AuthenticationEntryPoint.class);

		this.mvc.perform(get("/"));

		verify(entryPoint).commence(
				any(HttpServletRequest.class),
				any(HttpServletResponse.class),
				any(AuthenticationException.class));
	}

	/**
	 * See SEC-750. If the http security post processor causes beans to be instantiated too eagerly, they way miss
	 * additional processing. In this method we have a UserDetailsService which is referenced from the namespace
	 * and also has a post processor registered which will modify it.
	 */
	@Test
	public void configureWhenUsingCustomUserDetailsServiceThenBeanPostProcessorsAreStillApplied() {
		this.spring.configLocations(xml("Sec750")).autowire();

		BeanNameCollectingPostProcessor postProcessor =
				this.spring.getContext().getBean(BeanNameCollectingPostProcessor.class);

		assertThat(postProcessor.getBeforeInitPostProcessedBeans())
				.contains("authenticationProvider", "userService");
		assertThat(postProcessor.getAfterInitPostProcessedBeans())
				.contains("authenticationProvider", "userService");

	}

	/* SEC-934 */
	@Test
	public void getWhenUsingTwoIdenticalInterceptUrlsThenTheSecondTakesPrecedence() throws Exception {
		this.spring.configLocations(xml("Sec934")).autowire();

		this.mvc.perform(get("/protected")
				.with(httpBasic("user", "password")))
				.andExpect(status().isOk());

		this.mvc.perform(get("/protected")
				.with(httpBasic("admin", "password")))
				.andExpect(status().isForbidden());
	}

	@Test
	public void getWhenAuthenticatingThenConsultsCustomSecurityContextRepository() throws Exception {
		this.spring.configLocations(xml("SecurityContextRepository")).autowire();

		SecurityContextRepository repository = this.spring.getContext().getBean(SecurityContextRepository.class);
		SecurityContext context = new SecurityContextImpl(new TestingAuthenticationToken("user", "password"));
		when(repository.loadContext(any(HttpRequestResponseHolder.class))).thenReturn(context);

		MvcResult result =
			this.mvc.perform(get("/protected")
					.with(httpBasic("user", "password")))
					.andExpect(status().isOk())
					.andReturn();

		assertThat(result.getRequest().getSession(false)).isNotNull();

		verify(repository, atLeastOnce()).saveContext(
				any(SecurityContext.class),
				any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void getWhenUsingInterceptUrlExpressionsThenAuthorizesAccordingly() throws Exception {
		this.spring.configLocations(xml("InterceptUrlExpressions")).autowire();

		this.mvc.perform(get("/protected")
				.with(httpBasic("admin", "password")))
				.andExpect(status().isOk());

		this.mvc.perform(get("/protected")
				.with(httpBasic("user", "password")))
				.andExpect(status().isForbidden());

		this.mvc.perform(get("/unprotected")
				.with(httpBasic("user", "password")))
				.andExpect(status().isOk());

	}

	@Test
	public void getWhenUsingCustomExpressionHandlerThenAuthorizesAccordingly() throws Exception {
		this.spring.configLocations(xml("ExpressionHandler")).autowire();

		PermissionEvaluator permissionEvaluator = this.spring.getContext().getBean(PermissionEvaluator.class);
		when(permissionEvaluator.hasPermission(any(Authentication.class), any(Object.class), any(Object.class)))
				.thenReturn(false);

		this.mvc.perform(get("/")
				.with(httpBasic("user", "password")))
				.andExpect(status().isForbidden());

		verify(permissionEvaluator).hasPermission(any(Authentication.class), any(Object.class), any(Object.class));
	}

	@Test
	public void configureWhenProtectingLoginPageThenWarningLogged() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		redirectLogsTo(baos, DefaultFilterChainValidator.class);

		this.spring.configLocations(xml("ProtectedLoginPage")).autowire();

		assertThat(baos.toString()).contains("[WARN]");
	}

	/*
	def disablingUrlRewritingThroughTheNamespaceSetsCorrectPropertyOnContextRepo() {
		xml.http('auto-config':'true', 'disable-url-rewriting':'true')
		createAppContext()

		expect:
		getFilter(SecurityContextPersistenceFilter).repo.disableUrlRewriting
	}

	def userDetailsServiceInParentContextIsLocatedSuccessfully() {
		when:
		createAppContext()
		httpAutoConfig {
			'remember-me'
		}
		appContext = new InMemoryXmlApplicationContext(writer.toString(), appContext)

		then:
		notThrown(BeansException)
	}*/


	/*

	def httpConfigWithNoAuthProvidersWorksOk() {
		when:
		"Http config has no internal authentication providers"
		xml.debug()
		xml.http() {
			'form-login' ()
			csrf(disabled:true)
			anonymous(enabled:'false')
		}
		createAppContext()
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
		request.setServletPath("/login");
		request.addParameter("username", "bob");
		request.addParameter("password", "bobspassword");
		then:
		"App context creation and login request succeed"
		DebugFilter debugFilter = appContext.getBean(BeanIds.SPRING_SECURITY_FILTER_CHAIN);
		debugFilter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		appListener.events.size() == 2
		appListener.authenticationEvents.size() == 2
	}

	def eraseCredentialsDefaultsToTrue() {
		xml.http() {
			'form-login' ()
		}
		createAppContext()
		expect:
		getFilter(UsernamePasswordAuthenticationFilter).authenticationManager.eraseCredentialsAfterAuthentication
	}

	def eraseCredentialsIsSetFromParentAuthenticationManager() {
		xml.http() {
			'form-login' ()
		}
		createAppContext("<authentication-manager erase-credentials='false' />");
		expect:
		!getFilter(UsernamePasswordAuthenticationFilter).authenticationManager.eraseCredentialsAfterAuthentication
	}

	def 'SEC-2020 authentication-manager@erase-credentials with http@authentication-manager-ref'()

	{
		xml.http('authentication-manager-ref':'authMgr'){
		'form-login' ()
	}
		createAppContext("<authentication-manager id='authMgr' erase-credentials='false' />");
		expect:
		def authManager = getFilter(UsernamePasswordAuthenticationFilter).authenticationManager
		!authManager.eraseCredentialsAfterAuthentication
		!authManager.parent.eraseCredentialsAfterAuthentication
	}

	def 'authentication-manager@erase-credentials with http@authentication-manager-ref not ProviderManager'()

	{
		xml.http('authentication-manager-ref':'authMgr'){
		'form-login' ()
	}
		xml. 'b:bean' (id:'authMgr', 'class':MockAuthenticationManager.class.name)
		createAppContext()
		expect:
		def authManager = getFilter(UsernamePasswordAuthenticationFilter).authenticationManager
		!authManager.eraseCredentialsAfterAuthentication
		authManager.parent instanceof MockAuthenticationManager
	}

	def jeeFilterExtractsExpectedRoles() {
		xml.http() {
			jee('mappable-roles':'admin,user,a,b,c')
		}
		createAppContext()
		FilterChainProxy fcp = appContext.getBean(BeanIds.FILTER_CHAIN_PROXY)
		Principal p = Mock(Principal)
		p.getName() >> 'joe'

		when:

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/something")
		request.setUserPrincipal(p)
		request.addUserRole('admin')
		request.addUserRole('user')
		request.addUserRole('c')
		request.addUserRole('notmapped')
		fcp.doFilter(request, new MockHttpServletResponse(), new MockFilterChain())
		SecurityContext ctx = request.getSession().getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
		Set<String> roles = AuthorityUtils.authorityListToSet(ctx.getAuthentication().getAuthorities());

		then:
		roles.size() == 3
		roles.contains 'ROLE_admin'
		roles.contains 'ROLE_user'
		roles.contains 'ROLE_c'
	}

	def authenticationDetailsSourceInjectionSucceeds() {
		xml.http() {
			'form-login' ('authentication-details-source-ref' :'adsr')
			'openid-login' ('authentication-details-source-ref' :'adsr')
			'http-basic' ('authentication-details-source-ref' :'adsr')
			'x509' ('authentication-details-source-ref' :'adsr')
		}
		bean('adsr', 'org.springframework.security.web.authentication.WebAuthenticationDetailsSource')
		createAppContext()
		def adsr = appContext.getBean('adsr')
		expect:
		getFilter(UsernamePasswordAuthenticationFilter).authenticationDetailsSource == adsr
		getFilter(OpenIDAuthenticationFilter).authenticationDetailsSource == adsr
		getFilter(BasicAuthenticationFilter).authenticationDetailsSource == adsr
		getFilter(X509AuthenticationFilter).authenticationDetailsSource == adsr
	}

	def includeJaasApiIntegrationFilter() {
		xml.http(['auto-config':'true', 'jaas-api-provision':'true'])
		createAppContext()
		expect:
		getFilter(JaasApiIntegrationFilter.class) != null
	}

	def httpFirewallInjectionIsSupported() {
		xml. 'http-firewall' (ref:'fw')
		xml.http() {
			'form-login' ()
		}
		bean('fw', DefaultHttpFirewall)
		createAppContext()
		FilterChainProxy fcp = appContext.getBean(BeanIds.FILTER_CHAIN_PROXY)
		expect:
		fcp.firewall == appContext.getBean('fw')
	}

	def customAccessDecisionManagerIsSupported() {
		xml.http('auto-config':'true', 'access-decision-manager-ref':'adm')
		xml. 'b:bean' (id:'adm', 'class':AffirmativeBased.class.name){
			'b:constructor-arg' {
				'b:list' () {
					'b:bean' ('class':RoleVoter.class.name)
					'b:bean' ('class':RoleVoter.class.name)
					'b:bean' ('class':RoleVoter.class.name)
					'b:bean' ('class':WebExpressionVoter.class.name)
				}
			}
		}
		createAppContext()
		expect:
		getFilter(FilterSecurityInterceptor.class).accessDecisionManager.decisionVoters[3] instanceof WebExpressionVoter
	}

	def customAuthenticationManagerIsSupported() {
		xml.http('auto-config':'true', 'authentication-manager-ref':'am')
		xml. 'b:bean' (id:'am', 'class':MockAuthenticationManager.class.name)
		createAppContext("")
		expect:
		getFilter(UsernamePasswordAuthenticationFilter.class).authenticationManager.parent instanceof MockAuthenticationManager
	}

	// SEC-1893
	def customPortMappings() {
		when:
		'A custom port-mappings is registered'
		def expectedHttpsPortMappings = [8443:8080]
		xml.http('auto-config':'true'){
			'intercept-url' ('pattern':'/**', 'requires-channel':'https')
			'port-mappings' {
				'port-mapping' (http:'8443', https:'8080')
			}
		}
		createAppContext()

		then:
		'All the components created by the namespace use that port mapping'
		getFilter(RequestCacheAwareFilter.class).requestCache.portResolver.portMapper.httpsPortMappings == expectedHttpsPortMappings

		def channelProcessors = getFilter(ChannelProcessingFilter.class).channelDecisionManager.channelProcessors
		channelProcessors.size() == 2
		channelProcessors.each {
			cp ->
					cp.entryPoint.portMapper.httpsPortMappings == expectedHttpsPortMappings
			cp.entryPoint.portResolver.portMapper.httpsPortMappings == expectedHttpsPortMappings
		}

		def authEntryPoint = getFilter(ExceptionTranslationFilter.class).authenticationEntryPoint
		authEntryPoint.portMapper.httpsPortMappings == expectedHttpsPortMappings
		authEntryPoint.portResolver.portMapper.httpsPortMappings == expectedHttpsPortMappings
	}*/

	@RestController
	static class BasicController {
		@RequestMapping("/unprotected")
		public String unprotected() {
			return "ok";
		}

		@RequestMapping("/protected")
		public String protectedMethod(@AuthenticationPrincipal String name) {
			return name;
		}
	}

	@RestController
	static class CustomKeyController {
		@GetMapping("/customKey")
		public String customKey() {
			Authentication authentication =
					SecurityContextHolder.getContext().getAuthentication();

			if ( authentication != null &&
					authentication instanceof AnonymousAuthenticationToken ) {
				return String.valueOf(
								((AnonymousAuthenticationToken) authentication).getKeyHash());
			}

			return null;
		}
	}

	class MockAuthenticationManager implements AuthenticationManager {
		public Authentication authenticate(Authentication authentication) {
			return null;
		}
	}

	class MockPermissionEvaluator implements PermissionEvaluator {
		public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
			return true;
		}

		public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
			return true;
		}

	}

	class MockEntryPoint extends LoginUrlAuthenticationEntryPoint {
		public MockEntryPoint() {
			super("/notused");
		}
	}

	private void redirectLogsTo(OutputStream os, Class<?> clazz) {
		Logger logger = (Logger)LoggerFactory.getLogger(clazz);
		Appender<ILoggingEvent> appender = mock(Appender.class);
		when(appender.isStarted()).thenReturn(true);
		doAnswer(writeTo(os)).when(appender).doAppend(any(ILoggingEvent.class));
		logger.addAppender(appender);
	}

	private Answer<ILoggingEvent> writeTo(OutputStream os) {
		return invocation -> {
			os.write(invocation.getArgument(0).toString().getBytes());
			return null;
		};
	}

	private void assertThatFiltersMatchExpectedAutoConfigList() {
		assertThatFiltersMatchExpectedAutoConfigList("/");
	}

	private void assertThatFiltersMatchExpectedAutoConfigList(String url) {
		Iterator<Filter> filters = getFilters(url).iterator();

		assertThat(filters.next()).isInstanceOf(SecurityContextPersistenceFilter.class);
		assertThat(filters.next()).isInstanceOf(WebAsyncManagerIntegrationFilter.class);
		assertThat(filters.next()).isInstanceOf(HeaderWriterFilter.class);
		assertThat(filters.next()).isInstanceOf(CsrfFilter.class);
		assertThat(filters.next()).isInstanceOf(LogoutFilter.class);
		assertThat(filters.next()).isInstanceOf(UsernamePasswordAuthenticationFilter.class);
		assertThat(filters.next()).isInstanceOf(DefaultLoginPageGeneratingFilter.class);
		assertThat(filters.next()).isInstanceOf(DefaultLogoutPageGeneratingFilter.class);
		assertThat(filters.next()).isInstanceOf(BasicAuthenticationFilter.class);
		assertThat(filters.next()).isInstanceOf(RequestCacheAwareFilter.class);
		assertThat(filters.next()).isInstanceOf(SecurityContextHolderAwareRequestFilter.class);
		assertThat(filters.next()).isInstanceOf(AnonymousAuthenticationFilter.class);
		assertThat(filters.next()).isInstanceOf(SessionManagementFilter.class);
		assertThat(filters.next()).isInstanceOf(ExceptionTranslationFilter.class);
		assertThat(filters.next()).isInstanceOf(FilterSecurityInterceptor.class)
				.hasFieldOrPropertyWithValue("observeOncePerRequest", true);
	}

	private <T extends Filter> T getFilter(Class<T> filterClass) {
		return (T)getFilters("/").stream().filter(filterClass::isInstance).findFirst().orElse(null);
	}

	private List<Filter> getFilters(String url) {
		FilterChainProxy proxy = this.spring.getContext().getBean(FilterChainProxy.class);
		return proxy.getFilters(url);
	}

	private static String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}
}
