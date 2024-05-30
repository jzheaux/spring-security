/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authorization.method;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import org.springframework.core.annotation.AliasFor;
import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.prepost.PreAuthorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link AuthorizationAnnotationUtils}.
 *
 * @author Josh Cummings
 * @author Sam Brannen
 */
class AuthorizationAnnotationUtilsTests {

	@Test // gh-13132
	void annotationsOnSyntheticMethodsShouldNotTriggerAnnotationConfigurationException() throws NoSuchMethodException {
		StringRepository proxy = (StringRepository) Proxy.newProxyInstance(
				Thread.currentThread().getContextClassLoader(), new Class[] { StringRepository.class },
				(p, m, args) -> null);
		Method method = proxy.getClass().getDeclaredMethod("findAll");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class);
		assertThat(preAuthorize.value()).isEqualTo("hasRole('someRole')");
	}

	@Test // gh-13625
	void annotationsFromSuperSuperInterfaceShouldNotTriggerAnnotationConfigurationException() throws Exception {
		Method method = HelloImpl.class.getDeclaredMethod("sayHello");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class);
		assertThat(preAuthorize.value()).isEqualTo("hasRole('someRole')");
	}

	@Test
	@Disabled
	void multipleIdenticalAnnotationsOnClassShouldNotTriggerAnnotationConfigurationException() {
		Class<?> clazz = MultipleIdenticalPreAuthorizeAnnotationsOnClass.class;
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(clazz, PreAuthorize.class);
		assertThat(preAuthorize.value()).isEqualTo("hasRole('someRole')");
	}

	@Test
	@Disabled
	void multipleIdenticalAnnotationsOnMethodShouldNotTriggerAnnotationConfigurationException() throws Exception {
		Method method = MultipleIdenticalPreAuthorizeAnnotationsOnMethod.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class);
		assertThat(preAuthorize.value()).isEqualTo("hasRole('someRole')");
	}

	@Test
	void classOverridingAnnotationShouldNotTriggerAnnotationConfigurationException() throws Exception {
		Method method = ConcreteRepository.class.getDeclaredMethod("findAll");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class);
		assertThat(preAuthorize.value()).isEqualTo("hasRole('someOtherRole')");
	}

	@Test
	void competingAnnotationsOnClassShouldTriggerAnnotationConfigurationException() {
		Class<?> clazz = CompetingPreAuthorizeAnnotationsOnClass.class;
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> AuthorizationAnnotationUtils.findUniqueAnnotation(clazz, PreAuthorize.class))
			.withMessageContainingAll("Found 2 competing annotations:", "someRole", "otherRole");
	}

	@Test
	void competingAnnotationsOnMethodShouldTriggerAnnotationConfigurationException() throws Exception {
		Method method = CompetingPreAuthorizeAnnotationsOnMethod.class.getDeclaredMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class))
			.withMessageContainingAll("Found 2 competing annotations:", "someRole", "otherRole");
	}

	@Test
	void composedMergedAnnotationsAreNotSupported() {
		Class<?> clazz = ComposedPreAuthAnnotationOnClass.class;
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(clazz, PreAuthorize.class);

		// If you comment out .map(MergedAnnotation::withNonMergedAttributes) in
		// AuthorizationAnnotationUtils.findDistinctAnnotation(), the value of
		// the merged annotation would be "hasRole('composedRole')".
		assertThat(preAuthorize.value()).isEqualTo("hasRole('metaRole')");
	}

	@Test
	void testOne() throws Exception {
		Method method = One.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("one");
	}

	@Test
	void testTwo() throws Exception {
		Method method = Two.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("two");
	}

	@Test
	void testThree() throws Exception {
		Method method = Three.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	@Test
	void testFour() throws Exception {
		Method method = Four.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("four");
	}

	@Test
	void testFive() throws Exception {
		Method method = Five.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("five");
	}

	@Test
	void testSix() throws Exception {
		Method method = Six.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("six");
	}

	@Test
	void testEight() throws Exception {
		Method method = Eight.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eight");
	}

	@Test
	void testEleven() throws Exception {
		Method method = Eleven.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eleven");
	}

	@Test
	void testTwelve() throws Exception {
		Method method = Twelve.class.getDeclaredMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
				.apply(method, method.getDeclaringClass()));
	}

	@Test
	void testThirteen() throws Exception {
		Method method = Thirteen.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("thirteen");
	}

	@Test
	void testFourteen() throws Exception {
		Method method = Fourteen.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("fourteen");
	}

	@Test
	void testFifteen() throws Exception {
		Method method = Fifteen.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("seven");
	}

	@Test
	void testSixteen() throws Exception {
		Method method = Sixteen.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("sixteen");
	}

	@Test
	void testSeventeen() throws Exception {
		Method method = Seventeen.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("seventeen");
	}

	@Test
	void testEighteen() throws Exception {
		Method method = Eighteen.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("eight");
	}

	@Test
	void testNineteen() throws Exception {
		Method method = Nineteen.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("nineteen");
	}

	@Test
	void testTwenty() throws Exception {
		Method method = Twenty.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twenty");
	}

	@Test
	void testTwentyOne() throws Exception {
		Method method = TwentyOne.class.getDeclaredMethod("method");
		assertThatExceptionOfType(AnnotationConfigurationException.class)
			.isThrownBy(() -> AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
				.apply(method, method.getDeclaringClass()));
	}

	@Test
	void testTwentyTwo() throws Exception {
		Method method = TwentyTwo.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentytwo");
	}

	@Test
	void testTwentyThree() throws Exception {
		Method method = TwentyThree.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentythree");
	}

	@Test
	void testTwentyFour() throws Exception {
		Method method = TwentyFour.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("three");
	}

	@Test
	void testTwentyFive() throws Exception {
		Method method = TwentyFive.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentyfive");
	}

	@Test
	void testTwentySix() throws Exception {
		Method method = TwentySix.class.getDeclaredMethod("method");
		PreAuthorize preAuthorize = AuthorizationAnnotationUtils.withDefaults(PreAuthorize.class)
			.apply(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("twentysix");
	}

	private interface BaseRepository<T> {

		Iterable<T> findAll();

	}

	private interface StringRepository extends BaseRepository<String> {

		@Override
		@PreAuthorize("hasRole('someRole')")
		List<String> findAll();

	}

	private interface OtherStringRepository extends BaseRepository<String> {

		@Override
		@PreAuthorize("hasRole('someOtherRole')")
		List<String> findAll();

	}

	private static class ConcreteRepository implements StringRepository, OtherStringRepository {

		@Override
		@PreAuthorize("hasRole('someOtherRole')")
		public List<String> findAll() {
			return List.of("hi");
		}

	}

	private interface Hello {

		@PreAuthorize("hasRole('someRole')")
		String sayHello();

	}

	private interface SayHello extends Hello {

	}

	private static class HelloImpl implements SayHello {

		@Override
		public String sayHello() {
			return "hello";
		}

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasRole('someRole')")
	private @interface RequireSomeRole {

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasRole('otherRole')")
	private @interface RequireOtherRole {

	}

	@RequireSomeRole
	@PreAuthorize("hasRole('someRole')")
	private static class MultipleIdenticalPreAuthorizeAnnotationsOnClass {

	}

	private static class MultipleIdenticalPreAuthorizeAnnotationsOnMethod {

		@RequireSomeRole
		@PreAuthorize("hasRole('someRole')")
		void method() {
		}

	}

	@RequireOtherRole
	@PreAuthorize("hasRole('someRole')")
	private static class CompetingPreAuthorizeAnnotationsOnClass {

	}

	private static class CompetingPreAuthorizeAnnotationsOnMethod {

		@RequireOtherRole
		@PreAuthorize("hasRole('someRole')")
		void method() {
		}

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreAuthorize("hasRole('metaRole')")
	private @interface ComposedPreAuth {

		@AliasFor(annotation = PreAuthorize.class)
		String value();

	}

	@ComposedPreAuth("hasRole('composedRole')")
	private static class ComposedPreAuthAnnotationOnClass {

	}

	@PreAuthorize("one")
	private interface One {

		String method();

	}

	@PreAuthorize("two")
	private interface Two {

		String method();

	}

	private interface Three {

		@PreAuthorize("three")
		String method();

	}

	private interface Four {

		@PreAuthorize("four")
		String method();

	}

	@PreAuthorize("five")
	private static class Five {

		// unambigously five
		String method() {
			return "ok";
		}

	}

	private static class Six {

		@PreAuthorize("six") // unambigously six
		String method() {
			return "ok";
		}

	}

	@PreAuthorize("seven")
	private interface Seven extends One {

	}

	private interface Eight extends One {

		@PreAuthorize("eight")
		String method();

	}

	private interface Nine extends One, Two {

	}

	@PreAuthorize("ten")
	private interface Ten extends One, Two {

	}

	private interface Eleven extends One, Two {

		@PreAuthorize("eleven")
		String method();

	}

	private static class Twelve implements One, Two {

		@Override
		public String method() {
			return "ok";
		} // ambiguous

	}

	@PreAuthorize("thirteen")
	private static class Thirteen implements One, Two {

		@Override
		public String method() {
			return "ok";
		} // unambiguously thirteen

	}

	private static class Fourteen implements One, Two {

		@Override
		@PreAuthorize("fourteen")
		public String method() {
			return "ok";
		} // unambiguously fourteen

	}

	private static class Fifteen implements Seven {

		@Override
		public String method() {
			return "ok";
		} // unambiougously seven

	}

	@PreAuthorize("sixteen")
	private static class Sixteen implements Seven {

		@Override
		public String method() {
			return "ok";
		} // unambiouously sixteen

	}

	private static class Seventeen implements Seven {

		@Override
		@PreAuthorize("seventeen")
		public String method() {
			return "ok";
		} // unambiguously seventeen

	}

	private static class Eighteen implements Eight {

		@Override
		public String method() {
			return "ok";
		} // unambiguously eight

	}

	@PreAuthorize("nineteen")
	private static class Nineteen implements Eight {

		@Override
		public String method() {
			return "ok";
		} // unambiguously nineteen

	}

	private static class Twenty implements Eight {

		@Override
		@PreAuthorize("twenty")
		public String method() {
			return "ok";
		} // unambiguously twenty

	}

	private static class TwentyOne implements Nine {

		@Override
		public String method() {
			return "ok";
		} // ambiguous

	}

	@PreAuthorize("twentytwo")
	private static class TwentyTwo implements Nine {

		@Override
		public String method() {
			return "ok";
		} // unambiguously twenty-two

	}

	private static class TwentyThree implements Nine {

		@Override
		@PreAuthorize("twentythree")
		public String method() {
			return "ok";
		} // unambiguously twenty-three

	}

	private static class TwentyFour implements One, Three {

		@Override
		public String method() {
			return "ok";
		} // unambiguously three

	}

	@PreAuthorize("twentyfive")
	private static class TwentyFive implements One, Three {

		@Override
		public String method() {
			return "ok";
		} // unambiguously twenty-five

	}

	private static class TwentySix implements One, Three {

		@Override
		@PreAuthorize("twentysix")
		public String method() {
			return "ok";
		} // unambiguously twenty-six

	}

}
