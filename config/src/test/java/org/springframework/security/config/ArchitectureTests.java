/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config;

import java.util.ArrayList;
import java.util.List;

import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.EvaluationResult;
import com.tngtech.archunit.library.dependencies.SliceAssignment;
import com.tngtech.archunit.library.dependencies.SliceIdentifier;
import org.junit.Test;

import static com.tngtech.archunit.base.DescribedPredicate.alwaysTrue;
import static com.tngtech.archunit.base.DescribedPredicate.describe;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;
import static org.assertj.core.api.Assertions.assertThat;

public class ArchitectureTests {

	@Test
	public void freeOfCycles() {
		String pkg = "org.springframework.security.config";
		JavaClasses classes = new ClassFileImporter().importPackages(pkg);
		EvaluationResult result = slices().assignedFrom(this.fullPackageSlices).should().beFreeOfCycles()
				.ignoreDependency(this.shouldIgnore, alwaysTrue())
				.ignoreDependency(alwaysTrue(), this.shouldIgnore)
				.evaluate(classes);

		List<String> cycles = result.getFailureReport().getDetails();
		List<String> formatted = new ArrayList<>();
		int step = 0;
		for (String cycle : cycles) {
			String[] details = cycle.split("\n");
			for (String detail : details) {
				if (detail.startsWith("Cycle detected")) {
					String[] cycleDetails = detail.split("->");
					StringBuilder sb = new StringBuilder(cycleDetails[0].trim());
					for (int i = 1; i < cycleDetails.length; i++) {
						sb.append(" ->\n")
							.append("                ")
							.append(cycleDetails[i].trim());
					}
					formatted.add(sb.toString());
					step = 0;
				} else if (detail.startsWith("Dependencies of Slice")) {
					formatted.add("\t" + ++step + ". " + detail);
				} else {
					formatted.add("\t\t - " + detail);
				}
			}
		}
		String message = System.lineSeparator() + String.join(System.lineSeparator(), formatted);
		assertThat(cycles.size()).overridingErrorMessage("Cycles Detected " + message).isEqualTo(0);
	}

	DescribedPredicate<JavaClass> shouldIgnore = describe("tests and legacy hot spots", input -> {
		if (input.getFullName().contains("Tests")) {
			return true;
		}

		if (input.getFullName().endsWith("Dsl") ) {
			return true;
		}

		if (input.getFullName().endsWith("ProviderManagerBuilder")) {
			return true;
		}

		return false;
	});

	SliceAssignment fullPackageSlices = new SliceAssignment() {
		@Override
		public SliceIdentifier getIdentifierOf(JavaClass javaClass) {
			return SliceIdentifier.of(javaClass.getPackageName());
		}

		@Override
		public String getDescription() {
			return "full package slices";
		}
	};
}
