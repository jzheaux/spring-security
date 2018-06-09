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

package sample.provider;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;

import java.time.Duration;
import java.util.Arrays;

public class Container {
	String configFileName;
	String dockerFileName;

	GenericContainer container;

	public String getConfigFileName() {
		return configFileName;
	}

	public void setConfigFileName(String configFileName) {
		this.configFileName = configFileName;
	}

	public String getDockerFileName() {
		return dockerFileName;
	}

	public void setDockerFileName(String dockerFileName) {
		this.dockerFileName = dockerFileName;
	}

	public void start() {
		this.container = new GenericContainer(
				new ImageFromDockerfile()
						.withFileFromClasspath(this.configFileName, this.configFileName)
						.withFileFromClasspath("Dockerfile", this.dockerFileName))
						.withMinimumRunningDuration(Duration.ofSeconds(5));
		this.container.setPortBindings(Arrays.asList("8080:8080"));
		this.container.start();
	}

	public void stop() {
		this.container.stop();
	}
}
