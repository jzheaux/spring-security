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
package org.springframework.security.config.web.server

import org.apache.http.HttpHeaders
import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Tests for [ServerPasswordManagementDsl].
 *
 * @author Evgeniy Cheban
 */
class ServerPasswordManagementDslTests {

    @Rule
    @JvmField
    val spring = SpringTestRule()

    private lateinit var client: WebTestClient

    @Autowired
    fun setup(context: ApplicationContext) {
        this.client = WebTestClient
                .bindToApplicationContext(context)
                .configureClient()
                .build()
    }

    @Test
    fun `when change password page not set then default change password page used`() {
        this.spring.register(PasswordManagementWithDefaultChangePasswordPageConfig::class.java).autowire()

        this.client.get()
                .uri("/.well-known/change-password")
                .exchange()
                .expectStatus().isFound
                .expectHeader().valueEquals(HttpHeaders.LOCATION, "/change-password")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class PasswordManagementWithDefaultChangePasswordPageConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                passwordManagement {}
            }
        }
    }

    @Test
    fun `when change password page set then specified change password page used`() {
        this.spring.register(PasswordManagementWithCustomChangePasswordPageConfig::class.java).autowire()

        this.client.get()
                .uri("/.well-known/change-password")
                .exchange()
                .expectStatus().isFound
                .expectHeader().valueEquals(HttpHeaders.LOCATION, "/custom-change-password-page")
    }

    @EnableWebFluxSecurity
    @EnableWebFlux
    open class PasswordManagementWithCustomChangePasswordPageConfig {
        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                passwordManagement {
                    changePasswordPage = "/custom-change-password-page"
                }
            }
        }
    }
}
