package com.example.kakao_practice.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final CustomSuccessHandler successHandler;
	private final CustomAuthorizationRequestResolver customAuthorizationRequestResolver;
	private final CustomAuthenticationFilter customAuthenticationFilter;
	private final CustomLogoutHandler logoutHandler;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(authorizeRequests ->
					authorizeRequests
						.requestMatchers("/h2-console/**")
						.permitAll()
						.requestMatchers("/logout/kakao", "/user-profile")
						.authenticated()
						.anyRequest().permitAll())
			.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.headers(
				headers ->
					headers.frameOptions(
						HeadersConfigurer.FrameOptionsConfig::sameOrigin
					)
			)
			.csrf(AbstractHttpConfigurer::disable)
			.oauth2Login(
				oauth2Login -> oauth2Login
					.successHandler(successHandler)
					.authorizationEndpoint(
						authorizationEndpoint -> authorizationEndpoint
							.authorizationRequestResolver(customAuthorizationRequestResolver)))
			.logout(logout -> logout
				.addLogoutHandler(logoutHandler)
				.invalidateHttpSession(true)
				.logoutSuccessUrl("/home-view")
			)
			.addFilterBefore(customAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}
}
