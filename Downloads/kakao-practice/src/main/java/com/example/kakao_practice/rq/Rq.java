package com.example.kakao_practice.rq;

import java.util.Arrays;
import java.util.Optional;

import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

import com.example.kakao_practice.member.Member;
import com.example.kakao_practice.member.MemberService;
import com.example.kakao_practice.security.SecurityUser;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequestScope
@Component
@RequiredArgsConstructor
public class Rq {
	private final HttpServletResponse response;
	private final HttpServletRequest request;
	private final MemberService memberService;

	public Member getActor() {
		return Optional.ofNullable(
				SecurityContextHolder
					.getContext()
					.getAuthentication()
			)
			.map(Authentication::getPrincipal)
			.filter(principal -> principal instanceof SecurityUser)
			.map(principal -> (SecurityUser) principal)
			.map(securityUser -> new Member(securityUser.getId(), securityUser.getUsername(), securityUser.getNickname()))
			.orElse(null);
	}

	public void setCookie(String name, String value, Long expiration) {
		ResponseCookie cookie = ResponseCookie.from(name, value)
			.path("/")
			.domain("localhost")
			.sameSite("Strict")
			.secure(true)
			.httpOnly(true)
			.maxAge(expiration)
			.build();

		response.addHeader("Set-Cookie", cookie.toString());
	}

	public String getCookie(String name) {
		return Optional
			.ofNullable(request.getCookies())
			.stream()
			.flatMap(cookies -> Arrays.stream(cookies))
			.filter(cookie -> cookie.getName().equals(name))
			.map(cookie -> cookie.getValue())
			.findFirst()
			.orElse(null);
	}

	public void deleteCookie(String name) {
		ResponseCookie cookie = ResponseCookie.from(name, null)
			.path("/")
			.domain("localhost")
			.sameSite("Strict")
			.secure(true)
			.httpOnly(true)
			.maxAge(0)
			.build();

		response.addHeader("Set-Cookie", cookie.toString());
	}

}
