package com.example.kakao_practice.security;

import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import com.example.kakao_practice.rq.Rq;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomLogoutHandler implements LogoutHandler {
	private final Rq rq;
	private final RedisTemplate<String, String> redisTemplate;
	private final JwtTokenProvider jwtTokenProvider;

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		// access-token 쿠키 삭제
		rq.deleteCookie("access-token");

		// refresh-token 쿠키 삭제
		String refreshToken = rq.getCookie("refresh-token");
		redisTemplate.opsForValue().set(refreshToken, "logout", jwtTokenProvider.getExpiration(refreshToken), TimeUnit.MILLISECONDS);
		rq.deleteCookie("refresh-token");

		// JSESSIONID 쿠키 삭제
		rq.deleteCookie("JSESSIONID");
	}

}
