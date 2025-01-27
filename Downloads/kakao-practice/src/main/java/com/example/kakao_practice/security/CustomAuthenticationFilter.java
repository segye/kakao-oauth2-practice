package com.example.kakao_practice.security;

import java.io.IOException;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.kakao_practice.member.Member;
import com.example.kakao_practice.member.MemberService;
import com.example.kakao_practice.rq.Rq;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationFilter extends OncePerRequestFilter {
	private final JwtTokenProvider jwtTokenProvider;
	private final MemberService memberService;
	private final Rq rq;
	private final RedisTemplate<String, String> redisTemplate;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		String jwt = resolveToken(request);

		if (jwt == null) {
			jwt = rq.getCookie("access-token");
		}

		Authentication authentication = null;

		// access token이 유효하고 만료되지 않은 경우
		if (jwt != null && jwtTokenProvider.validate(jwt) && !jwtTokenProvider.isExpired(jwt)) {
			log.info("Access token is valid and not expired.");
			authentication = jwtTokenProvider.getAuthentication(jwt);
		}

		// access token이 없거나 만료된 경우
		if (authentication == null && jwt == null || jwtTokenProvider.isExpired(jwt)) {
			log.info("access-token 만료");
			String refreshToken = rq.getCookie("refresh-token");
			if (jwtTokenProvider.validate(refreshToken) && (redisTemplate.opsForValue().get(refreshToken) == null
				|| redisTemplate.opsForValue().get(refreshToken).isEmpty())) {
				String username = jwtTokenProvider.getUsername(refreshToken);
				Member member = memberService.findByUsername(username)
					.orElseThrow(() -> new IllegalArgumentException("멤버가 존재하지 않습니다."));
				String newAccessToken = jwtTokenProvider.createToken(member);
				String newRefreshToken = jwtTokenProvider.createRefreshToken(member);
				rq.setCookie("access-token", newAccessToken, jwtTokenProvider.getExpiration(newAccessToken));
				rq.setCookie("refresh-token", newRefreshToken, jwtTokenProvider.getExpiration(newRefreshToken));
				authentication = jwtTokenProvider.getAuthentication(newAccessToken);
				log.info("새로운 token 발급 완료");
			} else {
				log.info("유효하지 않은 refresh-token");
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				return;
			}
		}

		if (jwt == null || !jwtTokenProvider.validate(jwt)) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		// 인증 정보가 유효하면 SecurityContext에 설정
		if (authentication != null) {
			SecurityContextHolder.getContext().setAuthentication(authentication);
		} else {
			log.info("권한이 없습니다.");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		filterChain.doFilter(request, response);
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		String requestURI = request.getRequestURI();
		return requestURI.matches("/home-view") || requestURI.startsWith("/h2-console");
	}

	private String resolveToken(HttpServletRequest request) {
		String jwt = request.getHeader("Authorization");

		if (StringUtils.hasText(jwt) && jwt.startsWith("Bearer ")) {
			return jwt.substring(7);
		}
		return null;
	}


}
