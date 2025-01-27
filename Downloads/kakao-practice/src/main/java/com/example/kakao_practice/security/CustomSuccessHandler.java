package com.example.kakao_practice.security;

import java.io.IOException;
import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.example.kakao_practice.member.Member;
import com.example.kakao_practice.member.MemberService;
import com.example.kakao_practice.rq.Rq;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class CustomSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	private final JwtTokenProvider jwtTokenProvider;
	private final MemberService memberService;
	private final Rq rq;

	@SneakyThrows
	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		String existingAccessToken = resolveToken(request);

		if (existingAccessToken == null) {
			existingAccessToken = rq.getCookie("access-token");
		}

		// 유효한 access-token이 있으면 새로 발급하지 않음
		if (existingAccessToken != null && jwtTokenProvider.validate(existingAccessToken) && !jwtTokenProvider.isExpired(existingAccessToken)) {
			log.info("유효한 access-token존재");
			response.addHeader("Authorization", "Bearer " + existingAccessToken);
			String redirectUrl = request.getParameter("state");
			response.sendRedirect(redirectUrl);
			return;
		}

		// 유효한 access-token 없으면 새로 발급
		Member member = memberService.findById(rq.getActor().getId()).get();

		String token = jwtTokenProvider.createToken(member);
		String refreshToken = jwtTokenProvider.createRefreshToken(member);

		response.addHeader("Authorization", "Bearer " + token);

		rq.setCookie("access-token", token, jwtTokenProvider.getExpiration(token));
		rq.setCookie("refresh-token", refreshToken, jwtTokenProvider.getExpiration(refreshToken));

		String redirectUrl = request.getParameter("state");

		response.sendRedirect(redirectUrl);
	}

	private String resolveToken(HttpServletRequest request) {
		String token = request.getHeader("Authorization");
		if (StringUtils.hasText(token) && token.startsWith("Bearer ")) {
			return token.substring(7); // "Bearer " 이후의 토큰 값 반환
		}
		return null;
	}

}
