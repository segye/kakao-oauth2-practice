package com.example.kakao_practice.security;

import java.util.Date;
import java.util.Map;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.example.kakao_practice.member.Member;
import com.example.kakao_practice.member.MemberService;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

	@Value("${jwt.secret}")
	private String secret;
	private final static Long ACCESS_EXPIRE_TIME = 30* 60 * 1000L; // 30분
	private final static Long REFRESH_EXPIRE_TIME = 4 * 60 * 60 * 1000L; // 4시간

	private final MemberService memberService;
	private SecretKey secretKey;

	@PostConstruct
	public void init() {
		this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
	}

	public String createToken(Member member) {
		String username = member.getUsername();
		Date now = new Date();
		Date expireTime = new Date(now.getTime() + ACCESS_EXPIRE_TIME);

		return Jwts.builder()
			.claim("username", username)
			.issuedAt(now)
			.expiration(expireTime)
			.signWith(secretKey)
			.compact();
	}

	public String createRefreshToken(Member member) {
		String username = member.getUsername();
		Date now = new Date();
		Date expireTime = new Date(now.getTime() + REFRESH_EXPIRE_TIME);

		return Jwts.builder()
			.claim("username", username)
			.issuedAt(now)
			.expiration(expireTime)
			.signWith(secretKey)
			.compact();
	}

	public boolean validate(String token) {
		try {
			Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
		} catch (JwtException | IllegalArgumentException | NullPointerException e) {
			return false;
		}
		return true;
	}

	public boolean isExpired(String token) {
		try {
			Date expiration = Jwts.parser()
				.verifyWith(secretKey)
				.build()
				.parseSignedClaims(token)
				.getPayload()
				.getExpiration();
			return expiration.before(new Date());
		} catch (JwtException e) {
			return true;
		}
	}

	public String getUsername(String token) {
		return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
	}

	public Authentication getAuthentication(String token) {
		String username = getUsername(token);
		Member member = memberService.findByUsername(username)
			.orElseThrow(() -> new IllegalArgumentException("멤버가 존재하지 않습니다."));

		return new UsernamePasswordAuthenticationToken(member, "", member.getAuthorities());
	}

	public Long getExpiration(String token) {
		return Jwts.parser()
			.verifyWith(secretKey)
			.build()
			.parseSignedClaims(token)
			.getPayload()
			.getExpiration().getTime();
	}
}
