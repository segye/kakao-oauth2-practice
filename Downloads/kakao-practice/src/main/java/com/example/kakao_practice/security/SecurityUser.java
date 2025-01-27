package com.example.kakao_practice.security;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import lombok.Getter;

@Getter
public class SecurityUser extends User implements OAuth2User {
	private long id;
	private String nickname;

	public SecurityUser(
		long id,
		String username,
		String password,
		String nickname,
		Collection<? extends GrantedAuthority> authorities
	) {
		super(username, password, authorities);
		this.id = id;
		this.nickname = nickname;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return Map.of();
	}

	@Override
	public String getName() {
		return getUsername();
	}
}
