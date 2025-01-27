package com.example.kakao_practice.member;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Member extends BaseTime{
	@Column(unique = true, length = 30)
	private String username;

	@Column(length = 50)
	private String password;

	@Column(length = 30)
	private String nickname;

	private String profileImgUrl;

	public String getName() {
		return nickname;
	}

	public boolean isAdmin() {
		return "admin".equals(username);
	}

	public boolean matchPassword(String password) {
		return this.password.equals(password);
	}

	public Member(long id, String username, String nickname) {
		this.setId(id);
		this.username = username;
		this.nickname = nickname;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return getAuthoritiesAsStringList()
			.stream()
			.map(SimpleGrantedAuthority::new)
			.toList();
	}

	public List<String> getAuthoritiesAsStringList() {
		List<String> authorities = new ArrayList<>();

		if (isAdmin())
			authorities.add("ROLE_ADMIN");

		return authorities;
	}

	public String getProfileImgUrlOrDefault() {
		return isBlank(profileImgUrl) ? "https://placehold.co/640x640?text=O_O" : profileImgUrl;
	}

	public static boolean isBlank(String str) {
		return str == null || str.trim().isEmpty();
	}
}
