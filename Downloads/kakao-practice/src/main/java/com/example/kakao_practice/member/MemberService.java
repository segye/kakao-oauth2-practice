package com.example.kakao_practice.member;

import java.util.Optional;
import java.util.UUID;

import org.hibernate.service.spi.ServiceException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MemberService {
	private final MemberRepository memberRepository;
	public Member join(String username, String password, String nickname, String profileImgUrl) {
		memberRepository
			.findByUsername(username)
			.ifPresent(_username -> {
				throw new IllegalArgumentException("해당 username은 이미 사용중입니다.");
			});

		Member member = Member.builder()
			.username(username)
			.password(password)
			.nickname(nickname)
			.profileImgUrl(profileImgUrl)
			.build();

		return memberRepository.save(member);
	}

	public Optional<Member> findByUsername(String username) {
		return memberRepository.findByUsername(username);
	}

	public Optional<Member> findByNickname(String nickname) {
		return memberRepository.findByNickname(nickname);
	}


	public Optional<Member> findById(long authorId) {
		return memberRepository.findById(authorId);
	}

	public void modify(Member member, String nickname, String profileImgUrl) {
		member.setNickname(nickname);
		member.setProfileImgUrl(profileImgUrl);
	}

	public Member modifyOrJoin(String username, String nickname, String profileImgUrl) {
		Optional<Member> opMember = findByUsername(username);

		if (opMember.isPresent()) {
			Member member = opMember.get();
			modify(member, nickname, profileImgUrl);
			return member;
		}

		return join(username, "", nickname, profileImgUrl);
	}
}

