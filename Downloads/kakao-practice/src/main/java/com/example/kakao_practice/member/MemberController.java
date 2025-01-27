package com.example.kakao_practice.member;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequiredArgsConstructor
@Slf4j
public class MemberController {

	@GetMapping("/home-view")
	public String home() {
		return "home";
	}

	@GetMapping("/user-profile")
	public String userProfile(@AuthenticationPrincipal Member member, Model model) {
		model.addAttribute("username", member.getUsername());
		model.addAttribute("profileImage", member.getProfileImgUrl());
		return "user-profile";
	}

	@GetMapping("/debug")
	@ResponseBody
	public String debugAuthentication() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			return "Authentication is null.";
		}
		return "Authentication is present: " + authentication.getPrincipal();
	}

}
