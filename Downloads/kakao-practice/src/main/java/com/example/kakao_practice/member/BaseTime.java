package com.example.kakao_practice.member;

import java.time.LocalDateTime;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

@Getter
@EntityListeners(AuditingEntityListener.class)
@MappedSuperclass
public class BaseTime extends BaseEntity{
	@CreatedDate
	@Setter(AccessLevel.PRIVATE)
	private LocalDateTime createDate;

	@LastModifiedDate
	@Setter(AccessLevel.PRIVATE)
	private LocalDateTime modifyDate;
}
