# JWT_Security_ver2 (MyBatis 버전)

**작성일:** 2025-10-29  

Spring Boot + MyBatis + Spring Security + JWT를 사용한 **보안 템플릿 프로젝트(ver2)**입니다.  
기존 ver1에서 불필요한 코드들을 제거하고, **템플릿처럼 재사용 가능하도록 구조를 정리**했습니다.

---

## 🔹 프로젝트 특징

- **JWT 기반 인증**
  - 로그인 시 DB 정보를 확인 후 JWT 토큰 발급
  - 발급된 토큰을 서버로 보내 유효성 확인
  - SecurityContext에 사용자 정보 저장
- **권한 설정**
  - `ROLE_USER`, `ROLE_ADMIN` 지원
  - `ROLE_USER` 권한이 있어야 접근 가능한 메서드 예시 구현
- **회원 관리**
  - 회원 가입 기능 구현 (DB 저장, 유효성 검증 미구현)
  - 비밀번호는 **BCrypt 암호화** 후 저장
  - 로그인 기능 구현
  - 회원 정보 조회 기능 포함
- **MyBatis 기반**
  - SQL 매퍼(XML) 기반 DAO 구현
  - ver1 대비 불필요한 코드를 제거, 유지보수 편리

---

## 🔹 기본 DB 설정 및 샘플 데이터

```sql
-- 데이터베이스 생성
CREATE DATABASE dbName;
USE dbName;

-- 회원 테이블
CREATE TABLE user (
    user_idx    BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY COMMENT '회원 고유번호',
    user_id     VARCHAR(60) NOT NULL UNIQUE COMMENT '로그인 아이디',
    user_pw     VARCHAR(255) NOT NULL COMMENT '비밀번호 (암호화 저장)',
    is_enabled  BOOLEAN     NOT NULL DEFAULT TRUE COMMENT '계정 활성 여부',
    created_at  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '가입일시',
    updated_at  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '수정일시'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='회원 기본 정보';

-- 권한 테이블
CREATE TABLE user_auth (
    auth_idx BIGINT NOT NULL AUTO_INCREMENT COMMENT '권한 고유번호',
    user_idx BIGINT NOT NULL COMMENT '회원 고유번호 (FK)',
    auth VARCHAR(50) NOT NULL COMMENT '권한명 (ex: ROLE_USER, ROLE_ADMIN)',
    PRIMARY KEY (auth_idx),
    CONSTRAINT fk_user_auth_user FOREIGN KEY (user_idx)
        REFERENCES user(user_idx)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='회원 권한 정보';

-- 샘플 사용자
INSERT INTO user(user_id, user_pw)
VALUES('test1', '$2a$10$9gyJQgOXFeLqigSmLrEzWOj5k86ar.2qyEVtV9RQzOIN4oRECSLYe');

INSERT INTO user_auth(user_idx, auth)
VALUES(1, 'ROLE_USER');
