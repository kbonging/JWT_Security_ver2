package com.nexus.core.security.jwt.provider;

import com.nexus.core.prop.JwtProp;
import com.nexus.core.security.custom.CustomUser;
import com.nexus.core.security.jwt.constants.JwtConstants;
import com.nexus.core.user.dao.UserDAO;
import com.nexus.core.user.dto.UserAuthDTO;
import com.nexus.core.user.dto.UserDTO;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT 토큰 관련 기능을 제공해주는 클래스
 * - 토큰 생성
 * - 토큰 해석
 * - 토큰 유효성
 *  */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    private final JwtProp jwtProp;
    private final UserDAO userDAO;

    /**
     * 👩‍💼➡🔐 토큰 생성
     */
    public String createToken(long userIdx, String userId, List<String> roles) {

        // JWT 토큰 생성
        String jwt = Jwts.builder()
                .signWith(getShaKey(), Jwts.SIG.HS512)      // 서명에 사용할 키와 알고리즘 설정
                // .setHeaderParam("typ", SecurityConstants.TOKEN_TYPE)        // deprecated (version: before 1.0)
                .header()                                                      // update (version : after 1.0)
                .add("typ", JwtConstants.TOKEN_TYPE)              // 헤더 설정
                .and()
                .expiration(new Date(System.currentTimeMillis() + 864000000))  // 토큰 만료 시간 설정 (10일)
                .claim("uno", "" + userIdx)                                // 클레임 설정: 사용자 번호
                .claim("uid", userId)                                     // 클레임 설정: 사용자 아이디
                .claim("rol", roles)                                      // 클레임 설정: 권한
                .compact();

        log.info("jwt : {}", jwt);

        return jwt;
    }

    /**
     * 🔐➡👩‍💼 토큰 해석
     *
     * Authorization : Bearer + {jwt}  (authHeader)
     * ➡ jwt 추출
     * ➡ UsernamePasswordAuthenticationToken
     * @param authHeader
     * @return
     * @throws Exception
     */
    public UsernamePasswordAuthenticationToken getAuthentication(String authHeader) {
        if(authHeader == null || authHeader.length() == 0 )
            return null;

        try {

            // jwt 추출
            String jwt = authHeader.replace(JwtConstants.TOKEN_PREFIX, "");

            // 🔐➡👩‍💼 JWT 파싱
            Jws<Claims> parsedToken = Jwts.parser()
                    .verifyWith(getShaKey())
                    .build()
                    .parseSignedClaims(jwt);

            log.info("parsedToken : {}" , parsedToken);

            // 인증된 사용자 번호
            String userIdx = parsedToken.getPayload().get("uno").toString();
            long no = ( userIdx == null ? 0 : Integer.parseInt(userIdx) );
            log.info("userIdx : : {}", userIdx);

            // 인증된 사용자 아이디
            String userId = parsedToken.getPayload().get("uid").toString();
            log.info("userId : {}", userId);

            // 인증된 사용자 권한
            Claims claims = parsedToken.getPayload();
            Object roles = claims.get("rol");
            log.info("roles : {}" , roles);


            // 토큰에 userId 있는지 확인
            if( userId == null || userId.length() == 0 )
                return null;


            UserDTO user = new UserDTO();
            user.setUserIdx(no);
            user.setUserId(userId);
            // OK: 권한도 바로 Users 객체에 담아보기
            List<UserAuthDTO> authList = ((List<?>) roles )
                    .stream()
                    .map(auth -> new UserAuthDTO(no, auth.toString()) )
                    .collect( Collectors.toList() );

            user.setAuthList(authList);

            // CustomeUser 에 권한 담기
            List<SimpleGrantedAuthority> authorities = ((List<?>) roles )
                    .stream()
                    .map(auth -> new SimpleGrantedAuthority( (String) auth ))
                    .collect( Collectors.toList() );


            UserDetails userDetails = new CustomUser(user);

            // new UsernamePasswordAuthenticationToken( 사용자정보객체, 비밀번호, 사용자의 권한(목록)  );
            return new UsernamePasswordAuthenticationToken(userDetails, null, authorities);

        } catch (ExpiredJwtException exception) {
            log.warn("Request to parse expired JWT : {} failed : {}", authHeader, exception.getMessage());
        } catch (UnsupportedJwtException exception) {
            log.warn("Request to parse unsupported JWT : {} failed : {}", authHeader, exception.getMessage());
        } catch (MalformedJwtException exception) {
            log.warn("Request to parse invalid JWT : {} failed : {}", authHeader, exception.getMessage());
        } catch (IllegalArgumentException exception) {
            log.warn("Request to parse empty or null JWT : {} failed : {}", authHeader, exception.getMessage());
        }

        return null;
    }

    /**
     * 토큰 유효성 검사
     * true : 유효
     * false : 만료
     * */
    public boolean validateToken(String jwt){

        try {
            // 🔐➡👩‍💼 JWT 파싱
            Jws<Claims> parsedToken = Jwts.parser()
                    .verifyWith(getShaKey())
                    .build()
                    .parseSignedClaims(jwt);

            log.info("###### 토큰 만료기간 #####");
            log.info("-> {}", parsedToken.getPayload().getExpiration());

            Date exp = parsedToken.getPayload().getExpiration();

            // 만료시간과 현재시간 비교
            // 2023.12.01 vs 2023.12.14 --> 만료 : true ---> false
            // 2023.12.30 vs 2023.12.14 --> 유효 : false ---> ture
            return !exp.before(new Date());

        } catch (ExpiredJwtException exception) {
            log.error("Token Expired");                 // 토큰 만료
            return false;
        } catch (JwtException exception) {
            log.error("Token Tampered");                // 토큰 손상
            return false;
        } catch (NullPointerException exception) {
            log.error("Token is null");                 // 토큰 없음
            return false;
        } catch (Exception e) {
            return false;
        }

    }

    // secretKey -> signingKey
    private byte[] getSigningKey() {
        return jwtProp.getSecretKey().getBytes();
    }

    // secretKey -> (HMAC-SHA algorithms) -> signingKey
    private SecretKey getShaKey(){
        return Keys.hmacShaKeyFor(getSigningKey());
    }
}
