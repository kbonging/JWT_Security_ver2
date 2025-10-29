package com.nexus.core.security.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nexus.core.security.custom.CustomUser;
import com.nexus.core.security.jwt.constants.JwtConstants;
import com.nexus.core.security.jwt.provider.JwtTokenProvider;
import com.nexus.core.user.dto.UserDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

/**         (/login)
 * client -> filter -> server
 * username, password 인증 시도 (attemptAuthentication)
 *      인증 실패 : response > status : 401 (NUATHORIZED)
 *
 *      인증 성공 (successfulAuthentication)
 *      -> JWT 생성
 *      -> response > headers > authorization : (JWT)
 * */
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;

        setFilterProcessesUrl(JwtConstants.AUTH_LOGIN_URL);
    }

    /**
     * 인증 시도 메소드
     * : /login 경로로 (username, password) 를 요청하면 이 필터에서 걸려 인증을 시도
     * Authentication 인증 시도한 사용자 인증 객체를 반환하여, 시큐리티가 인증 성공 여부를 판단하게 함
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        UserDTO user = new UserDTO();

        try {
            // JSON 형식 파싱
            ObjectMapper objectMapper = new ObjectMapper();
            user = objectMapper.readValue(request.getInputStream(), UserDTO.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // 클라이언트에서 전달받은 로그인 정보
        String username = user.getUserId();
        String password = user.getUserPw();

        log.info("userId : {}", username);
        log.info("userPw : {}", password);

        // 인증 토큰 생성
        Authentication authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        try {
            // 사용자 인증 시도
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            log.info("authenticationManager : {}", authenticationManager);
            log.info("authentication : {}", authentication);
            log.info("인증 여부 : {}", authentication.isAuthenticated());

            return authentication;

        } catch (AuthenticationException e) {
            log.warn("인증 실패: {}", e.getMessage());  // 실제 예외 메시지를 그대로 출력
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            throw e;
        }
    }

    /**
     * 인증 성공 메서드
     *
     *  - JWT 을 생성
     *  - JWT 를 응답 헤더에 설정
     * */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        log.info("인증 성공...");

        CustomUser user = (CustomUser) authentication.getPrincipal();
        long userIdx = user.getUser().getUserIdx();
        String userId = user.getUser().getUserId();

        List<String> roles = user.getUser().getAuthList()
                .stream()
                .map( (auth) -> auth.getAuth()).collect(Collectors.toList());

        // JWT
        String jwt = jwtTokenProvider.createToken(userIdx, userId, roles);

        // { Authentication : Bearer + {jwt} }
        response.addHeader(JwtConstants.TOKEN_HEADER, JwtConstants.TOKEN_PREFIX + jwt);
        response.setStatus(200); // 200 > 정상적으로 처리
    }
}
