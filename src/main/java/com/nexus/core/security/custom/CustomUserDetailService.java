package com.nexus.core.security.custom;

import com.nexus.core.user.dao.UserDAO;
import com.nexus.core.user.dto.UserDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {
    private final UserDAO userDAO;

    @Override
    public UserDetails loadUserByUsername(String username) {
        log.info("login - loadUserByUsername : {}", username);

        UserDTO user = userDAO.selectByUserId(username);

        if(user == null){
            log.info("사용자 없음... (일치하는 아이디가 없음)");
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다. : " + username);
        }

        log.info("user : {}", user.toString());

        // UserDTO -> CustomUser
        CustomUser customUser = new CustomUser(user);

        log.info("customUser : ");
        log.info(customUser.toString());

        return customUser;
    }
}
