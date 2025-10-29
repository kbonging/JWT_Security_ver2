package com.nexus.core.security.custom;

import com.nexus.core.user.dto.UserAuthDTO;
import com.nexus.core.user.dto.UserDTO;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@ToString
public class CustomUser implements UserDetails {
    private UserDTO user;

    public CustomUser(UserDTO user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<UserAuthDTO> authList = user.getAuthList();


        Collection<SimpleGrantedAuthority> roleList = authList.stream()
                .map((auth) -> new SimpleGrantedAuthority(auth.getAuth()))
                .collect(Collectors.toList());
        return roleList;
    }

    @Override
    public String getPassword() {
        return user.getUserPw();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }
}
