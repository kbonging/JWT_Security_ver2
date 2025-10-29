package com.nexus.core.user.dao;

import com.nexus.core.user.dto.UserDTO;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserDAO {
    /** 회원 아이디로 정보 조회 */
    UserDTO selectByUserId(String userId);
}
