package com.nexus.core.user.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class UserAuthDTO {
    /** 권한 고유 번호 */
    private long authIdx;
    /** 사용자 고유 번호*/
    private long userIdx;
    /** 권한 */
    private String auth;

    public UserAuthDTO() {
    }

    public UserAuthDTO(long userIdx, String auth) {
        this.userIdx = userIdx;
        this.auth = auth;
    }
}
