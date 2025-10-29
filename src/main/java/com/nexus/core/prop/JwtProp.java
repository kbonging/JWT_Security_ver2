package com.nexus.core.prop;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties("com.nexus.core")
public class JwtProp {
    // 인코딩된 시크릿 키
    private String secretKey;
}
