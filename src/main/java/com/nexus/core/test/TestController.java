package com.nexus.core.test;

import com.nexus.core.user.dao.UserDAO;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class TestController {
    private final UserDAO userDAO;
    
    @GetMapping("/test")
    public String index(){
        System.out.println("testController!!!!");
        System.out.println(userDAO.selectByUserId("apple75391"));
        
        return "";
    }
}
