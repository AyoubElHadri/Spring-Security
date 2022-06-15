package com.example.springsecurity.auth;

import java.util.Optional;

public interface ApplicationDao {

    Optional<ApplicationUser> selectApplicationUserByUserName(String username);

}
