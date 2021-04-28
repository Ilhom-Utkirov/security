package com.example.demo.auth;

import java.util.Optional;

public interface ApplicationUserDao {

   Optional<ApplicationUser> selectapplicationUserByUsername(String username);

}
