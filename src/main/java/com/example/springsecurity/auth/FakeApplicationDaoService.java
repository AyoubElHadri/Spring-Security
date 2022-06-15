package com.example.springsecurity.auth;

import com.example.springsecurity.security.ApplicationUserRole;
import com.google.common.collect.Lists;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository("fake")
@AllArgsConstructor
public class FakeApplicationDaoService implements ApplicationDao {

    private final PasswordEncoder passwordEncoder;
    @Override
    public Optional<ApplicationUser> selectApplicationUserByUserName(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername())).findFirst();
    }
    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUserList = Lists.newArrayList(
                new ApplicationUser("lalo",
                        passwordEncoder.encode("user"),
                        ApplicationUserRole.STUDENT.getGrantedAuthority(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser("gustavo",
                        passwordEncoder.encode("admin"),
                        ApplicationUserRole.ADMIN.getGrantedAuthority(),
                        true,
                        true,
                        true,
                        true
                ),
                new ApplicationUser("jesse",
                        passwordEncoder.encode("trainee"),
                        ApplicationUserRole.ADMINTRAINEE.getGrantedAuthority(),
                        true,
                        true,
                        true,
                        true
                )

        );
        return applicationUserList;
    }
}
