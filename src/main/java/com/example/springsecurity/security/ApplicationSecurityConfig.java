package com.example.springsecurity.security;

import com.example.springsecurity.SpringSecurityApplication;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

         http
//                 .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                 .and()
                 .csrf().disable()
                 .authorizeRequests()
                 .antMatchers("/", "index").permitAll()
                 .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
                 /* WE CAN USE ANNOTATIONS INSTEAD @PreAuthorize IN CONTROLLER CLASS and
                 @EnableGlobalMethodSecurity(prePostEnabled = true) in this class*/
                 .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                 .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                 .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                 .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())

                 .anyRequest()
                 .authenticated()
                 .and()
                 .formLogin()
                 .loginPage("/login").permitAll();

        return http.build();
    }

    @Bean
    protected UserDetailsService userDetailsService(){
       UserDetails laloUser = User.builder()
                .username("lalo")
                .password(passwordEncoder.encode("user"))
               // .roles(ApplicationUserRole.STUDENT.name())
               .authorities(ApplicationUserRole.STUDENT.getGrantedAuthority())
               .build();
        UserDetails gustavoUser = User.builder()
                .username("gustavo")
                .password(passwordEncoder.encode("admin"))
               // .roles(ApplicationUserRole.ADMIN.name())
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthority())

                .build();
        UserDetails jesseUser = User.builder()
                .username("jesse")
                .password(passwordEncoder.encode("trainee"))
              //  .roles(ApplicationUserRole.ADMINTRAINEE.name())
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthority())

                .build();

        return new InMemoryUserDetailsManager(
                gustavoUser,
                laloUser,
                jesseUser
        );
    }



}
//- http authorizeRequest (create whitelist) antmatcher(indexcssjs) permitall anyrequest athenticationand httpbasic