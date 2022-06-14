package com.example.springsecurity.security;

import com.example.springsecurity.SpringSecurityApplication;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

         http
                 .authorizeRequests()
                 .antMatchers("/", "index").permitAll()
                 .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
                 .anyRequest()
                 .authenticated()
                 .and()
                 .httpBasic();

        return http.build();
    }

    @Bean
    protected UserDetailsService userDetailsService(){
       UserDetails laloUser = User.builder()
                .username("lalo")
                .password(passwordEncoder.encode("user"))
                .roles(ApplicationUserRole.STUDENT.name())
               .build();
        UserDetails gustavoUser = User.builder()
                .username("gustavo")
                .password(passwordEncoder.encode("admin"))
                .roles(ApplicationUserRole.ADMIN.name())
                .build();
        UserDetails jesseUser = User.builder()
                .username("jesse")
                .password(passwordEncoder.encode("trainee"))
                .roles(ApplicationUserRole.ADMINTRAINEE.name())
                .build();

        return new InMemoryUserDetailsManager(
                gustavoUser,
                laloUser,
                jesseUser
        );
    }



}
//- http authorizeRequest (create whitelist) antmatcher(indexcssjs) permitall anyrequest athenticationand httpbasic