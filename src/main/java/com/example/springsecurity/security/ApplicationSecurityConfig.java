package com.example.springsecurity.security;

import com.example.springsecurity.SpringSecurityApplication;
import com.example.springsecurity.auth.ApplicationUserService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;



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
                     .loginPage("/login").permitAll()
                     .defaultSuccessUrl("/courses",true)
//                     .passwordParameter("password")
//                     .usernameParameter("username")
                 .and()
                 .rememberMe()
                     .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(30))
                     .key("secured");
//                    .rememberMeParameter("remember-me");
/*                 .and()
                 .logout()
                 .logoutUrl("/logout")
                 .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                 .clearAuthentication(true)
                 .invalidateHttpSession(true)
                 .deleteCookies("JSESSIONID", "remember-me")
                 .logoutSuccessUrl("/login");*/

        return http.build();
    }

    /*@Bean
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
    }*/
/*    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.authenticationProvider(daoAuthenticationProvider());
    }*/


    protected AuthenticationManager authenticationManager(AuthenticationManagerBuilder builder) throws Exception {
        return (AuthenticationManager) builder.authenticationProvider(daoAuthenticationProvider());
    }
    @Bean
public DaoAuthenticationProvider daoAuthenticationProvider(){
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setPasswordEncoder(passwordEncoder);
    provider.setUserDetailsService(applicationUserService);
    return provider;
}


}