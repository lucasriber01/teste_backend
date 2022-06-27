package com.dhbrasil.projetoIntegrador.AlugaVerso.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.h2.server.web.WebServlet;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String[] PUBLIC = { "/h2-console/**" };
    private static final String[] OPERATOR_GET = { "/hello", "/categories", "/lands/**",  "/metaverses", "/lands/search/metaverse", "/lands/search/category", "/lands/search/**"};
    private static final String[] OPERATOR_GET_RESERVATION = { "/reservation", "/reservation/{id}"};
    private static final String[] OPERATOR_POST = { "/users", "/login"};
    private static final String[] OPERATOR_DELETE = { "/users/{id}", "/reservation/{id}"};
    private static final String ROLE_CLIENT = "CLIENT";
    private static final String ROLE_ADMIN = "ADMIN";

    @Autowired
    private Environment env;

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration().applyPermitDefaultValues();
        configuration.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "OPTIONS"));
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.headers().frameOptions().disable();
        http.cors().and().csrf().disable()
                .addFilterAfter(new JWTFilter(), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers(PUBLIC).permitAll()
                .antMatchers(HttpMethod.GET, OPERATOR_GET).permitAll() //ok
                .antMatchers(HttpMethod.POST, OPERATOR_POST).permitAll() //ok
                .antMatchers(HttpMethod.DELETE, "/reservation/me").hasAnyRole(ROLE_CLIENT, ROLE_ADMIN)
                .antMatchers(HttpMethod.DELETE, OPERATOR_DELETE).hasAnyRole(ROLE_ADMIN) //ok
                // User
                .antMatchers(HttpMethod.GET, "/users").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.GET, "/users/me").hasAnyRole(ROLE_CLIENT, ROLE_ADMIN)
                .antMatchers(HttpMethod.GET, "/users/{id}").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.PUT, "/users/me").hasAnyRole(ROLE_CLIENT, ROLE_ADMIN)
                .antMatchers(HttpMethod.PUT, "/users/{id}").hasAnyRole(ROLE_ADMIN)

                //Reservation
                .antMatchers(HttpMethod.GET, OPERATOR_GET_RESERVATION).hasAnyRole(ROLE_ADMIN)//
                .antMatchers(HttpMethod.GET, "/reservation/me").hasAnyRole(ROLE_CLIENT, ROLE_ADMIN)
                .antMatchers(HttpMethod.GET, "/reservation/filter/user").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.GET, "/reservation/filter/me").hasAnyRole(ROLE_CLIENT,ROLE_ADMIN)
                .antMatchers(HttpMethod.GET, "/reservation/filter/lands").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.PUT, "/reservation/me").hasAnyRole(ROLE_CLIENT, ROLE_ADMIN)
                .antMatchers(HttpMethod.PUT, "/reservation/{id}").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.POST, "/reservation/me").hasAnyRole(ROLE_CLIENT, ROLE_ADMIN)

                // Categories
                .antMatchers("/categories/**").hasAnyRole(ROLE_ADMIN) //ok
//
                // Lands
                .antMatchers("/lands/**").hasAnyRole(ROLE_ADMIN)// ok

                // Metaverses
                .antMatchers("/metaverses").hasAnyRole(ROLE_ADMIN) //ok

                .anyRequest().authenticated().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    public ServletRegistrationBean h2servletRegistration() {
        ServletRegistrationBean registrationBean = new ServletRegistrationBean(new WebServlet());
        registrationBean.addUrlMappings("/h2-console/*");
        return registrationBean;
    }

}
