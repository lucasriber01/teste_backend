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
                .antMatchers("/h2-console/**").permitAll()
                .antMatchers("/reservation/**").permitAll()
                .antMatchers(HttpMethod.GET, "/categories/**").permitAll()
                .antMatchers(HttpMethod.GET, "/lands/**").permitAll()
                .antMatchers(HttpMethod.GET, "/metaverses").permitAll()
                .antMatchers(HttpMethod.POST, "/users").permitAll()
                .antMatchers(HttpMethod.POST, "/login").permitAll()

                .antMatchers(HttpMethod.POST, "/users/{id}").hasAnyRole(ROLE_CLIENT, ROLE_ADMIN) //verficar
                .antMatchers(HttpMethod.PUT, "/users/{id}").hasAnyRole(ROLE_CLIENT, ROLE_ADMIN) // verificar
                .antMatchers(HttpMethod.DELETE, "/users/{id}").hasAnyRole(ROLE_CLIENT, ROLE_ADMIN) //verificar
                .antMatchers(HttpMethod.POST, "/categories").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.PUT, "/categories").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.DELETE, "/categories").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.POST, "/lands").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.PUT, "/lands").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.DELETE, "/lands").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.POST, "/metaverses").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.PUT, "/metaverses").hasAnyRole(ROLE_ADMIN)
                .antMatchers(HttpMethod.DELETE, "/metaverses").hasAnyRole(ROLE_ADMIN)
//                .antMatchers(HttpMethod.GET, "/users").hasAnyRole(ROLE_CLIENT) // aisjiajsiasj
                .antMatchers(HttpMethod.GET, "/users").permitAll()
                .anyRequest().authenticated().and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    public ServletRegistrationBean h2servletRegistration() {
        ServletRegistrationBean registrationBean = new ServletRegistrationBean(new WebServlet());
        registrationBean.addUrlMappings("/h2-console/*");
        return registrationBean;
    }

}

// a234@gmail.com // almocogratis
