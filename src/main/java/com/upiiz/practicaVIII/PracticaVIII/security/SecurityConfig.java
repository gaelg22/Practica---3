package com.upiiz.practicaVIII.PracticaVIII.security;

import com.upiiz.practicaVIII.PracticaVIII.services.UsuarioDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.http.HttpMethod;

@Configuration
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final UsuarioDetailsServiceImpl usuarioDetailsService;

    public SecurityConfig(JwtAuthenticationFilter jwtFilter,
                          UsuarioDetailsServiceImpl usuarioDetailsService) {
        this.jwtFilter = jwtFilter;
        this.usuarioDetailsService = usuarioDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Desactivar CSRF porque usamos JWT
        http.csrf(csrf -> csrf.disable());

        // Stateless: no usamos sesiones
        http.sessionManagement(sm ->
                sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        // Configuración de rutas
        http.authorizeHttpRequests(auth -> auth

                // -----------------------------------------
                // ENDPOINTS PÚBLICOS (Login, Register y root)
                // -----------------------------------------
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/", "/health").permitAll()   // <-- /health agregado para Render

                // -----------------------------------------
                // GET públicos
                // -----------------------------------------
                .requestMatchers(HttpMethod.GET, "/api/jugadores").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/equipos").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/ligas").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/entrenadores").permitAll()

                // -----------------------------------------
                // Swagger público
                // -----------------------------------------
                .requestMatchers("/swagger-ui/**",
                        "/v3/api-docs/**",
                        "/swagger-resources/**",
                        "/webjars/**").permitAll()

                // H2 Console (solo si la usas)
                .requestMatchers("/h2-console/**").permitAll()

                // -----------------------------------------
                // POST protegidos por JWT
                // -----------------------------------------
                .requestMatchers(HttpMethod.POST, "/api/jugadores").authenticated()
                .requestMatchers(HttpMethod.POST, "/api/equipos").authenticated()
                .requestMatchers(HttpMethod.POST, "/api/entrenadores").authenticated()

                // -----------------------------------------
                // Cualquier otro request necesita token
                // -----------------------------------------
                .anyRequest().authenticated()
        );

        // Permitir frames (para H2 Console)
        http.headers(headers -> headers.frameOptions(frame -> frame.disable()));

        // Agregar filtro JWT antes del filtro de usuario/clave
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // Configuración de autenticación
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(usuarioDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        return config.getAuthenticationManager();
    }
}
