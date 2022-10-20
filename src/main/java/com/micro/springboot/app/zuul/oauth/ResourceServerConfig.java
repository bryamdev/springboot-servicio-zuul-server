package com.micro.springboot.app.zuul.oauth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@RefreshScope
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter{
	
	@Value("${config.security.oauth.jwt.key}")
	private String jwtKey;
	
	//Configura el generador de token (mismo bean del AuthServer)
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.tokenStore(tokenStore());
	}
	
	//Configurando las reglas de autorizacion para los endpoints de los servicios ruteados.
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers("/api/v1/oauth/oauth/**").permitAll()
			.antMatchers(HttpMethod.GET, "/api/v1/productos/listar", 
					"/api/v1/items/listar", "/api/v1/usuarios/usuarios").permitAll()
			.antMatchers(HttpMethod.GET, "/api/v1/productos/ver/{id}",
					"/api/v1/items/ver/{id}/cantidad/{cantidad}",
					"/api/v1/usuarios/usuarios/{id}").hasAnyRole("ADMIN", "USER")
			.antMatchers(HttpMethod.POST, "/api/v1/productos/crear",
					"/api/v1/items/crear", "/api/v1/usuarios/usuarios").hasAnyRole("ADMIN")
			.antMatchers(HttpMethod.PUT, "/api/v1/productos/editar/{id}",
					"/api/v1/items/editar/{id}", "/api/v1/usuarios/usuarios/{id}").hasAnyRole("ADMIN")
			.antMatchers(HttpMethod.DELETE, "/api/v1/productos/eliminar/{id}",
					"/api/v1/items/eliminar/{id}", "/api/v1/usuarios/usuarios/{id}").hasAnyRole("ADMIN")
			.anyRequest().authenticated();
		
	}

	@Bean
	public JwtTokenStore tokenStore() {
		return new JwtTokenStore(accesTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter accesTokenConverter() {		
		JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
		accessTokenConverter.setSigningKey(jwtKey);
		return accessTokenConverter;
	}	
	
}
