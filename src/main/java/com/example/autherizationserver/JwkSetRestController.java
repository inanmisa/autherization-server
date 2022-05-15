package com.example.autherizationserver;

import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class JwkSetRestController {

	@Autowired
	JWKSource<SecurityContext> jwkSource;

	@GetMapping("/.well-known/jwks2.json")
	public Map<String, Object> keys() {
		return ((ImmutableJWKSet)this.jwkSource).getJWKSet().toJSONObject();
	}
}