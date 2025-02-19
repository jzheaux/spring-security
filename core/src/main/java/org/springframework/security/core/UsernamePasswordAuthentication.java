package org.springframework.security.core;

import java.util.Collection;
import java.util.Objects;

import org.springframework.security.core.authority.AuthorityUtils;

public record UsernamePasswordAuthentication(String username, Collection<GrantedAuthority> authorities) implements GrantedAuthentication<String>{
	public UsernamePasswordAuthentication(String username, String... authorities) {
		this(username, AuthorityUtils.createAuthorityList(authorities));
	}

	@Override
	public String principal() {
		return this.username;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof UsernamePasswordAuthentication that)) return false;
		return Objects.equals(this.username, that.username);
	}

	@Override
	public int hashCode() {
		return Objects.hashCode(this.username);
	}
}
