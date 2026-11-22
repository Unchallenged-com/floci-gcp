package io.floci.gcp.services.credentials;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@RegisterForReflection
public class StoredCredentialToken {

	public enum TokenKind {
		IMPERSONATED,
		DOWNSCOPED
	}

	private String tokenValue;
	private TokenKind tokenKind;
	private Instant expireTime;
	private String sourceToken;
	private String principal;
	private List<CredentialAccessBoundaryRule> gcsRules = new ArrayList<>();
	private boolean revoked;
	// Audit identity: the key a jwt-bearer exchange verified, and the principals that minted the token through
	// generateAccessToken, first delegator first.
	private String serviceAccountKeyName;
	private List<String> delegates = new ArrayList<>();

	public StoredCredentialToken() {
	}

	public StoredCredentialToken(String tokenValue, TokenKind tokenKind, Instant expireTime,
			String sourceToken, String principal, List<CredentialAccessBoundaryRule> gcsRules) {
		this.tokenValue = tokenValue;
		this.tokenKind = tokenKind;
		this.expireTime = expireTime;
		this.sourceToken = sourceToken;
		this.principal = principal;
		this.gcsRules = new ArrayList<>(gcsRules);
	}

	public String getTokenValue() {
		return tokenValue;
	}

	public void setTokenValue(String tokenValue) {
		this.tokenValue = tokenValue;
	}

	public TokenKind getTokenKind() {
		return tokenKind;
	}

	public void setTokenKind(TokenKind tokenKind) {
		this.tokenKind = tokenKind;
	}

	public Instant getExpireTime() {
		return expireTime;
	}

	public void setExpireTime(Instant expireTime) {
		this.expireTime = expireTime;
	}

	public String getSourceToken() {
		return sourceToken;
	}

	public void setSourceToken(String sourceToken) {
		this.sourceToken = sourceToken;
	}

	public String getPrincipal() {
		return principal;
	}

	public void setPrincipal(String principal) {
		this.principal = principal;
	}

	public List<CredentialAccessBoundaryRule> getGcsRules() {
		return gcsRules;
	}

	public void setGcsRules(List<CredentialAccessBoundaryRule> gcsRules) {
		this.gcsRules = gcsRules == null ? new ArrayList<>() : new ArrayList<>(gcsRules);
	}

	public boolean isRevoked() {
		return revoked;
	}

	public void setRevoked(boolean revoked) {
		this.revoked = revoked;
	}

	public String getServiceAccountKeyName() {
		return serviceAccountKeyName;
	}

	public void setServiceAccountKeyName(String serviceAccountKeyName) {
		this.serviceAccountKeyName = serviceAccountKeyName;
	}

	public List<String> getDelegates() {
		return delegates;
	}

	public void setDelegates(List<String> delegates) {
		this.delegates = delegates == null ? new ArrayList<>() : new ArrayList<>(delegates);
	}
}
