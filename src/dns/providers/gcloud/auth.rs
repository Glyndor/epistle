//! The OAuth access token the Google Cloud provider asks for and caches.

use super::*;

impl GcloudProvider {
	/// Return a valid bearer access token, refreshing the cache when needed.
	pub(super) async fn ensure_token(&self) -> Result<String, ProviderError> {
		if let Some(cached) = self.cached.lock().unwrap().clone()
			&& cached.expires_at > Instant::now()
		{
			return Ok(cached.access_token);
		}
		let now = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs();
		let claims = json!({
			"iss": self.account.client_email,
			"scope": DNS_SCOPE,
			"aud": TOKEN_AUDIENCE,
			"iat": now,
			"exp": now + JWT_TTL_SECS,
		});
		let jwt = sign_rs256(&self.account.private_key, &claims)
			.map_err(|e| ProviderError::Remote(format!("jwt signing: {e:?}")))?;
		let body =
			format!("grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={jwt}");
		let response = self
			.client
			.post(self.token_base.with_segments(["token"])?.into_url())
			.header(
				reqwest::header::CONTENT_TYPE,
				"application/x-www-form-urlencoded",
			)
			.body(body)
			.send()
			.await
			.map_err(transport)?;
		Self::classify(&response, true)?;
		let text = self.read_body(response).await?;
		let parsed: Value =
			serde_json::from_str(&text).map_err(|e| ProviderError::Remote(e.to_string()))?;
		let access_token = parsed
			.get("access_token")
			.and_then(Value::as_str)
			.ok_or_else(|| ProviderError::Remote("missing access_token".into()))?
			.to_string();
		let expires_in = parsed
			.get("expires_in")
			.and_then(Value::as_u64)
			.unwrap_or(JWT_TTL_SECS);
		let expires_at =
			Instant::now() + Duration::from_secs(expires_in.saturating_sub(TOKEN_LEEWAY_SECS));
		*self.cached.lock().unwrap() = Some(CachedToken {
			access_token: access_token.clone(),
			expires_at,
		});
		Ok(access_token)
	}
}
