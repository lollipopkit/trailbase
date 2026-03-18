use async_trait::async_trait;
use base64::Engine as _;
use lazy_static::lazy_static;
use oauth2::{CsrfToken, PkceCodeChallenge};
use serde::Deserialize;
use url::Url;

use crate::app_state::AppState;
use crate::auth::AuthError;
use crate::auth::oauth::provider::{TokenResponse, build_oauth_http_client};
use crate::auth::oauth::providers::{OAuthProviderError, OAuthProviderFactory};
use crate::auth::oauth::{OAuthClientSettings, OAuthProvider, OAuthUser};
use crate::config::proto::{OAuthProviderConfig, OAuthProviderId};
use crate::constants::AUTH_API_PATH;

pub(crate) struct WeChatOAuthProvider {
  client_id: String,
  client_secret: String,
}

#[derive(Debug, Deserialize)]
struct WeChatTokenResponse {
  access_token: String,
  openid: String,
  unionid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WeChatUser {
  openid: String,
  headimgurl: Option<String>,
  unionid: Option<String>,
}

impl WeChatOAuthProvider {
  const NAME: &'static str = "wechat";
  const DISPLAY_NAME: &'static str = "WeChat";

  const AUTH_URL: &'static str = "https://open.weixin.qq.com/connect/qrconnect#wechat_redirect";
  const TOKEN_URL: &'static str = "https://api.weixin.qq.com/sns/oauth2/access_token";
  const USER_API_URL: &'static str = "https://api.weixin.qq.com/sns/userinfo";
  const SYNTHETIC_EMAIL_DOMAIN: &'static str = "wechat.oauth.invalid";

  fn new(config: &OAuthProviderConfig) -> Result<Self, OAuthProviderError> {
    let Some(client_id) = config.client_id.clone() else {
      return Err(OAuthProviderError::Missing("WeChat client id".to_string()));
    };
    let Some(client_secret) = config.client_secret.clone() else {
      return Err(OAuthProviderError::Missing(
        "WeChat client secret".to_string(),
      ));
    };

    Ok(Self {
      client_id,
      client_secret,
    })
  }

  pub fn factory() -> OAuthProviderFactory {
    OAuthProviderFactory {
      id: OAuthProviderId::Wechat,
      factory_name: Self::NAME,
      factory_display_name: Self::DISPLAY_NAME,
      factory: Box::new(|_name: &str, config: &OAuthProviderConfig| {
        Ok(Box::new(Self::new(config)?))
      }),
    }
  }

  fn synthetic_email(provider_user_id: &str) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(provider_user_id);
    format!("{encoded}@{}", Self::SYNTHETIC_EMAIL_DOMAIN)
  }

  async fn exchange_code(
    &self,
    state: &AppState,
    auth_code: String,
  ) -> Result<WeChatTokenResponse, AuthError> {
    let Some(ref site_url) = *state.site_url() else {
      return Err(AuthError::Internal(
        "Missing site_url for redirect back from external provider to your TB instance".into(),
      ));
    };

    let _redirect_url = site_url
      .join(&format!("/{AUTH_API_PATH}/oauth/{}/callback", Self::NAME))
      .map_err(|err| AuthError::FailedDependency(err.into()))?;

    let mut token_url = Url::parse(Self::TOKEN_URL).expect("infallible");
    token_url.query_pairs_mut().extend_pairs([
      ("appid", self.client_id.as_str()),
      ("secret", self.client_secret.as_str()),
      ("code", auth_code.as_str()),
      ("grant_type", "authorization_code"),
    ]);

    let response = build_oauth_http_client()?
      .get(token_url)
      .send()
      .await
      .map_err(|err| AuthError::FailedDependency(err.into()))?;

    response
      .json::<WeChatTokenResponse>()
      .await
      .map_err(|err| AuthError::FailedDependency(err.into()))
  }
}

#[async_trait]
impl OAuthProvider for WeChatOAuthProvider {
  fn name(&self) -> &'static str {
    Self::NAME
  }

  fn provider(&self) -> OAuthProviderId {
    OAuthProviderId::Wechat
  }

  fn display_name(&self) -> &'static str {
    Self::DISPLAY_NAME
  }

  fn settings(&self) -> Result<OAuthClientSettings, AuthError> {
    lazy_static! {
      static ref AUTH_URL: Url = Url::parse(WeChatOAuthProvider::AUTH_URL).expect("infallible");
      static ref TOKEN_URL: Url = Url::parse(WeChatOAuthProvider::TOKEN_URL).expect("infallible");
    }

    Ok(OAuthClientSettings {
      auth_url: AUTH_URL.clone(),
      token_url: TOKEN_URL.clone(),
      client_id: self.client_id.clone(),
      client_secret: self.client_secret.clone(),
    })
  }

  fn oauth_scopes(&self) -> Vec<&'static str> {
    vec!["snsapi_login"]
  }

  fn use_pkce(&self) -> bool {
    false
  }

  fn authorize_url(
    &self,
    state: &AppState,
    _server_pkce_code_challenge: PkceCodeChallenge,
  ) -> Result<(Url, CsrfToken), AuthError> {
    let Some(ref site_url) = *state.site_url() else {
      return Err(AuthError::Internal(
        "Missing site_url for redirect back from external provider to your TB instance".into(),
      ));
    };

    let redirect_url = site_url
      .join(&format!("/{AUTH_API_PATH}/oauth/{}/callback", Self::NAME))
      .map_err(|err| AuthError::FailedDependency(err.into()))?;

    let csrf_state = CsrfToken::new_random();
    let csrf_secret = csrf_state.secret().to_string();
    let mut auth_url = Url::parse(Self::AUTH_URL).expect("infallible");
    auth_url.query_pairs_mut().extend_pairs([
      ("appid", self.client_id.as_str()),
      ("redirect_uri", redirect_url.as_str()),
      ("response_type", "code"),
      ("scope", "snsapi_login"),
      ("state", csrf_secret.as_str()),
    ]);

    Ok((auth_url, csrf_state))
  }

  async fn get_user_from_code(
    &self,
    state: &AppState,
    auth_code: String,
    _server_pkce_code_verifier: String,
  ) -> Result<OAuthUser, AuthError> {
    let token = self.exchange_code(state, auth_code).await?;
    let mut user_api_url = Url::parse(Self::USER_API_URL).expect("infallible");
    user_api_url.query_pairs_mut().extend_pairs([
      ("access_token", token.access_token.as_str()),
      ("openid", token.openid.as_str()),
      ("lang", "en"),
    ]);

    let response = build_oauth_http_client()?
      .get(user_api_url)
      .send()
      .await
      .map_err(|err| AuthError::FailedDependency(err.into()))?;

    let user = response
      .json::<WeChatUser>()
      .await
      .map_err(|err| AuthError::FailedDependency(err.into()))?;

    let provider_user_id = user
      .unionid
      .or(token.unionid)
      .unwrap_or_else(|| user.openid.clone());

    Ok(OAuthUser {
      provider_user_id: provider_user_id.clone(),
      provider_id: OAuthProviderId::Wechat,
      email: Self::synthetic_email(&provider_user_id),
      verified: true,
      avatar: user.headimgurl,
    })
  }

  async fn get_user(&self, _token_response: &TokenResponse) -> Result<OAuthUser, AuthError> {
    Err(AuthError::Internal(
      "WeChat OAuth uses a custom authorization code exchange flow".into(),
    ))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::HashMap;

  use oauth2::PkceCodeChallenge;

  use crate::app_state::{TestStateOptions, test_state};
  use crate::auth::oauth::OAuthProvider;
  use crate::config::proto::{Config, OAuthProviderConfig, OAuthProviderId};

  #[test]
  fn synthetic_email_is_stable_and_non_deliverable() {
    let email = WeChatOAuthProvider::synthetic_email("unionid-123");

    assert_eq!(email, "dW5pb25pZC0xMjM@wechat.oauth.invalid");
  }

  #[test]
  fn wechat_provider_disables_pkce() {
    let provider = WeChatOAuthProvider {
      client_id: "client-id".to_string(),
      client_secret: "client-secret".to_string(),
    };

    assert!(!provider.use_pkce());
    assert_eq!(provider.oauth_scopes(), vec!["snsapi_login"]);
  }

  #[tokio::test]
  async fn wechat_authorize_url_uses_appid_instead_of_client_id() {
    let mut config = Config::new_with_custom_defaults();
    config.server.site_url = Some("https://example.com".to_string());
    config.auth.oauth_providers.insert(
      WeChatOAuthProvider::NAME.to_string(),
      OAuthProviderConfig {
        client_id: Some("wechat-app-id".to_string()),
        client_secret: Some("wechat-secret".to_string()),
        provider_id: Some(OAuthProviderId::Wechat as i32),
        ..Default::default()
      },
    );

    let state = test_state(Some(TestStateOptions {
      config: Some(config),
      ..Default::default()
    }))
    .await
    .unwrap();

    let auth_options = state.auth_options();
    let provider = auth_options
      .lookup_oauth_provider(WeChatOAuthProvider::NAME)
      .unwrap();
    let (pkce_code_challenge, _) = PkceCodeChallenge::new_random_sha256();
    let (authorize_url, csrf_state) = provider.authorize_url(&state, pkce_code_challenge).unwrap();

    let query: HashMap<_, _> = authorize_url.query_pairs().collect();
    assert_eq!(query.get("appid").unwrap(), "wechat-app-id");
    assert_eq!(query.get("response_type").unwrap(), "code");
    assert_eq!(query.get("scope").unwrap(), "snsapi_login");
    assert_eq!(query.get("state").unwrap(), csrf_state.secret());
    assert_eq!(
      query.get("redirect_uri").unwrap(),
      "https://example.com/api/auth/v1/oauth/wechat/callback"
    );
    assert!(query.get("client_id").is_none());
    assert_eq!(authorize_url.fragment(), Some("wechat_redirect"));
  }
}
