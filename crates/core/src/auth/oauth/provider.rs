use async_trait::async_trait;
use oauth2::{
  AsyncHttpClient, AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
  EndpointNotSet, EndpointSet, HttpClientError, HttpRequest, HttpResponse, PkceCodeChallenge,
  PkceCodeVerifier, RedirectUrl, Scope, StandardRevocableToken, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use url::Url;

use crate::app_state::AppState;
use crate::auth::AuthError;
use crate::config::proto::OAuthProviderId;
use crate::constants::AUTH_API_PATH;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExtraTokenFields {
  /// The `OpenID` Connect ID token returned by some providers. Expected to be in JWT format.
  pub id_token: Option<String>,
}
impl oauth2::ExtraTokenFields for ExtraTokenFields {}

pub type TokenResponse =
  oauth2::StandardTokenResponse<ExtraTokenFields, oauth2::basic::BasicTokenType>;

pub type OAuthClient<
  HasAuthUrl = EndpointSet,
  HasDeviceAuthUrl = EndpointNotSet,
  HasIntrospectionUrl = EndpointNotSet,
  HasRevocationUrl = EndpointNotSet,
  HasTokenUrl = EndpointSet,
> = oauth2::Client<
  oauth2::basic::BasicErrorResponse,
  TokenResponse,
  oauth2::basic::BasicTokenIntrospectionResponse,
  StandardRevocableToken,
  oauth2::basic::BasicRevocationErrorResponse,
  HasAuthUrl,
  HasDeviceAuthUrl,
  HasIntrospectionUrl,
  HasRevocationUrl,
  HasTokenUrl,
>;

#[derive(Serialize, Deserialize, Debug)]
pub struct OAuthUser {
  pub provider_user_id: String,
  pub provider_id: OAuthProviderId,

  pub email: String,
  pub verified: bool,

  pub avatar: Option<String>,
}

#[derive(Debug)]
pub struct OAuthClientSettings {
  pub auth_url: Url,
  pub token_url: Url,
  pub client_id: String,
  pub client_secret: String,
}

pub(crate) fn build_oauth_http_client() -> Result<reqwest::Client, AuthError> {
  reqwest::ClientBuilder::new()
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .map_err(|err| AuthError::Internal(err.into()))
}

pub(crate) struct ReqwestClient(pub reqwest::Client);

impl<'c> AsyncHttpClient<'c> for ReqwestClient {
  type Error = HttpClientError<reqwest::Error>;

  #[cfg(target_arch = "wasm32")]
  type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + 'c>>;
  #[cfg(not(target_arch = "wasm32"))]
  type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

  fn call(&'c self, request: HttpRequest) -> Self::Future {
    Box::pin(async move {
      let response = self
        .0
        .execute(request.try_into().map_err(Box::new)?)
        .await
        .map_err(Box::new)?;

      let mut builder = axum::http::Response::builder().status(response.status());

      #[cfg(not(target_arch = "wasm32"))]
      {
        builder = builder.version(response.version());
      }

      for (name, value) in response.headers().iter() {
        builder = builder.header(name, value);
      }

      builder
        .body(response.bytes().await.map_err(Box::new)?.to_vec())
        .map_err(HttpClientError::Http)
    })
  }
}

#[async_trait]
pub trait OAuthProvider {
  #[allow(unused)]
  fn provider(&self) -> OAuthProviderId;

  fn name(&self) -> &str;

  fn display_name(&self) -> &str;

  fn settings(&self) -> Result<OAuthClientSettings, AuthError>;

  fn oauth_client(&self, state: &AppState) -> Result<OAuthClient, AuthError> {
    let Some(ref site_url) = *state.site_url() else {
      return Err(AuthError::Internal(
        "Missing site_url for redirect back from external provider to your TB instance".into(),
      ));
    };

    let redirect_url: Url = site_url
      .join(&format!(
        "/{AUTH_API_PATH}/oauth/{name}/callback",
        name = self.name()
      ))
      .map_err(|err| AuthError::FailedDependency(err.into()))?;

    let settings = self.settings()?;
    if settings.client_id.is_empty() {
      return Err(AuthError::Internal(
        format!("Missing client id for {}", self.name()).into(),
      ));
    }
    if settings.client_secret.is_empty() {
      return Err(AuthError::Internal(
        format!("Missing client secret for {}", self.name()).into(),
      ));
    }

    let client = Client::new(ClientId::new(settings.client_id))
      .set_client_secret(ClientSecret::new(settings.client_secret))
      .set_auth_uri(AuthUrl::from_url(settings.auth_url))
      .set_token_uri(TokenUrl::from_url(settings.token_url))
      .set_redirect_uri(RedirectUrl::from_url(redirect_url));

    return Ok(client);
  }

  fn oauth_scopes(&self) -> Vec<&'static str>;

  fn use_pkce(&self) -> bool {
    true
  }

  fn oauth_authorize_params(&self) -> Vec<(&'static str, &'static str)> {
    vec![]
  }

  fn authorize_url(
    &self,
    state: &AppState,
    server_pkce_code_challenge: PkceCodeChallenge,
  ) -> Result<(Url, CsrfToken), AuthError> {
    let oauth_client = self.oauth_client(state)?;

    let (authorize_url, csrf_state) = if self.use_pkce() {
      let authorize_request = oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(
          self
            .oauth_scopes()
            .into_iter()
            .map(|scope| Scope::new(scope.to_string())),
        )
        .set_pkce_challenge(server_pkce_code_challenge);

      self
        .oauth_authorize_params()
        .into_iter()
        .fold(authorize_request, |request, (name, value)| {
          request.add_extra_param(name, value)
        })
        .url()
    } else {
      let authorize_request = oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(
          self
            .oauth_scopes()
            .into_iter()
            .map(|scope| Scope::new(scope.to_string())),
        );

      self
        .oauth_authorize_params()
        .into_iter()
        .fold(authorize_request, |request, (name, value)| {
          request.add_extra_param(name, value)
        })
        .url()
    };

    Ok((authorize_url, csrf_state))
  }

  async fn get_user_from_code(
    &self,
    state: &AppState,
    auth_code: String,
    server_pkce_code_verifier: String,
  ) -> Result<OAuthUser, AuthError> {
    let http_client = build_oauth_http_client()?;
    let oauth_client = self.oauth_client(state)?;

    let token_response: TokenResponse = if self.use_pkce() {
      oauth_client
        .exchange_code(AuthorizationCode::new(auth_code))
        .set_pkce_verifier(PkceCodeVerifier::new(server_pkce_code_verifier))
        .request_async(&ReqwestClient(http_client))
        .await
        .map_err(|err| AuthError::FailedDependency(err.into()))?
    } else {
      oauth_client
        .exchange_code(AuthorizationCode::new(auth_code))
        .request_async(&ReqwestClient(http_client))
        .await
        .map_err(|err| AuthError::FailedDependency(err.into()))?
    };

    self.get_user(&token_response).await
  }

  //async fn get_user(&self, access_token: &oauth2::AccessToken) -> Result<OAuthUser, AuthError>;
  async fn get_user(&self, token_response: &TokenResponse) -> Result<OAuthUser, AuthError>;
}
