use std::collections::HashMap;

use anyhow::{self, Context};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use url::Url;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client_id = std::env::var("CLIENT_ID").context("missing CLIENT_ID")?;
    let client_secret = std::env::var("CLIENT_SECRET").context("missing CLIENT_SECRET")?;
    let domain = std::env::var("DOMAIN").context("missing DOMAIN")?;

    let data = reqwest::get(format!("https://{}/.well-known/openid-configuration", domain))
        .await?
        .json::<serde_json::Value>()
        .await?;

    let auth_endpoint = data["authorization_endpoint"].as_str().context("Missing require oidc field: authorization_endpoint")?;
    let token_endpoint = data["token_endpoint"].as_str().context("Missing require oidc field: authorization_endpoint")?;
    let user_info_endpoint = data["userinfo_endpoint"].as_str().context("Missing require oidc field: authorization_endpoint")?;

    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
        AuthUrl::new(auth_endpoint.to_string())?,
        Some(TokenUrl::new(token_endpoint.to_string())?),
    )
    // Set the URL the user will be redirected to after the authorization process.
    // user will actually go back to `https://localhost:3000/callback?code=...&state=...`
    //.set_redirect_uri(RedirectUrl::new("https://2143.me/auth/callback".to_string())?);
    .set_redirect_uri(RedirectUrl::new("http://localhost:3000/auth/callback".to_string())?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL. This should be unique for each new login.
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        // required
        .add_scope(Scope::new("openid".to_string()))
        //.add_scope(Scope::new("groups".to_string()))
        // optional
        //.add_scope(Scope::new("profile".to_string()))
        //.add_scope(Scope::new("offline_access".to_string()))
        // PII
        //.add_scope(Scope::new("email".to_string()))
        //.add_scope(Scope::new("phone".to_string()))
        //.add_scope(Scope::new("address".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    println!("Browse to: {}", auth_url);

    println!("Paste the full redirect URL here: (make sure to copy the entire URL)");
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer)?;

    // Parse the redirect URL.
    let url = Url::parse(&buffer)?;
    let query_params = url
        .query_pairs()
        .collect::<HashMap<_, _>>();

    println!("We found the following query parameters: {:#?}", query_params);
    // {
    //     "code": "4/0AeanS...",
    //     "prompt": "consent",
    //     "scope": "openid",
    //     "authuser": "0",
    //     "state": "RPKbLPc7z...",
    // }

    let callback_code = query_params.get("code").context("missing code in callback uri")?;
    let callback_state = query_params.get("state").context("missing state in callback uri")?;

    anyhow::ensure!(callback_state == csrf_token.secret(), "Client CSRF token does not match server CSRF token");

    // Server can trade code from client for a bearer token
    let token_result = client
        .exchange_code(AuthorizationCode::new(
            callback_code.to_string(),
        ))
        //.add_extra_param("grant_type", "authorization_code")
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await;

    let bearer_token = match token_result {
        Ok(token) => {
            //&token = StandardTokenResponse {
            //    access_token: AccessToken([redacted]),
            //    token_type: Bearer,
            //    expires_in: Some(
            //        86400,
            //    ),
            //    refresh_token: None,
            //    scopes: None,
            //    extra_fields: EmptyExtraTokenFields,
            //}

            println!("Token (the frontend should use this as a bearer): {}", &token.access_token().secret());
            println!("Token type: {:?}", &token.token_type());
            println!("Token extra fields: {:?}", &token.extra_fields());
            // Scopes
            println!("Token scopes: {:?}", &token.scopes());
            token.access_token().secret().to_string()
        },

        Err(err) => {
            anyhow::bail!("Failed to receive access token: {:?}", err)
        }
    };



    println!("... now we can use the bearer token to access the api ...");


    let f = reqwest::Client::new()
        .get(user_info_endpoint)
        .bearer_auth(bearer_token)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    dbg!(f);
    Ok(())
}
