//! Webhook handlers for onramp providers.

use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

use crate::types::banxa;

/// Creates a JSON-RPC error for webhook validation failures.
fn webhook_error(msg: &str) -> jsonrpsee::types::error::ErrorObject<'static> {
    jsonrpsee::types::error::ErrorObject::owned(
        jsonrpsee::types::error::INVALID_PARAMS_CODE,
        msg,
        None::<()>,
    )
}

/// HMAC signature verification.
pub fn verify_signature(body: &str, secret: &str, signature: &str) -> bool {
    if body.is_empty() || secret.is_empty() || signature.is_empty() {
        return false;
    }

    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return false,
    };

    mac.update(body.as_bytes());
    let result = mac.finalize();
    let hash = hex::encode(result.into_bytes());

    hash == signature
}

/// Parameters for webhook requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookRequest {
    /// The webhook body (JSON string).
    pub body: String,
    /// The authorization header.
    pub authorization: String,
    /// The HTTP method.
    pub method: String,
    /// The request path.
    pub path: String,
}

/// Ithaca webhook RPC namespace.
#[rpc(server, client, namespace = "webhook")]
pub trait WebhookApi {
    /// Handle a Banxa webhook.
    #[method(name = "banxa")]
    async fn handle_banxa_webhook(&self, request: WebhookRequest) -> RpcResult<String>;
}

/// Webhook RPC module.
#[derive(Debug, Default)]
pub struct Webhook {
    /// Banxa webhook secret.
    banxa_webhook_secret: Option<String>,
    /// Banxa webhook API key.
    banxa_webhook_key: Option<String>,
}

impl Webhook {
    /// Create a new webhook RPC module.
    pub fn new() -> Self {
        Self {
            banxa_webhook_secret: std::env::var("BANXA_WEBHOOK_API_SECRET").ok(),
            banxa_webhook_key: std::env::var("BANXA_WEBHOOK_API_KEY").ok(),
        }
    }
}

#[async_trait]
impl WebhookApiServer for Webhook {
    async fn handle_banxa_webhook(&self, request: WebhookRequest) -> RpcResult<String> {
        if request.method != "POST" {
            return Err(webhook_error("Only POST requests are supported"));
        }

        // Parse the payload
        let payload: banxa::WebhookPayload = serde_json::from_str(&request.body)
            .map_err(|_| webhook_error("Malformed request body"))?;

        // Parse Bearer token format: "Bearer api_key:signature:nonce"
        if !request.authorization.starts_with("Bearer ") {
            return Err(webhook_error("Invalid authorization header format"));
        }

        let auth_data = &request.authorization[7..]; // Remove "Bearer " prefix
        let parts: Vec<&str> = auth_data.split(':').collect();
        if parts.len() != 3 {
            return Err(webhook_error("Auth header missing webhook API key, signature, or nonce"));
        }

        let (api_key, signature, nonce) = (parts[0], parts[1], parts[2]);

        // Get webhook secret and key from environment
        let webhook_secret = self
            .banxa_webhook_secret
            .as_ref()
            .ok_or_else(|| webhook_error("Missing banxa webhook API secret"))?;
        let webhook_key = self
            .banxa_webhook_key
            .as_ref()
            .ok_or_else(|| webhook_error("Missing banxa webhook API key"))?;

        // Verify API key
        if api_key != webhook_key {
            return Err(webhook_error("Invalid API key"));
        }

        // Create signature body as in the original TypeScript implementation
        let signature_body =
            format!("{}\n{}\n{}\n{}", request.method, request.path, nonce, request.body);

        // Verify signature
        if !verify_signature(&signature_body, webhook_secret, signature) {
            return Err(webhook_error("Invalid signature"));
        }

        // Process the webhook payload
        tracing::info!(
            "Received Banxa webhook for order {}: {:?}",
            payload.order_id,
            payload.status
        );

        // TODO: Process the webhook payload (update order status, etc.)

        Ok("success".to_string())
    }
}
