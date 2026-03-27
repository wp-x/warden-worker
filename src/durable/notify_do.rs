use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use worker::{
    durable_object, DurableObject, Env, Method, Request, Response, Result, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair,
};

use crate::{
    auth, db,
    notifications::{
        self, AuthRequestPublish, AuthResponsePublish, ConnectionAttachment,
        InternalPublishRequest, PublishSelector, ANONYMOUS_KIND_TAG, INITIAL_RESPONSE,
        USER_KIND_TAG,
    },
    push,
};

#[durable_object]
pub struct NotifyDo {
    state: State,
    env: Env,
}

#[derive(Debug, Default, Deserialize)]
struct HubQuery {
    access_token: Option<String>,
    token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublishStats {
    matched: usize,
    sent: usize,
    pruned: usize,
}

impl DurableObject for NotifyDo {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        console_error_panic_hook::set_once();
        let _ = console_log::init_with_level(log::Level::Debug);

        match (req.method(), req.path().as_str()) {
            (Method::Get, "/notifications/hub") | (Method::Get, "/hub") => {
                self.handle_user_hub(req).await
            }
            (Method::Get, "/notifications/anonymous-hub") | (Method::Get, "/anonymous-hub") => {
                self.handle_anonymous_hub(req).await
            }
            (Method::Post, "/publish") => self.handle_publish(&mut req).await,
            _ => Response::error("Not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let Some(mut attachment) = self.deserialize_attachment(&ws) else {
            self.close_socket(&ws, 1008, "missing connection attachment");
            return Ok(());
        };

        match message {
            WebSocketIncomingMessage::String(text) => {
                if notifications::is_initial_message(&text) {
                    attachment.protocol_initialized = true;
                    ws.serialize_attachment(&attachment)?;
                    ws.send_with_bytes(INITIAL_RESPONSE)?;
                }
            }
            WebSocketIncomingMessage::Binary(bytes) => {
                ws.send_with_bytes(bytes)?;
            }
        }

        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        code: usize,
        reason: String,
        was_clean: bool,
    ) -> Result<()> {
        log::info!("NotifyDo websocket closed: code={code}, clean={was_clean}, reason={reason}");
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, error: worker::Error) -> Result<()> {
        log::error!("NotifyDo websocket error: {error}");
        self.close_socket(&ws, 1011, "websocket error");
        Ok(())
    }
}

impl NotifyDo {
    // ── Hub handlers ────────────────────────────────────────────────

    async fn handle_user_hub(&self, req: Request) -> Result<Response> {
        if !self.is_websocket_upgrade(&req) {
            return Response::error("Expected WebSocket", 426);
        }

        let query = req.query::<HubQuery>().unwrap_or_default();
        let token = match query
            .access_token
            .or(auth::bearer_token_from_headers(req.headers())
                .ok()
                .flatten())
        {
            Some(token) => token,
            None => return Response::error("Missing access token", 401),
        };

        let claims = match auth::decode_access_token(&self.env, &token).await {
            Ok(claims) => claims,
            Err(error) => {
                log::warn!("NotifyDo rejected websocket token: {error}");
                return Response::error("Invalid token", 401);
            }
        };

        let pair = WebSocketPair::new()?;
        let attachment =
            ConnectionAttachment::user(claims.sub.clone(), Some(claims.device), db::now_string());
        pair.server.serialize_attachment(&attachment)?;

        let user_tag = notifications::user_tag(&claims.sub);
        let tags = [user_tag.as_str(), USER_KIND_TAG];
        self.state.accept_websocket_with_tags(&pair.server, &tags);

        Response::from_websocket(pair.client)
    }

    async fn handle_anonymous_hub(&self, req: Request) -> Result<Response> {
        if !self.is_websocket_upgrade(&req) {
            return Response::error("Expected WebSocket", 426);
        }

        let query = req.query::<HubQuery>().unwrap_or_default();
        let Some(token) = query.token.filter(|value| !value.is_empty()) else {
            return Response::error("Missing token", 400);
        };

        if self
            .env
            .var("ANONYMOUS_HUB_ENABLED")
            .ok()
            .is_none_or(|value| value.to_string() != "true")
        {
            return Response::error("Anonymous hub is not enabled", 403);
        }

        let pair = WebSocketPair::new()?;
        let attachment = ConnectionAttachment::anonymous(token.clone(), db::now_string());
        pair.server.serialize_attachment(&attachment)?;

        let anonymous_tag = notifications::anonymous_tag(&token);
        let tags = [anonymous_tag.as_str(), ANONYMOUS_KIND_TAG];
        self.state.accept_websocket_with_tags(&pair.server, &tags);

        Response::from_websocket(pair.client)
    }

    // ── Unified publish handler ─────────────────────────────────────

    async fn handle_publish(&self, req: &mut Request) -> Result<Response> {
        let command = match req.json::<InternalPublishRequest>().await {
            Ok(command) => command,
            Err(error) => {
                log::warn!("NotifyDo received invalid publish payload: {error}");
                return Response::error("Invalid publish payload", 400);
            }
        };

        let (selector, ws_message) = self.build_ws_from_command(&command);
        let stats = self.ws_fanout(&selector, &ws_message);

        match push::push_config(&self.env) {
            Ok(Some(cfg)) => {
                if let Err(error) = self.try_push_relay(&cfg, &command).await {
                    log::warn!("Push relay notification failed: {error}");
                }
            }
            Ok(None) => {}
            Err(error) => {
                log::error!("Push config error (misconfigured?): {error}");
            }
        }

        Response::from_json(&stats)
    }

    // ── WS message building ─────────────────────────────────────────

    fn build_ws_from_command(
        &self,
        command: &InternalPublishRequest,
    ) -> (PublishSelector, Vec<u8>) {
        match command {
            InternalPublishRequest::UserUpdate(cmd) => (
                PublishSelector::user(&cmd.user_id),
                notifications::build_user_update_message(
                    cmd.update_type,
                    &cmd.user_id,
                    &cmd.date,
                    cmd.context_id.as_deref(),
                ),
            ),
            InternalPublishRequest::FolderUpdate(cmd) => (
                PublishSelector::user(&cmd.user_id),
                notifications::build_folder_update_message(
                    cmd.update_type,
                    &cmd.folder_id,
                    &cmd.user_id,
                    &cmd.revision_date,
                    cmd.context_id.as_deref(),
                ),
            ),
            InternalPublishRequest::CipherUpdate(cmd) => (
                PublishSelector::user(&cmd.user_id),
                notifications::build_cipher_update_message(
                    cmd.update_type,
                    &cmd.cipher_id,
                    cmd.payload_user_id.as_deref(),
                    cmd.organization_id.as_deref(),
                    cmd.collection_ids.clone(),
                    cmd.revision_date.as_deref(),
                    cmd.context_id.as_deref(),
                ),
            ),
            InternalPublishRequest::SendUpdate(cmd) => (
                PublishSelector::user(&cmd.user_id),
                notifications::build_send_update_message(
                    cmd.update_type,
                    &cmd.send_id,
                    cmd.payload_user_id.as_deref(),
                    &cmd.revision_date,
                ),
            ),
            InternalPublishRequest::AuthRequest(cmd) => (
                PublishSelector::user(&cmd.user_id),
                notifications::build_auth_request_message(
                    &cmd.user_id,
                    &cmd.auth_request_id,
                    cmd.context_id.as_deref(),
                ),
            ),
            InternalPublishRequest::AuthResponse(cmd) => (
                PublishSelector::user(&cmd.user_id),
                notifications::build_auth_response_message(
                    &cmd.user_id,
                    &cmd.auth_request_id,
                    cmd.context_id.as_deref(),
                ),
            ),
            InternalPublishRequest::AnonymousAuthResponse(cmd) => (
                PublishSelector::anonymous(&cmd.token),
                notifications::build_anonymous_auth_response_message(
                    &cmd.user_id,
                    &cmd.auth_request_id,
                ),
            ),
        }
    }

    // ── WS fan-out ──────────────────────────────────────────────────

    fn ws_fanout(&self, selector: &PublishSelector, message: &[u8]) -> PublishStats {
        let mut stats = PublishStats {
            matched: 0,
            sent: 0,
            pruned: 0,
        };

        for ws in self.state.get_websockets_with_tag(&selector.tag()) {
            stats.matched += 1;

            let Some(attachment) = self.deserialize_attachment(&ws) else {
                stats.pruned += 1;
                self.close_socket(&ws, 1008, "invalid connection attachment");
                continue;
            };

            if !attachment.protocol_initialized {
                log::warn!("NotifyDo websocket protocol not initialized; skipping");
                continue;
            }

            if !attachment.matches_selector(selector) {
                log::warn!("NotifyDo selector mismatch despite tag match; skipping");
                continue;
            }

            if let Err(error) = ws.send_with_bytes(message) {
                stats.pruned += 1;
                log::warn!("NotifyDo failed to fan out websocket message: {error}");
                self.close_socket(&ws, 1011, "send failed");
                continue;
            }

            stats.sent += 1;
        }

        stats
    }

    // ── Push relay integration ──────────────────────────────────────

    async fn try_push_relay(
        &self,
        cfg: &push::PushConfig,
        command: &InternalPublishRequest,
    ) -> std::result::Result<(), crate::error::AppError> {
        // Vaultwarden skips org-scoped or multi-user cipher fan-out
        // In this project, org feature is not supported, so we skip the check

        let (user_id, context_id) = match command {
            InternalPublishRequest::UserUpdate(cmd) => (&cmd.user_id, cmd.context_id.as_deref()),
            InternalPublishRequest::FolderUpdate(cmd) => (&cmd.user_id, cmd.context_id.as_deref()),
            InternalPublishRequest::CipherUpdate(cmd) => (&cmd.user_id, cmd.context_id.as_deref()),
            InternalPublishRequest::SendUpdate(cmd) => (&cmd.user_id, None),
            InternalPublishRequest::AuthRequest(cmd) => (&cmd.user_id, cmd.context_id.as_deref()),
            InternalPublishRequest::AuthResponse(cmd) => (&cmd.user_id, cmd.context_id.as_deref()),
            InternalPublishRequest::AnonymousAuthResponse(_) => return Ok(()),
        };

        if !self.user_has_push_device(user_id).await? {
            return Ok(());
        }

        let device_info = if let Some(ctx_id) = context_id {
            self.lookup_device_push_info(user_id, ctx_id).await?
        } else {
            None
        };
        let device_ref = device_info.as_ref().map(|d| push::DevicePushInfo {
            push_uuid: d.push_uuid.clone(),
            identifier: d.identifier.clone(),
        });

        let payload = self.build_push_payload(command, device_ref.as_ref());
        push::send_to_push_relay(cfg, &payload).await
    }

    fn build_push_payload(
        &self,
        command: &InternalPublishRequest,
        device: Option<&push::DevicePushInfo>,
    ) -> JsonValue {
        match command {
            InternalPublishRequest::CipherUpdate(cmd) => push::build_cipher_push_payload(
                &cmd.user_id,
                &cmd.cipher_id,
                cmd.payload_user_id.as_deref(),
                cmd.revision_date.as_deref(),
                cmd.update_type,
                device,
            ),
            InternalPublishRequest::UserUpdate(cmd) => {
                push::build_user_push_payload(&cmd.user_id, &cmd.date, cmd.update_type, device)
            }
            InternalPublishRequest::FolderUpdate(cmd) => push::build_folder_push_payload(
                &cmd.user_id,
                &cmd.folder_id,
                &cmd.revision_date,
                cmd.update_type,
                device,
            ),
            InternalPublishRequest::SendUpdate(cmd) => push::build_send_push_payload(
                &cmd.user_id,
                &cmd.send_id,
                cmd.payload_user_id.as_deref(),
                &cmd.revision_date,
                cmd.update_type,
                device,
            ),
            InternalPublishRequest::AuthRequest(cmd) => push::build_auth_request_push_payload(
                &cmd.user_id,
                &cmd.auth_request_id,
                cmd.update_type(),
                device,
            ),
            InternalPublishRequest::AuthResponse(cmd) => push::build_auth_request_push_payload(
                &cmd.user_id,
                &cmd.auth_request_id,
                cmd.update_type(),
                device,
            ),
            InternalPublishRequest::AnonymousAuthResponse(_) => {
                unreachable!("anonymous events don't go through push relay")
            }
        }
    }

    async fn user_has_push_device(
        &self,
        user_id: &str,
    ) -> std::result::Result<bool, crate::error::AppError> {
        let db = self
            .env
            .d1("vault1")
            .map_err(crate::error::AppError::Worker)?;
        let count: Option<f64> = db
            .prepare(
                "SELECT COUNT(*) as cnt FROM devices WHERE user_id = ?1 AND push_token IS NOT NULL",
            )
            .bind(&[user_id.into()])
            .map_err(crate::error::AppError::Worker)?
            .first(Some("cnt"))
            .await
            .map_err(|_| crate::error::AppError::Database)?;
        Ok(count.unwrap_or(0.0) > 0.0)
    }

    async fn lookup_device_push_info(
        &self,
        user_id: &str,
        device_identifier: &str,
    ) -> std::result::Result<Option<push::DevicePushInfo>, crate::error::AppError> {
        let db = self
            .env
            .d1("vault1")
            .map_err(crate::error::AppError::Worker)?;
        let row: Option<JsonValue> = db
            .prepare(
                "SELECT push_uuid, identifier FROM devices WHERE identifier = ?1 AND user_id = ?2",
            )
            .bind(&[device_identifier.into(), user_id.into()])
            .map_err(crate::error::AppError::Worker)?
            .first(None)
            .await
            .map_err(|_| crate::error::AppError::Database)?;

        Ok(row.and_then(|r| serde_json::from_value(r).ok()))
    }

    // ── Utility ─────────────────────────────────────────────────────

    fn deserialize_attachment(&self, ws: &WebSocket) -> Option<ConnectionAttachment> {
        match ws.deserialize_attachment::<ConnectionAttachment>() {
            Ok(attachment) => attachment,
            Err(error) => {
                log::warn!("NotifyDo failed to deserialize websocket attachment: {error}");
                None
            }
        }
    }

    fn close_socket(&self, ws: &WebSocket, code: u16, reason: &str) {
        if let Err(error) = ws.close(Some(code), Some(reason)) {
            log::warn!("NotifyDo failed to close websocket: {error}");
        }
    }

    fn is_websocket_upgrade(&self, req: &Request) -> bool {
        req.headers()
            .get("Upgrade")
            .ok()
            .flatten()
            .map(|value| value.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
    }
}

// Helper trait to get update_type from auth request/response commands
trait HasUpdateType {
    fn update_type(&self) -> i32;
}

impl HasUpdateType for AuthRequestPublish {
    fn update_type(&self) -> i32 {
        notifications::UpdateType::AuthRequest as i32
    }
}

impl HasUpdateType for AuthResponsePublish {
    fn update_type(&self) -> i32 {
        notifications::UpdateType::AuthRequestResponse as i32
    }
}
