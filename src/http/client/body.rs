//! Bounded response-body reads with the `MAX_RESPONSE_BODY_BYTES` cap and
//! per-class timeouts.

use crate::http::timeouts::RequestClass;

use super::{ClientError, HttpClient};

/// Hard cap on a single response body read (`read_body_with_timeout` /
/// `read_body_string_with_timeout`): a malicious or misconfigured target
/// streaming an unbounded/huge body must not be allowed to exhaust memory —
/// the stream is read incrementally and aborted the moment this is exceeded,
/// so at most one chunk beyond the cap is ever buffered.
pub const MAX_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024;

impl HttpClient {
    /// Read response body with timeout to prevent hanging on slow/incomplete responses.
    ///
    /// `ClientError::Timeout` (or any other error) must never be scored as an
    /// empty body — callers must skip scoring (`continue`/negative trial) so a
    /// transport failure cannot become a finding. `Timeout` is retryable in
    /// `send_with_retry`; body-read timeouts are surfaced here for the same
    /// treatment (retry/skip, never a finding).
    ///
    /// Default-class overload of [`Self::read_body_with_timeout_for_class`].
    ///
    /// # Errors
    /// Returns an error if reading the body times out or the underlying stream fails.
    ///
    /// # Errors
    /// Also returns [`ClientError::BodyTooLarge`] once the accumulated body
    /// exceeds [`MAX_RESPONSE_BODY_BYTES`] — the stream is dropped
    /// immediately rather than being drained to completion.
    pub async fn read_body_with_timeout(
        &self,
        resp: reqwest::Response,
    ) -> Result<Vec<u8>, ClientError> {
        self.read_body_with_timeout_for_class(resp, RequestClass::Default)
            .await
    }

    /// Class-aware body read (C10): the same per-class timeout that bounded
    /// the send bounds the body stream, so a `time` probe cannot linger on a
    /// dripping body past its 15s class budget.
    ///
    /// # Errors
    /// Returns an error if reading the body times out or the stream fails.
    pub async fn read_body_with_timeout_for_class(
        &self,
        resp: reqwest::Response,
        class: RequestClass,
    ) -> Result<Vec<u8>, ClientError> {
        use futures::StreamExt as _;
        let timeout = self.timeouts.for_class(class);
        let fut = async {
            let mut buf = Vec::new();
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                buf.extend_from_slice(&chunk);
                if buf.len() > MAX_RESPONSE_BODY_BYTES {
                    return Err(ClientError::BodyTooLarge(MAX_RESPONSE_BODY_BYTES));
                }
            }
            Ok(buf)
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ClientError::Timeout(timeout))?
    }

    /// Bounded `String` body read: `read_body_with_timeout` + lossy UTF-8.
    ///
    /// Use this instead of `resp.text().await` everywhere — `text()` has no
    /// bound and `unwrap_or_default()` turns transport errors into `""`,
    /// which scores as similarity ~0 / confidence 0.75 (false positive).
    ///
    /// Default-class overload of [`Self::read_body_string_for_class`].
    ///
    /// # Errors
    /// Returns an error if reading the body times out or the stream fails.
    pub async fn read_body_string_with_timeout(
        &self,
        resp: reqwest::Response,
    ) -> Result<String, ClientError> {
        self.read_body_string_for_class(resp, RequestClass::Default)
            .await
    }

    /// Class-aware bounded `String` body read (C10).
    ///
    /// # Errors
    /// Returns an error if reading the body times out or the stream fails.
    pub async fn read_body_string_for_class(
        &self,
        resp: reqwest::Response,
        class: RequestClass,
    ) -> Result<String, ClientError> {
        let bytes = self.read_body_with_timeout_for_class(resp, class).await?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}
