//! Cloudflare Workers I/O and its independently testable configuration rules.

use crate::{AddressPolicy, ClientConfig, Error};

/// Accept only options the public-only Cloudflare backend can actually honor.
pub(crate) fn validate_config(config: &ClientConfig) -> Result<(), Error> {
    if config.policy != AddressPolicy::DenyLocal {
        return Err(Error::UnsupportedConfiguration(
            "Cloudflare public-only egress supports only AddressPolicy::DenyLocal",
        ));
    }
    if matches!(config.max_redirects, Some(max) if max > 0) {
        return Err(Error::UnsupportedConfiguration(
            "Cloudflare Workers egress does not follow redirects; max_redirects must be None or Some(0)",
        ));
    }
    // JavaScript timers use signed 32-bit milliseconds. The connect deadline
    // is capped by the total deadline, so validating the latter covers both.
    if config.timeout.as_millis() > i32::MAX as u128 {
        return Err(Error::UnsupportedConfiguration(
            "Cloudflare Workers egress timeout exceeds the supported timer range",
        ));
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
mod platform {
    use std::{ops::Deref, time::Duration};

    use futures_util::{
        future::{select, Either},
        StreamExt,
    };
    use gloo_timers::future::TimeoutFuture;
    use js_sys::Uint8Array;
    use url::Url;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{AbortController, Headers, RequestInit, RequestRedirect, WorkerGlobalScope};

    use super::{check_body_size, validate_config};
    use crate::{ClientConfig, Error, Response};

    fn js_error(err: JsValue) -> Error {
        Error::Request(err.as_string().unwrap_or_else(|| format!("{err:?}")))
    }

    // Dropping a Rust future does not cancel its JS fetch promise. Abort even
    // when the caller cancels or an unexpected error returns early.
    struct AbortOnDrop(AbortController);

    impl Deref for AbortOnDrop {
        type Target = AbortController;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// The JS Fetch primitives are used directly rather than depending on a
    /// particular workers-rs SDK version, so applications can use their own.
    #[derive(Debug, Clone)]
    pub(crate) struct CloudflareClient {
        timeout: Duration,
        connect_timeout: Duration,
        user_agent: String,
    }

    impl CloudflareClient {
        pub(crate) fn new(config: &ClientConfig) -> Result<Self, Error> {
            validate_config(config)?;
            Headers::new()
                .map_err(js_error)?
                .set("User-Agent", &config.user_agent)
                .map_err(js_error)?;
            Ok(Self {
                timeout: config.timeout,
                connect_timeout: config.connect_timeout,
                user_agent: config.user_agent.clone(),
            })
        }

        pub(crate) async fn get(
            &self,
            url: Url,
            require_success: bool,
            max_response_bytes: u64,
        ) -> Result<Response, Error> {
            let headers = Headers::new().map_err(js_error)?;
            headers
                .set("User-Agent", &self.user_agent)
                .map_err(js_error)?;
            let controller = AbortOnDrop(AbortController::new().map_err(js_error)?);
            let init = RequestInit::new();
            init.set_method("GET");
            init.set_headers(headers.as_ref());
            // Cloudflare rejects redirect="error". Manual prevents following
            // redirects; callers receive the redirect's status and body.
            init.set_redirect(RequestRedirect::Manual);
            init.set_signal(Some(&controller.signal()));

            // TimeoutFuture registers its timer at creation, so the total
            // deadline runs while waiting for headers as well as for the body.
            let mut deadline = Box::pin(TimeoutFuture::new(self.timeout.as_millis() as u32));
            let header_limit = self.connect_timeout.min(self.timeout);
            let mut headers_deadline =
                Box::pin(TimeoutFuture::new(header_limit.as_millis() as u32));
            let global: WorkerGlobalScope = js_sys::global().unchecked_into();
            let mut fetch = Box::pin(JsFuture::from(
                global.fetch_with_str_and_init(url.as_str(), &init),
            ));
            let response: web_sys::Response =
                match select(fetch.as_mut(), headers_deadline.as_mut()).await {
                    Either::Left((Ok(response), _)) => response.dyn_into().map_err(js_error)?,
                    Either::Left((Err(err), _)) => {
                        controller.abort();
                        return Err(js_error(err));
                    }
                    Either::Right(((), _)) => {
                        controller.abort();
                        return Err(Error::Timeout(header_limit));
                    }
                };
            // Headers arrived; this shorter timer must not keep running while
            // the total deadline continues to cover the response body.
            drop(headers_deadline);
            drop(fetch);

            let status = response.status();
            if require_success && !(200..300).contains(&status) {
                controller.abort();
                return Err(Error::Status {
                    status,
                    url: url.to_string(),
                });
            }

            let content_length = response.headers().get("Content-Length").map_err(|err| {
                controller.abort();
                js_error(err)
            })?;
            if let Some(len) = content_length.and_then(|value| value.parse::<u64>().ok()) {
                if len > max_response_bytes {
                    controller.abort();
                    return Err(Error::TooLarge(len));
                }
            }

            let Some(raw_stream) = response.body() else {
                return Ok(Response {
                    status,
                    body: Vec::new(),
                });
            };
            let mut stream =
                wasm_streams::ReadableStream::from_raw(raw_stream.unchecked_into()).into_stream();
            let mut body = Vec::new();
            loop {
                let mut next = Box::pin(stream.next());
                match select(next.as_mut(), deadline.as_mut()).await {
                    Either::Left((None, _)) => break,
                    Either::Left((Some(Ok(chunk)), _)) => {
                        let array: Uint8Array = match chunk.dyn_into() {
                            Ok(array) => array,
                            Err(err) => {
                                controller.abort();
                                return Err(js_error(err));
                            }
                        };
                        let len = array.length() as usize;
                        if let Err(err) = check_body_size(body.len(), len, max_response_bytes) {
                            controller.abort();
                            return Err(err);
                        }
                        let offset = body.len();
                        body.resize(offset + len, 0);
                        array.copy_to(&mut body[offset..]);
                    }
                    Either::Left((Some(Err(err)), _)) => {
                        controller.abort();
                        return Err(js_error(err));
                    }
                    Either::Right(((), _)) => {
                        controller.abort();
                        return Err(Error::Timeout(self.timeout));
                    }
                }
            }
            Ok(Response { status, body })
        }
    }

    pub(crate) use CloudflareClient as PlatformClient;
}

#[cfg(target_arch = "wasm32")]
pub(crate) use platform::PlatformClient as CloudflareClient;

/// Check an incoming chunk before allocating or appending it.
fn check_body_size(current: usize, incoming: usize, max_response_bytes: u64) -> Result<(), Error> {
    if (current as u64).saturating_add(incoming as u64) > max_response_bytes {
        return Err(Error::TooLarge(max_response_bytes));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn cloudflare_defaults_and_zero_redirects_are_supported() {
        assert!(validate_config(&ClientConfig::default()).is_ok());
        assert!(validate_config(&ClientConfig {
            max_redirects: Some(0),
            ..ClientConfig::default()
        })
        .is_ok());
    }

    #[test]
    fn cloudflare_rejects_redirect_following() {
        let err = validate_config(&ClientConfig {
            max_redirects: Some(1),
            ..ClientConfig::default()
        })
        .expect_err("redirect following must be refused");
        assert!(matches!(err, Error::UnsupportedConfiguration(_)));
    }

    #[test]
    fn cloudflare_rejects_allow_all_for_public_only_routing() {
        let err = validate_config(&ClientConfig {
            policy: AddressPolicy::AllowAll,
            ..ClientConfig::default()
        })
        .expect_err("public-only routing cannot honor AllowAll");
        assert!(matches!(err, Error::UnsupportedConfiguration(_)));
    }

    #[test]
    fn cloudflare_rejects_a_timeout_that_would_wrap() {
        let err = validate_config(&ClientConfig {
            timeout: Duration::from_millis(i32::MAX as u64 + 1),
            ..ClientConfig::default()
        })
        .expect_err("wrapping a timeout would shorten it unexpectedly");
        assert!(matches!(err, Error::UnsupportedConfiguration(_)));
    }

    #[test]
    fn cloudflare_honors_explicit_plaintext_opt_in_at_url_check() {
        let config = ClientConfig {
            allow_plaintext: true,
            ..ClientConfig::default()
        };
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn streamed_body_cap_is_checked_before_allocation() {
        assert!(check_body_size(2, 1, 3).is_ok());
        assert!(matches!(check_body_size(3, 1, 3), Err(Error::TooLarge(3))));
        assert!(matches!(
            check_body_size(0, usize::MAX, 3),
            Err(Error::TooLarge(3))
        ));
    }
}
