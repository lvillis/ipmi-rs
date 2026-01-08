use std::time::Duration;

use crate::error::Error;

pub(crate) fn record_ok(
    mode: &'static str,
    netfn: u8,
    cmd: u8,
    elapsed: Duration,
    completion_code: u8,
) {
    let _ = (mode, netfn, cmd, elapsed, completion_code);

    #[cfg(feature = "metrics")]
    {
        metrics::counter!("ipmi_requests_total", "mode" => mode, "outcome" => "ok").increment(1);
        metrics::histogram!("ipmi_request_seconds", "mode" => mode).record(elapsed.as_secs_f64());
        if completion_code != 0x00 {
            metrics::counter!("ipmi_completion_code_nonzero_total", "mode" => mode).increment(1);
        }
    }

    #[cfg(feature = "tracing")]
    {
        tracing::debug!(
            mode,
            netfn,
            cmd,
            completion_code,
            elapsed_ms = elapsed.as_secs_f64() * 1000.0,
            "ipmi request ok"
        );
    }
}

pub(crate) fn record_err(mode: &'static str, netfn: u8, cmd: u8, elapsed: Duration, err: &Error) {
    let _ = (mode, netfn, cmd, elapsed, err);

    #[cfg(feature = "metrics")]
    {
        metrics::counter!("ipmi_requests_total", "mode" => mode, "outcome" => "err").increment(1);
        metrics::counter!(
            "ipmi_request_errors_total",
            "mode" => mode,
            "kind" => error_kind(err)
        )
        .increment(1);
        metrics::histogram!("ipmi_request_seconds", "mode" => mode).record(elapsed.as_secs_f64());
    }

    #[cfg(feature = "tracing")]
    {
        tracing::warn!(
            mode,
            netfn,
            cmd,
            error = %err,
            elapsed_ms = elapsed.as_secs_f64() * 1000.0,
            "ipmi request failed"
        );
    }
}

#[cfg(feature = "metrics")]
fn error_kind(err: &Error) -> &'static str {
    match err {
        Error::Io(_) => "io",
        Error::Timeout => "timeout",
        Error::Protocol(_) | Error::ProtocolOwned(_) => "protocol",
        Error::AuthenticationFailed(_) => "authentication",
        Error::Crypto(_) => "crypto",
        Error::Unsupported(_) => "unsupported",
        Error::InvalidArgument(_) => "invalid_argument",
        Error::CompletionCode { .. } => "completion_code",
    }
}
