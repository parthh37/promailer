//! RFC 3464 delivery status notifications (NDR / delay warnings).

use super::{enqueue, NewMessage, QueueEntry, RcptStatus, RecipientState, Source};
use crate::app::App;
use crate::message;
use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;

/// Cap on how much of the original header block is returned in the report.
const MAX_RETURNED_HEADERS: usize = 64 * 1024;

#[derive(Clone, Copy)]
enum Kind {
    Failure,
    Delay,
}

fn status_code(r: &RecipientState, kind: Kind) -> String {
    let resp = r.last_response.as_deref().unwrap_or("");
    // Look for an enhanced status code anywhere in the response ("550 5.1.1 ...").
    let found = resp.split_whitespace().find(|t| {
        let p: Vec<&str> = t.split('.').collect();
        p.len() == 3 && p.iter().all(|x| !x.is_empty() && x.chars().all(|c| c.is_ascii_digit()))
    });
    match (found, kind) {
        (Some(c), Kind::Failure) if c.starts_with('5') => c.to_string(),
        (Some(c), Kind::Delay) if c.starts_with('4') => c.to_string(),
        (_, Kind::Failure) => "5.0.0".into(),
        (_, Kind::Delay) => "4.0.0".into(),
    }
}

fn build(app: &App, entry: &QueueEntry, original: &[u8], kind: Kind) -> Vec<u8> {
    let cfg = app.cfg();
    let host = &cfg.server.hostname;
    let boundary = format!("=_{}", ulid::Ulid::new());
    let (subject, action, intro) = match kind {
        Kind::Failure => (
            "Delivery Status Notification (Failure)",
            "failed",
            "Delivery to the following recipients failed permanently:",
        ),
        Kind::Delay => (
            "Delivery Status Notification (Delay)",
            "delayed",
            "Delivery to the following recipients has been delayed. The server will keep\r\ntrying; you do not need to resend the message yet:",
        ),
    };
    let want = match kind {
        Kind::Failure => RcptStatus::Failed,
        Kind::Delay => RcptStatus::Pending,
    };
    let rcpts: Vec<&RecipientState> = entry.recipients.iter().filter(|r| r.status == want).collect();

    let hdr_end = message::header_end(original).min(MAX_RETURNED_HEADERS);
    let orig_headers = String::from_utf8_lossy(&original[..hdr_end]);
    let orig_subject = message::header_value(&message::headers(original), "Subject").unwrap_or_default();

    let mut human =
        format!("This is an automatically generated Delivery Status Notification from {host}.\r\n\r\n{intro}\r\n\r\n");
    for r in &rcpts {
        human.push_str(&format!(
            "    {}\r\n        Reason: {}\r\n",
            r.address,
            r.last_response.as_deref().unwrap_or("unknown")
        ));
    }
    if !orig_subject.is_empty() {
        human.push_str(&format!("\r\nOriginal subject: {}\r\n", orig_subject.chars().take(200).collect::<String>()));
    }

    let now = Utc::now().to_rfc2822();
    let mut status = format!(
        "Reporting-MTA: dns; {host}\r\nX-Promailer-Queue-ID: {}\r\nArrival-Date: {}\r\n",
        entry.id,
        entry.created.to_rfc2822()
    );
    for r in &rcpts {
        status.push_str(&format!(
            "\r\nFinal-Recipient: rfc822; {}\r\nAction: {action}\r\nStatus: {}\r\n",
            r.address,
            status_code(r, kind)
        ));
        if let Some(h) = &r.remote_host {
            status.push_str(&format!("Remote-MTA: dns; {h}\r\n"));
        }
        if let Some(resp) = &r.last_response {
            let clean: String = resp.chars().filter(|c| !c.is_control()).take(900).collect();
            status.push_str(&format!("Diagnostic-Code: smtp; {clean}\r\n"));
        }
        status.push_str(&format!("Last-Attempt-Date: {now}\r\n"));
    }

    format!(
        "From: Mail Delivery System <{postmaster}>\r\n\
         To: <{to}>\r\n\
         Subject: {subject}\r\n\
         Date: {now}\r\n\
         Message-ID: {mid}\r\n\
         MIME-Version: 1.0\r\n\
         Auto-Submitted: auto-replied\r\n\
         Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=\"{boundary}\"\r\n\
         \r\n\
         This is a MIME-formatted message.\r\n\
         \r\n\
         --{boundary}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         {human}\r\n\
         --{boundary}\r\n\
         Content-Type: message/delivery-status\r\n\
         \r\n\
         {status}\r\n\
         --{boundary}\r\n\
         Content-Type: text/rfc822-headers\r\n\
         \r\n\
         {orig_headers}\r\n\
         --{boundary}--\r\n",
        postmaster = cfg.postmaster(),
        to = entry.sender,
        mid = message::new_message_id(host),
    )
    .into_bytes()
}

async fn send(app: &Arc<App>, entry: &QueueEntry, original: &[u8], kind: Kind) -> Result<String> {
    let cfg = app.cfg();
    let data = build(app, entry, original, kind);
    let mut recipients = vec![entry.sender.clone()];
    if let (Kind::Failure, Some(copy)) = (kind, &cfg.delivery.ndr_copy_to) {
        if !copy.is_empty() {
            recipients.push(copy.clone());
        }
    }
    enqueue(
        app,
        NewMessage {
            sender: String::new(),
            recipients,
            data,
            source: Source::Ndr { original: entry.id.clone() },
            pool: entry.pool.clone(),
        },
    )
    .await
}

pub async fn send_failure(app: &Arc<App>, entry: &QueueEntry, original: &[u8]) -> Result<String> {
    send(app, entry, original, Kind::Failure).await
}

pub async fn send_delay(app: &Arc<App>, entry: &QueueEntry, original: &[u8]) -> Result<String> {
    send(app, entry, original, Kind::Delay).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_enhanced_status() {
        let mut r = RecipientState {
            address: "a@b.c".into(),
            status: RcptStatus::Failed,
            attempts: 1,
            last_response: Some("550 5.1.1 <a@b.c>: Recipient address rejected".into()),
            remote_host: None,
            updated: None,
        };
        assert_eq!(status_code(&r, Kind::Failure), "5.1.1");
        r.last_response = Some("connection refused".into());
        assert_eq!(status_code(&r, Kind::Failure), "5.0.0");
        assert_eq!(status_code(&r, Kind::Delay), "4.0.0");
    }
}
