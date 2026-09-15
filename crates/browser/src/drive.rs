use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tauri::{AppHandle, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

const MAX_SCRIPT: u64 = 1 << 20;
const POLL: Duration = Duration::from_millis(20);
const TIMEOUT: Duration = Duration::from_secs(60);

pub fn start(handle: AppHandle, path: &Path) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let next = Arc::new(AtomicU64::new(1));
    tauri::async_runtime::spawn(async move {
        let Ok(listener) = UnixListener::from_std(listener) else { return };
        while let Ok((stream, _)) = listener.accept().await {
            let id = next.fetch_add(1, Ordering::Relaxed);
            let handle = handle.clone();
            tauri::async_runtime::spawn(async move {
                let _ = serve(&handle, id, stream).await;
            });
        }
    });
    Ok(())
}

async fn serve(handle: &AppHandle, id: u64, mut stream: UnixStream) -> std::io::Result<()> {
    let mut script = String::new();
    (&mut stream).take(MAX_SCRIPT).read_to_string(&mut script).await?;
    let reply = match evaluate(handle, id, &script).await {
        Ok(json) => json,
        Err(e) => format!("{{\"err\":\"{e}\"}}"),
    };
    stream.write_all(reply.as_bytes()).await?;
    stream.shutdown().await
}

async fn evaluate(handle: &AppHandle, id: u64, script: &str) -> Result<String, String> {
    let chrome = handle.get_webview("chrome").ok_or("chrome web view missing")?;
    let slot = format!("window.__drive{id}");
    let start = format!(
        "(async () => {{ try {{ {slot} = {{ ok: await ({script}\n) }}; }} catch (e) {{ {slot} = {{ err: String(e) }}; }} }})();"
    );
    chrome.eval(start).map_err(|e| e.to_string())?;
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let (tx, rx) = oneshot::channel();
        let tx = std::sync::Mutex::new(Some(tx));
        chrome
            .eval_with_callback(format!("{slot} ?? null"), move |value| {
                if let Some(tx) = tx.lock().ok().and_then(|mut t| t.take()) {
                    let _ = tx.send(value);
                }
            })
            .map_err(|e| e.to_string())?;
        let value = rx.await.map_err(|e| e.to_string())?;
        if value != "null" {
            let _ = chrome.eval(format!("delete {slot};"));
            return Ok(value);
        }
        if tokio::time::Instant::now() > deadline {
            return Err("timed out".to_owned());
        }
        tokio::time::sleep(POLL).await;
    }
}
