//! Thin libcurl wrapper for web tools (web_search, web_fetch).
//!
//! Uses system TLS (OpenSSL/SecureTransport/SChannel) instead of rustls,
//! which is more reliable in Docker and constrained environments where
//! rustls-platform-verifier may fail to load root certificates.

use std::time::Duration;

/// Response from a curl HTTP request.
pub struct CurlResponse {
    pub status: u32,
    pub body: String,
    pub headers: Vec<String>,
}

/// Perform an HTTP GET using libcurl (runs on a blocking thread).
pub async fn curl_get(
    url: &str,
    headers: &[(&str, &str)],
    timeout: Duration,
    user_agent: Option<&str>,
    follow_redirects: bool,
) -> anyhow::Result<CurlResponse> {
    let url = url.to_string();
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let ua = user_agent.map(String::from);

    tokio::task::spawn_blocking(move || {
        do_curl_get(&url, &headers, timeout, ua.as_deref(), follow_redirects)
    })
    .await?
}

/// Perform an HTTP POST with a JSON body using libcurl (runs on a blocking thread).
pub async fn curl_post_json(
    url: &str,
    json_body: &str,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> anyhow::Result<CurlResponse> {
    let url = url.to_string();
    let body = json_body.to_string();
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    tokio::task::spawn_blocking(move || do_curl_post_json(&url, &body, &headers, timeout)).await?
}

fn do_curl_get(
    url: &str,
    headers: &[(String, String)],
    timeout: Duration,
    user_agent: Option<&str>,
    follow_redirects: bool,
) -> anyhow::Result<CurlResponse> {
    let mut easy = curl::easy::Easy::new();
    easy.url(url)?;
    easy.timeout(timeout)?;
    easy.connect_timeout(Duration::from_secs(10))?;

    if let Some(ua) = user_agent {
        easy.useragent(ua)?;
    } else {
        easy.useragent("ZeroClaw/1.0")?;
    }

    if follow_redirects {
        easy.follow_location(true)?;
        easy.max_redirections(5)?;
    }

    let mut header_list = curl::easy::List::new();
    for (key, value) in headers {
        header_list.append(&format!("{key}: {value}"))?;
    }
    easy.http_headers(header_list)?;

    let mut response_body = Vec::new();
    let mut response_headers = Vec::new();

    {
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            response_body.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.header_function(|header| {
            if let Ok(s) = std::str::from_utf8(header) {
                response_headers.push(s.trim().to_string());
            }
            true
        })?;
        transfer
            .perform()
            .map_err(|e| anyhow::anyhow!("curl GET {url} failed: {e}"))?;
    }

    let status = easy.response_code()? as u32;
    let body = String::from_utf8_lossy(&response_body).into_owned();

    Ok(CurlResponse {
        status,
        body,
        headers: response_headers,
    })
}

fn do_curl_post_json(
    url: &str,
    json_body: &str,
    headers: &[(String, String)],
    timeout: Duration,
) -> anyhow::Result<CurlResponse> {
    let mut easy = curl::easy::Easy::new();
    easy.url(url)?;
    easy.timeout(timeout)?;
    easy.connect_timeout(Duration::from_secs(10))?;
    easy.useragent("ZeroClaw/1.0")?;
    easy.post(true)?;
    easy.post_fields_copy(json_body.as_bytes())?;

    let mut header_list = curl::easy::List::new();
    header_list.append("Content-Type: application/json")?;
    for (key, value) in headers {
        header_list.append(&format!("{key}: {value}"))?;
    }
    easy.http_headers(header_list)?;

    let mut response_body = Vec::new();
    let mut response_headers = Vec::new();

    {
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            response_body.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.header_function(|header| {
            if let Ok(s) = std::str::from_utf8(header) {
                response_headers.push(s.trim().to_string());
            }
            true
        })?;
        transfer
            .perform()
            .map_err(|e| anyhow::anyhow!("curl POST {url} failed: {e}"))?;
    }

    let status = easy.response_code()? as u32;
    let body = String::from_utf8_lossy(&response_body).into_owned();

    Ok(CurlResponse {
        status,
        body,
        headers: response_headers,
    })
}

/// Perform an HTTP POST with URL-encoded form data using libcurl (runs on a blocking thread).
pub async fn curl_post_form(
    url: &str,
    form_data: &str,
    headers: &[(&str, &str)],
    timeout: Duration,
    user_agent: Option<&str>,
    follow_redirects: bool,
) -> anyhow::Result<CurlResponse> {
    let url = url.to_string();
    let form = form_data.to_string();
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let ua = user_agent.map(String::from);

    tokio::task::spawn_blocking(move || {
        do_curl_post_form(&url, &form, &headers, timeout, ua.as_deref(), follow_redirects)
    })
    .await?
}

fn do_curl_post_form(
    url: &str,
    form_data: &str,
    headers: &[(String, String)],
    timeout: Duration,
    user_agent: Option<&str>,
    follow_redirects: bool,
) -> anyhow::Result<CurlResponse> {
    let mut easy = curl::easy::Easy::new();
    easy.url(url)?;
    easy.timeout(timeout)?;
    easy.connect_timeout(Duration::from_secs(10))?;

    if let Some(ua) = user_agent {
        easy.useragent(ua)?;
    } else {
        easy.useragent("ZeroClaw/1.0")?;
    }

    if follow_redirects {
        easy.follow_location(true)?;
        easy.max_redirections(5)?;
    }

    easy.post(true)?;
    easy.post_fields_copy(form_data.as_bytes())?;

    let mut header_list = curl::easy::List::new();
    header_list.append("Content-Type: application/x-www-form-urlencoded")?;
    for (key, value) in headers {
        header_list.append(&format!("{key}: {value}"))?;
    }
    easy.http_headers(header_list)?;

    let mut response_body = Vec::new();
    let mut response_headers = Vec::new();

    {
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            response_body.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.header_function(|header| {
            if let Ok(s) = std::str::from_utf8(header) {
                response_headers.push(s.trim().to_string());
            }
            true
        })?;
        transfer
            .perform()
            .map_err(|e| anyhow::anyhow!("curl POST {url} failed: {e}"))?;
    }

    let status = easy.response_code()? as u32;
    let body = String::from_utf8_lossy(&response_body).into_owned();

    Ok(CurlResponse {
        status,
        body,
        headers: response_headers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_response_struct() {
        let resp = CurlResponse {
            status: 200,
            body: "hello".to_string(),
            headers: vec!["Content-Type: text/plain".to_string()],
        };
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, "hello");
    }
}
