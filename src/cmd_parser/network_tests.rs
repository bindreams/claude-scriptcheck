use super::network::*;
use super::CommandParser;
use pretty_assertions::assert_eq;

fn reads(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

fn writes(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| s.to_string()).collect()
}

#[skuld::test]
fn curl_o_writes() {
    let r = CurlParser
        .parse(&["-o", "out.html", "https://example.com"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, writes(&["/tmp/out.html"]));
}

#[skuld::test]
fn curl_no_file_access() {
    let r = CurlParser.parse(&["https://example.com"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
    assert!(r.writes.is_empty());
}

#[skuld::test]
fn curl_cookie_jar_writes() {
    let r = CurlParser
        .parse(&["-c", "cookies.txt", "https://example.com"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, writes(&["/tmp/cookies.txt"]));
}

#[skuld::test]
fn curl_dump_header_writes() {
    let r = CurlParser
        .parse(&["-D", "headers.txt", "https://example.com"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, writes(&["/tmp/headers.txt"]));
}

#[skuld::test]
#[allow(non_snake_case)]
fn wget_O_writes() {
    let r = WgetParser
        .parse(&["-O", "out.html", "https://example.com"], "/tmp")
        .unwrap();
    assert_eq!(r.writes, writes(&["/tmp/out.html"]));
}

#[skuld::test]
fn wget_input_file_reads() {
    let r = WgetParser.parse(&["-i", "urls.txt"], "/tmp").unwrap();
    assert_eq!(r.reads, reads(&["/tmp/urls.txt"]));
}

#[skuld::test]
fn wget_no_file_access() {
    let r = WgetParser.parse(&["https://example.com"], "/tmp").unwrap();
    assert!(r.reads.is_empty());
    assert!(r.writes.is_empty());
}

// ── zip / unzip ──
