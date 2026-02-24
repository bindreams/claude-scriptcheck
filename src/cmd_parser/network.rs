use clap::ArgAction;

use super::helpers::*;
use super::{resolve, CommandFileAccesses, CommandParser};

// ─── curl / wget ─────────────────────────────────────────────────────────────

pub(super) struct CurlParser;
impl CommandParser for CurlParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("curl")
            // File-producing flags
            .arg(val('o', "output").action(ArgAction::Append))
            .arg(flag('O', "remote-name"))
            .arg(val('c', "cookie-jar"))
            .arg(val('D', "dump-header"))
            .arg(val_l("output-dir"))
            // File-reading flags
            .arg(val('K', "config"))
            .arg(val('b', "cookie"))
            .arg(val('d', "data").action(ArgAction::Append))
            .arg(val_l("data-binary").action(ArgAction::Append))
            .arg(val_l("data-raw").action(ArgAction::Append))
            .arg(val_l("data-urlencode").action(ArgAction::Append))
            .arg(val('T', "upload-file").action(ArgAction::Append))
            .arg(val('F', "form").action(ArgAction::Append))
            .arg(val('E', "cert"))
            .arg(val_l("key"))
            .arg(val_l("cacert"))
            .arg(val_l("capath"))
            // Common value-taking flags (not file-related)
            .arg(val('H', "header").action(ArgAction::Append))
            .arg(val('X', "request"))
            .arg(val('u', "user"))
            .arg(val('A', "user-agent"))
            .arg(val('e', "referer"))
            .arg(val('m', "max-time"))
            .arg(val_l("connect-timeout"))
            .arg(val_l("retry"))
            .arg(val_l("retry-delay"))
            .arg(val_l("retry-max-time"))
            .arg(val('w', "write-out"))
            .arg(val('x', "proxy"))
            .arg(val('U', "proxy-user"))
            .arg(val_l("resolve").action(ArgAction::Append))
            .arg(val_l("interface"))
            .arg(val_l("dns-servers"))
            .arg(val_l("max-redirs"))
            .arg(val_l("limit-rate"))
            .arg(val_l("max-filesize"))
            .arg(val_l("proto"))
            .arg(val_l("range"))
            .arg(val('Y', "speed-limit"))
            .arg(val('y', "speed-time"))
            .arg(val_l("ciphers"))
            .arg(val_l("tls-max"))
            .arg(val_l("tlsv1"))
            // Bool flags
            .arg(flag('f', "fail"))
            .arg(flag('I', "head"))
            .arg(flag('i', "include"))
            .arg(flag('k', "insecure"))
            .arg(flag('L', "location"))
            .arg(flag('s', "silent"))
            .arg(flag('S', "show-error"))
            .arg(flag('v', "verbose"))
            .arg(flag('g', "globoff"))
            .arg(flag('G', "get"))
            .arg(flag('N', "no-buffer"))
            .arg(flag('n', "netrc"))
            .arg(flag('q', "disable"))
            .arg(flag('Z', "parallel"))
            .arg(flag('#', "progress-bar"))
            .arg(flag('C', "continue-at"))
            .arg(flag_l("compressed"))
            .arg(flag_l("create-dirs"))
            .arg(flag_l("fail-early"))
            .arg(flag_l("fail-with-body"))
            .arg(flag_l("http1.1"))
            .arg(flag_l("http2"))
            .arg(flag_l("no-keepalive"))
            .arg(flag_l("raw"))
            .arg(flag_l("tcp-nodelay"))
            .arg(flag_l("tr-encoding"))
            .arg(flag_l("no-progress-meter"))
            .arg(flag_l("no-sessionid"))
            .arg(flag_l("ssl"))
            .arg(flag_l("ssl-reqd"))
            .arg(flag_l("tlsv1.0"))
            .arg(flag_l("tlsv1.1"))
            .arg(flag_l("tlsv1.2"))
            .arg(flag_l("tlsv1.3"))
            .arg(flag_l("sslv2"))
            .arg(flag_l("sslv3"))
            .arg(flag_l("path-as-is"))
            .arg(flag_l("remote-header-name"))
            .arg(flag_l("remote-name-all"))
            .arg(flag_l("tcp-fastopen"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        // -o FILE → writes
        if let Some(files) = matches.get_many::<String>("output") {
            for f in files {
                writes.push(resolve(f, cwd));
            }
        }
        // -c FILE → writes (cookie jar)
        if let Some(f) = matches.get_one::<String>("cookie-jar") {
            writes.push(resolve(f, cwd));
        }
        // -D FILE → writes (dump header)
        if let Some(f) = matches.get_one::<String>("dump-header") {
            writes.push(resolve(f, cwd));
        }
        // -T FILE → reads (upload)
        if let Some(files) = matches.get_many::<String>("upload-file") {
            for f in files {
                reads.push(resolve(f, cwd));
            }
        }
        // -K FILE → reads (config)
        if let Some(f) = matches.get_one::<String>("config") {
            reads.push(resolve(f, cwd));
        }

        // Positionals are URLs — ignore them
        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}

pub(super) struct WgetParser;
impl CommandParser for WgetParser {
    fn parse(&self, args: &[&str], cwd: &str) -> Result<CommandFileAccesses, String> {
        let matches = base_cmd("wget")
            // File flags
            .arg(val('O', "output-document"))
            .arg(val('P', "directory-prefix"))
            .arg(val('i', "input-file"))
            .arg(val('a', "append-output"))
            .arg(val_l("post-file"))
            .arg(val_l("load-cookies"))
            .arg(val_l("save-cookies"))
            .arg(val_l("body-file"))
            .arg(val_l("ca-certificate"))
            .arg(val_l("certificate"))
            .arg(val_l("private-key"))
            // Common value-taking
            .arg(val('o', "output-file"))
            .arg(val('U', "user-agent"))
            .arg(val_l("header").action(ArgAction::Append))
            .arg(val_l("post-data"))
            .arg(val_l("body-data"))
            .arg(val_l("method"))
            .arg(val_l("user"))
            .arg(val_l("password"))
            .arg(val_l("http-user"))
            .arg(val_l("http-password"))
            .arg(val_l("proxy"))
            .arg(val_l("proxy-user"))
            .arg(val_l("proxy-password"))
            .arg(val_l("referer"))
            .arg(val('e', "execute").action(ArgAction::Append))
            .arg(val('Q', "quota"))
            .arg(val_l("limit-rate"))
            .arg(val('w', "wait"))
            .arg(val_l("waitretry"))
            .arg(val('t', "tries"))
            .arg(val('T', "timeout"))
            .arg(val_l("dns-timeout"))
            .arg(val_l("connect-timeout"))
            .arg(val_l("read-timeout"))
            .arg(val('l', "level"))
            .arg(val('A', "accept").action(ArgAction::Append))
            .arg(val('R', "reject").action(ArgAction::Append))
            .arg(val('D', "domains"))
            .arg(val_l("exclude-domains"))
            .arg(val_l("include-directories"))
            .arg(val_l("exclude-directories"))
            .arg(val_l("cut-dirs"))
            // Bool flags
            .arg(flag('q', "quiet"))
            .arg(flag('v', "verbose"))
            .arg(flag('c', "continue"))
            .arg(flag('N', "timestamping"))
            .arg(flag('S', "server-response"))
            .arg(flag('r', "recursive"))
            .arg(flag('p', "page-requisites"))
            .arg(flag('k', "convert-links"))
            .arg(flag('K', "backup-converted"))
            .arg(flag('m', "mirror"))
            .arg(flag('E', "adjust-extension"))
            .arg(flag('H', "span-hosts"))
            .arg(flag_l("no-check-certificate"))
            .arg(flag_l("no-clobber"))
            .arg(flag_l("no-directories"))
            .arg(flag_l("force-directories"))
            .arg(flag_l("no-host-directories"))
            .arg(flag_l("no-parent"))
            .arg(flag_l("content-disposition"))
            .arg(flag_l("trust-server-names"))
            .arg(flag_l("no-verbose"))
            .arg(flag_l("spider"))
            .arg(flag('b', "background"))
            .arg(bool_s('x'))
            .arg(flag('F', "force-html"))
            .arg(flag_l("delete-after"))
            .arg(flag_l("no-proxy"))
            .arg(flag_l("no-dns-cache"))
            .arg(flag_l("no-cache"))
            .arg(flag_l("no-cookies"))
            .arg(flag_l("keep-session-cookies"))
            .arg(flag_l("inet4-only"))
            .arg(flag_l("inet6-only"))
            .arg(files_arg())
            .try_get_matches_from(args)
            .map_err(|e| e.to_string())?;

        let mut reads = Vec::new();
        let mut writes = Vec::new();

        if let Some(f) = matches.get_one::<String>("output-document") {
            writes.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("directory-prefix") {
            writes.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("append-output") {
            writes.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("save-cookies") {
            writes.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("input-file") {
            reads.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("post-file") {
            reads.push(resolve(f, cwd));
        }
        if let Some(f) = matches.get_one::<String>("load-cookies") {
            reads.push(resolve(f, cwd));
        }

        // Positionals are URLs — ignore
        Ok(CommandFileAccesses { reads, writes, inline_script_start: None })
    }
}
