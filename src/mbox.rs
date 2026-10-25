use crate::dkim::Sig;
use crate::errors::*;
use mail_parser::mailbox::mbox::MessageIterator;
use mail_parser::{Address, Header, HeaderName, MessageParser};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use viadkim::signature::DkimSignature;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Email {
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub subject: Option<String>,
    pub message_ids: Vec<String>,
    pub dkim_signature: Option<Sig>,
    pub x_google_dkim_signature: Option<Sig>,
}

impl Email {
    pub fn print(&self, json: bool) -> Result<()> {
        if json {
            let json = serde_json::to_string(self)?;
            println!("{json}");
        } else {
            println!("{:#?}", self);
        }
        Ok(())
    }

    pub fn has_dkim(&self) -> bool {
        self.dkim().is_some()
    }

    pub fn dkim(&self) -> Option<&DkimSignature> {
        self.dkim_signature
            .as_ref()
            .or(self.x_google_dkim_signature.as_ref())
            .map(|sig| &sig.value)
    }

    pub fn set_text_header(target: &mut Option<String>, header: &Header) {
        if let Some(text) = header.value().as_text() {
            *target = Some(text.to_string());
        }
    }

    pub fn set_text_fn<T>(target: &mut Option<T>, header: &Header, f: impl Fn(&str) -> Option<T>) {
        if let Some(text) = header.value().as_text()
            && let Some(value) = f(text)
        {
            *target = Some(value);
        }
    }

    pub fn append_text_header(target: &mut Vec<String>, header: &Header) {
        if let Some(text) = header.value().as_text() {
            target.push(text.to_string());
        }
    }

    pub fn append_address_header(target: &mut Vec<String>, header: &Header) {
        let Some(addresses) = header.value().as_address() else {
            return;
        };

        let iter = addresses
            .iter()
            .flat_map(|addr| match addr {
                Address::Mailbox(mailbox) => Some(mailbox),
                Address::Group(group) => {
                    if group.mailboxes().peekable().peek().is_none() {
                        None
                    } else {
                        panic!("TODO: support group addresses: {:?}", group)
                    }
                }
            })
            .flat_map(|mailbox| mailbox.address())
            .map(String::from);

        target.extend(iter);
    }
}

pub struct Reader {
    reader: MessageIterator<BufReader<File>>,
}

impl Reader {
    pub fn new(file: File) -> Self {
        let reader = BufReader::new(file);
        let reader = MessageIterator::new(reader);
        Self { reader }
    }
}

impl Iterator for Reader {
    type Item = Result<(Email, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        for msg in &mut self.reader {
            let msg = match msg {
                Ok(msg) => msg,
                Err(err) => return Some(Err(err.into())),
            };

            let bytes = msg.contents();

            let Some(msg) = MessageParser::new().parse_headers(bytes) else {
                continue;
            };

            let mut email = Email::default();

            for header in msg.headers().iter() {
                match header.name() {
                    HeaderName::From => {
                        Email::append_address_header(&mut email.from, &header);
                    }
                    HeaderName::To => {
                        Email::append_address_header(&mut email.to, &header);
                    }
                    HeaderName::Subject => {
                        Email::set_text_header(&mut email.subject, &header);
                    }
                    HeaderName::MessageId => {
                        Email::append_text_header(&mut email.message_ids, &header);
                    }
                    HeaderName::DkimSignature => {
                        Email::set_text_fn(&mut email.dkim_signature, &header, |s| s.parse().ok());
                    }
                    // HeaderName::Dkim2Signature => panic!("TODO: dkim2signature"),
                    HeaderName::XGoogleDkimSignature => {
                        Email::set_text_fn(&mut email.x_google_dkim_signature, &header, |s| {
                            s.parse().ok()
                        });
                    }
                    _ => {}
                }
            }

            return Some(Ok((email, bytes.to_vec())));
        }

        None
    }
}

pub fn split_headers(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut scanned = 0usize;
    let mut pending = bytes;

    'outer: while let Some(idx) = memchr::memchr2(b'\r', b'\n', pending) {
        scanned = scanned.saturating_add(idx);

        let (_before, after) = bytes.split_at(scanned);
        pending = after;

        for delimiter in ["\r\n".as_bytes(), "\n".as_bytes()] {
            if let Some(after) = after.strip_prefix(delimiter) {
                if let Some(body) = after.strip_prefix(delimiter) {
                    return Some((bytes[..scanned].as_ref(), body));
                } else {
                    scanned = scanned.saturating_add(delimiter.len());
                    continue 'outer;
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_headers_crlf_crlf() {
        let input = b"Header: value\r\nHeader2: value2\r\n\r\nBody";
        let result = split_headers(input);
        assert!(result.is_some());
        let (headers, body) = result.unwrap();
        assert_eq!(headers, b"Header: value\r\nHeader2: value2");
        assert_eq!(body, b"Body");
    }

    #[test]
    fn test_split_headers_lf_lf() {
        let input = b"Header: value\nHeader2: value2\n\nBody";
        let result = split_headers(input);
        assert!(result.is_some());
        let (headers, body) = result.unwrap();
        assert_eq!(headers, b"Header: value\nHeader2: value2");
        assert_eq!(body, b"Body");
    }

    #[test]
    fn test_split_headers_crlf_crlf_body() {
        let input = b"Header: value\r\nHeader2: value2\r\n\r\nabc\ndef\r\n\r\nfoo\r\nbar\r\n";
        let result = split_headers(input);
        assert!(result.is_some());
        let (headers, body) = result.unwrap();
        assert_eq!(headers, b"Header: value\r\nHeader2: value2");
        assert_eq!(body, b"abc\ndef\r\n\r\nfoo\r\nbar\r\n");
    }

    #[test]
    fn test_split_headers_lf_lf_body() {
        let input = b"Header: value\nHeader2: value2\n\nabc\ndef\n\nfoo\nbar\n";
        let result = split_headers(input);
        assert!(result.is_some());
        let (headers, body) = result.unwrap();
        assert_eq!(headers, b"Header: value\nHeader2: value2");
        assert_eq!(body, b"abc\ndef\n\nfoo\nbar\n");
    }
}
