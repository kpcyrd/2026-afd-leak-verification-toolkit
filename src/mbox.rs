use crate::errors::*;
use mail_parser::mailbox::mbox::MessageIterator;
use mail_parser::{Address, Header, HeaderName, MessageParser};
use std::fs::File;
use std::io::BufReader;
use viadkim::signature::DkimSignature;

#[derive(Debug, Default)]
pub struct Email {
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub subject: Option<String>,
    pub message_ids: Vec<String>,
    pub dkim_signature: Option<DkimSignature>,
    pub x_google_dkim_signature: Option<DkimSignature>,
}

impl Email {
    pub fn has_dkim(&self) -> bool {
        self.dkim().is_some()
    }

    pub fn dkim(&self) -> Option<&DkimSignature> {
        self.dkim_signature
            .as_ref()
            .or(self.x_google_dkim_signature.as_ref())
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
    type Item = Result<Email>;

    fn next(&mut self) -> Option<Self::Item> {
        for msg in &mut self.reader {
            let msg = match msg {
                Ok(msg) => msg,
                Err(err) => return Some(Err(err.into())),
            };

            let Some(msg) = MessageParser::new().parse_headers(msg.contents()) else {
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

            return Some(Ok(email));
        }

        None
    }
}
