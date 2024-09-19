use std::collections::HashMap;

use chrono::Utc;

use crate::{general::TcpFlag, util::ipv4_to_string};
use super::Tracer as RootTracer;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum HTTPContentMethod {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum HTTPContentStatus {
    Ok = 200,
    MovedPermanently = 301,
    BadRequest = 400,
    Forbidden = 403,
    NotFound = 404,
    InternalError = 500, 
    ServiceUnavailable = 503,
}

impl HTTPContentStatus {
    pub fn to_tuple(&self) -> (u16, String) {
        match self {
            HTTPContentStatus::Ok => (*self as u16, "OK".to_string()),
            HTTPContentStatus::MovedPermanently => (*self as u16, "Moved Permanently".to_string()),
            HTTPContentStatus::BadRequest => (*self as u16, "Bad Request".to_string()),
            HTTPContentStatus::Forbidden => (*self as u16, "Forbidden".to_string()),
            HTTPContentStatus::NotFound => (*self as u16, "Not Found".to_string()),
            HTTPContentStatus::InternalError => (*self as u16, "Internal Error".to_string()),
            HTTPContentStatus::ServiceUnavailable => (*self as u16, "Service Unavailable".to_string()),
        }
    }
}

impl HTTPContentMethod {
    pub fn output(&self) -> String {
        match self {
            HTTPContentMethod::Get => "GET".to_owned(),
            HTTPContentMethod::Post => "POST".to_owned(),
            HTTPContentMethod::Put => "PUT".to_owned(),
            HTTPContentMethod::Delete => "DELETE".to_owned()
        }
    }
}

#[derive(Debug, Clone, PartialEq, PartialOrd)]
pub struct HTTPContent
{
    method: HTTPContentMethod,
    url: String,
    title: String,
    content: String
}

pub struct Tracer
{
    root: RootTracer,
    req_info: HashMap<String, String>,
    resp_info: HashMap<String, String>,
}

impl Tracer
{
    pub fn new(handler: RootTracer, server_name: &str) -> Self {
        let mut req_info = HashMap::new();
        req_info.insert("Connection".to_string(), "keep-alive".to_string());
        req_info.insert("Pragma".to_string(), "no-cache".to_string());
        req_info.insert("Cache-Control".to_string(), "no-cache".to_string());
        req_info.insert("Upgrade-Insecure-Requests".to_string(), "1".to_string());
        req_info.insert("User-Agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36".to_string());
        req_info.insert("Accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string());
        req_info.insert("Accept-Encoding".to_string(), "gzip, deflate".to_string());
        req_info.insert("Accept-Language".to_string(), "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7".to_string());


        let mut resp_info = HashMap::new();
        resp_info.insert("Content-Type".to_string(), "text/html;charset=utf-8".to_string());
        resp_info.insert("Server".to_string(), server_name.to_string());
        Self {
            root: handler,
            req_info,
            resp_info,
        }
    }

    pub fn internal_mut(&mut self) -> &mut RootTracer {
        &mut self.root
    }

    pub fn internal(&self) -> &RootTracer {
        &self.root
    }

    pub fn sendp_connect(&mut self) {
        self.internal_mut().sendp_handshake();
    }

    pub fn connected(&self) -> bool {
        self.internal().connected
    }

    pub fn sendp_disconnect(&mut self) {
        if self.connected() {
            self.internal_mut().sendp_tcp_finish();
        }
    }

    pub fn sendp_response(&mut self, status: HTTPContentStatus, from: &str, content: &str, fin: bool, recv_ack: bool) -> Vec<Vec<u8>> {
        let now = Utc::now();
        let intl = &mut self.root;
        let (status_num, desc) = status.to_tuple();
        let mut pkts = vec![];
        
        let mut string = String::new();
        let header = format!("HTTP/1.1 {} {}", status_num, desc);
        string += &header;
        string += "\r\n";
        for (k, v) in &self.resp_info {
            string += &format!("{}: {}\r\n", k, v);
        }
        
        if fin {
            string += &format!("Connection: close\r\n");
        }
        else {
            string += &format!("Connection: keep-alive\r\n");
        }

        string += &format!("Location: {}\r\n", from);
        string += &format!("Date: {}\r\n", now.format("%a, %d %b %Y %H:%M:%S GMT").to_string());
        string += &format!("Content-Length: {}\r\n", content.len());
        string += "\r\n";


        pkts.extend(intl.send(string.as_bytes(), recv_ack));

        if content.len() > 0 {
            let with_flags = if fin {
                TcpFlag::Push | TcpFlag::Ack | TcpFlag::Fin as u8
            }
            else {
                TcpFlag::Push | TcpFlag::Ack
            };
            pkts.extend(intl.send_advanced(content.as_bytes(), recv_ack, with_flags));
        }
        pkts
    }

    pub fn sendp_request(&mut self, method: HTTPContentMethod, url: &str, recv_ack: bool) -> Vec<u8> {
        let mut expect = vec![];
        if !self.connected() {
            self.sendp_connect();
        }
        let intl = &mut self.root;
        let session = intl.as_session_ref();

        let mut string = String::new();
        let http_header = format!("{} {} HTTP/1.1", method.output(), url);
        let host = if !session.is_reverse() {
            format!("Host: {}:{}", ipv4_to_string(&session.l3_dst_ip), session.l4_dport)
        } else {
            format!("Host: {}:{}", ipv4_to_string(&session.l3_src_ip), session.l4_sport)
        };
        string += &http_header;
        string += "\r\n";
        string += &host;
        string += "\r\n";
        for (k, v) in &self.req_info {
            string += &format!("{}: {}\r\n", k, v);
        }
        string += "\r\n";
        expect.extend(intl.send(string.as_bytes(), recv_ack));
        if expect.len() == 1 {
            expect[0].to_owned()
        }
        else {
            vec![]
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{general::{IPProtocol, TcpFlag}, preset::catch_syn_fp_preset, tracer::Tracer};
    use super::{HTTPContentMethod, HTTPContentStatus, Tracer as HTTPTracer};

    #[test]
    pub fn test_http_tracer() {
        let mut tracer = Tracer::new_with_l4(IPProtocol::TCP, 46103, 1980);
        tracer.set_mode_record_packet(true);
        tracer.regi_os(TcpFlag::Syn as u8, &catch_syn_fp_preset("Linux_2_0").unwrap());

        let mut http_tracer = HTTPTracer::new(tracer, "SampleServer/1.0");
        http_tracer.sendp_request(HTTPContentMethod::Get, "/index.html?hello=1", true);
        http_tracer.internal_mut().switch_direction(false);
        http_tracer.sendp_response(HTTPContentStatus::InternalError, "/index.html?hello=1", "<html>Internal Error</html>\n", true, false);

        http_tracer.sendp_request(HTTPContentMethod::Get, "/index.html?hello=2", true);
        http_tracer.internal_mut().switch_direction(false);
        http_tracer.sendp_response(HTTPContentStatus::InternalError, "/index.html?hello=2", "<html>Internal Error</html>\n", true, false);

        http_tracer.sendp_request(HTTPContentMethod::Get, "/index.html?hello=3", true);
        http_tracer.internal_mut().switch_direction(false);
        http_tracer.sendp_response(HTTPContentStatus::Ok, "/index.html?hello=3", "<html><title>Hello world</title><body><h1>You find!</h1></body></html>\n", true, false);
        let _ = http_tracer.internal().to_pcap("http_request.pcap");
    }
}