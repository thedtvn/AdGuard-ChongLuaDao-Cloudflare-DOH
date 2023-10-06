mod json_obj;

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest, HttpResponseBuilder};
use actix_web::http::{Method, StatusCode};
use base64::Engine;
use qstring::QString;
use dns_message_parser::{Dns, DomainName};
use base64::engine::general_purpose;
use dns_parser::{Builder, Packet};
use url::Url;

async fn dns_query(req: HttpRequest, bytes_body: web::Bytes, domains: web::Data<HashSet<String>>) -> impl Responder {
    let mut dns_q = Vec::new();
    if req.method() == Method::GET {
        let qs = QString::from(req.query_string());
        let val = qs.get("dns");
        if val.is_none() {
            return HttpResponse::BadRequest().body("no 'dns' query parameter found");
        } else {
            let val_qr = val.unwrap();
            let decode_ch = general_purpose::STANDARD_NO_PAD.decode(val_qr.to_string());
            let var_cl = val_qr.to_string();
            if decode_ch.is_err() {
                let client = reqwest::Client::new();
                let dns_req = client.get(format!("https://dns.cloudflare.com/dns-query?dns={}", var_cl)).send().await.unwrap();
                let status = dns_req.status().as_u16();
                let headers = dns_req.headers().clone();
                let body = dns_req.bytes_stream();
                let mut http_rp = HttpResponseBuilder::new(StatusCode::from_u16(status).unwrap()).streaming(body);
                let head = headers.get("Content-Type");
                if head.is_some() {
                    http_rp.headers_mut().insert("Content-Type".parse().unwrap(), head.unwrap().to_str().unwrap().parse().unwrap());
                }
                return HttpResponse::from(http_rp);
            }
            dns_q = decode_ch.unwrap();
        }
    } else if req.method() == Method::POST {
        if bytes_body.is_empty() {
            return HttpResponse::BadRequest().body("no request body found");
        }
        dns_q = bytes_body.to_vec();
    }
    let dns_check = Packet::parse(dns_q.as_slice());
    if dns_check.is_err() {
        let client = reqwest::Client::new();
        let dns_encode = general_purpose::STANDARD.encode(dns_q);
        let dns_req = client.get(format!("https://dns.cloudflare.com/dns-query?dns={}", dns_encode)).send().await.unwrap();
        let status = dns_req.status().as_u16();
        let headers = dns_req.headers().clone();
        let body = dns_req.bytes_stream();
        let mut http_rp = HttpResponseBuilder::new(StatusCode::from_u16(status).unwrap()).streaming(body);
        let head = headers.get("Content-Type");
        if head.is_some() {
            http_rp.headers_mut().insert("Content-Type".parse().unwrap(), head.unwrap().to_str().unwrap().parse().unwrap());
        }
        return HttpResponse::from(http_rp);
    }
    let dns = dns_check.unwrap();
    let mut new_dns_req = Builder::new_query(dns.header.id, dns.header.recursion_desired);
    let dns_rs = dns.questions;
    let mut cache_fake_domain = HashMap::new();
    for i in dns_rs {
        if !domains.contains(&*i.qname.to_string()) {
            new_dns_req.add_question(i.qname.to_string().as_str(), i.prefer_unicast, i.qtype, i.qclass);
        } else {
            println!("Blocked domain: {:?}", i.qname.to_string());
            let uuid_f = uuid::Uuid::new_v4().to_string();
            cache_fake_domain.insert(uuid_f.clone(), i.qname.to_string());
            new_dns_req.add_question(&*uuid_f, i.prefer_unicast, i.qtype, i.qclass);
        }
    }
    let client = reqwest::Client::new();
    let dns_encode = general_purpose::STANDARD.encode(new_dns_req.build().unwrap());
    let dns_req = client.get(format!("https://dns.cloudflare.com/dns-query?dns={}", dns_encode)).send().await.unwrap();
    let status = dns_req.status().as_u16();
    let headers = dns_req.headers().clone();
    let body = dns_req.bytes().await.unwrap();
    let dns_old = Dns::decode(body).unwrap();
    let mut questions_map = Vec::new();
    for i in dns_old.questions {
        let mut domain = i.domain_name.to_string();
        domain.replace_range(domain.len()-1..domain.len(), "");
        if cache_fake_domain.contains_key(&*domain) {
            questions_map.push(dns_message_parser::question::Question { domain_name: DomainName::from_str(&*domain).unwrap(), q_class: i.q_class, q_type: i.q_type });
        } else {
            questions_map.push(i);
        }
    }
    let new_dns_r = Dns {
        id: dns_old.id,
        flags: dns_old.flags,
        questions: questions_map,
        answers: dns_old.answers,
        authorities: dns_old.authorities,
        additionals: dns_old.additionals,
    };
    let body = new_dns_r.encode().unwrap();
    let mut http_rp = HttpResponseBuilder::new(StatusCode::from_u16(status).unwrap()).body(body);
    let head = headers.get("Content-Type");
    if head.is_some() {
        http_rp.headers_mut().insert("Content-Type".parse().unwrap(), head.unwrap().to_str().unwrap().parse().unwrap());
    }
    HttpResponse::from(http_rp)
}

async fn update_ads() -> HashSet<String> {
    let mut cache_set:HashSet<String> = HashSet::new();
    let client = reqwest::Client::new();
    let ads_list = client.get("https://v.firebog.net/hosts/AdguardDNS.txt").send().await.unwrap();
    let ads_list_text = ads_list.text().await.unwrap();
    for i in ads_list_text.lines() {
        if !(i.starts_with("#") || i.is_empty()) {
            cache_set.insert(i.to_string());
        }
    }
    let ads_list_easylist = client.get("https://v.firebog.net/hosts/Easylist.txt").send().await.unwrap();
    let ads_list_text_easylist = ads_list_easylist.text().await.unwrap();
    for i in ads_list_text_easylist.lines() {
        if !(i.starts_with("#") || i.is_empty()) {
            if !cache_set.contains(i) {
                cache_set.insert(i.to_string());
            }
        }
    }
    let ads_list_admiral = client.get("https://v.firebog.net/hosts/Admiral.txt").send().await.unwrap();
    let ads_list_text_admiral = ads_list_admiral.text().await.unwrap();
    for i in ads_list_text_admiral.lines() {
        if !(i.starts_with("#") || i.is_empty()) {
            if !cache_set.contains(i) {
                cache_set.insert(i.to_string());
            }
        }
    }
    let cld_list = client.get("https://api.chongluadao.vn/v2/blacklist").send().await.unwrap();
    let ads_list_json = cld_list.json::<json_obj::CldList>().await.unwrap();
    for i in ads_list_json {
        let url = Url::parse(&*i.url);
        if url.is_err() { continue; }
        let data = url.unwrap().host().unwrap().to_string().replace("*.", "");
        if !cache_set.contains(&*data) {
            cache_set.insert(data);
        }
    }
    cache_set
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let domains:HashSet<String> = update_ads().await;
    let domains_appdata = web::Data::new(domains.clone());
    let http_server = HttpServer::new(move || {
        App::new().app_data(domains_appdata.clone())
            .route("/dns-query", web::get().to(dns_query))
            .route("/dns-query", web::post().to(dns_query))
    }).bind(("127.0.0.1", 2001))?;
    println!("Server starting...");
    http_server.run().await
}