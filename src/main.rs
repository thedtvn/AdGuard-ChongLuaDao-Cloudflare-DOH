mod json_obj;

use std::collections::HashSet;
use actix_web::{web, App, HttpResponse, HttpServer, Responder, HttpRequest, HttpResponseBuilder};
use actix_web::http::{Method, StatusCode};
use base64::Engine;
use qstring::QString;
use base64::engine::general_purpose;
use dns_parser::{Builder, Packet};
use uuid::Uuid;
use url::Url;

async fn dns_query(req: HttpRequest, bytes_body: web::Bytes, domains: web::Data<HashSet<String>>) -> impl Responder {
    let mut dns_q = Vec::new();
    if req.method() == Method::GET {
        let qs = QString::from(req.query_string());
        let val = qs.get("dns");
        if val.is_none() {
            return HttpResponse::BadRequest().body("no 'dns' query parameter found");
        } else {
            let val_qr = val.unwrap().to_string();
            dns_q = general_purpose::STANDARD.decode(val_qr.to_string()).unwrap();
        }
    } else if req.method() == Method::POST {
        if bytes_body.is_empty() {
            return HttpResponse::BadRequest().body("no request body found");
        }
        dns_q = bytes_body.to_vec();
    }
    let dns = Packet::parse(dns_q.as_slice()).unwrap();
    let mut new_dns_req = Builder::new_query(dns.header.id, dns.header.recursion_desired);
    let dns_rs = dns.questions;
    for i in dns_rs {
        if !domains.contains(&*i.qname.to_string()) {
            new_dns_req.add_question(i.qname.to_string().as_str(), i.prefer_unicast, i.qtype, i.qclass);
        } else {
            let fake_domain = Uuid::new_v4().to_string().replace("-", "");
            new_dns_req.add_question(&*fake_domain, i.prefer_unicast, i.qtype, i.qclass);
        }
    }
    let client = reqwest::Client::new();
    let dns_encode = general_purpose::STANDARD.encode(new_dns_req.build().unwrap());
    let dns_req = client.get(format!("https://dns.cloudflare.com/dns-query?dns={}", dns_encode)).send().await.unwrap();
    let status = dns_req.status().as_u16();
    let headers = dns_req.headers().clone();
    let body = dns_req.bytes_stream();
    let mut http_rp = HttpResponseBuilder::new(StatusCode::from_u16(status).unwrap()).streaming(body);
    http_rp.headers_mut().insert("Content-Type".parse().unwrap(), headers.get("Content-Type").unwrap().to_str().unwrap().parse().unwrap());
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
    }).bind(("127.0.0.1", 8080))?;
    println!("Server starting...");
    http_server.run().await
}