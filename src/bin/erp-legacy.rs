//! `erp-legacy --port N`: GET /health, GET /orders, GET /orders/<id>. Plain HTTP/1.0, std only. This stands for any
//! enterprise system that was never written for the mesh; erp.orders@1 wraps it.
use std::io::{BufRead, BufReader, Write};

const ORDERS: &[(&str, &str, u64, &str)] = &[
    ("SO-1001", "Kungsgatan Print AB", 129_900, "shipped"),
    ("SO-1002", "Umea Robotics", 48_500, "open"),
    ("SO-1003", "Norrland Labs", 990_000, "invoiced"),
];

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let port = a.iter().position(|x| x == "--port").and_then(|i| a.get(i + 1)).cloned().unwrap_or("8088".into());
    let l = std::net::TcpListener::bind(format!("127.0.0.1:{port}")).expect("bind");
    // Stop with the process that started it (the wrapper), as a service manager would.
    let parent = std::os::unix::process::parent_id();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if std::os::unix::process::parent_id() != parent {
            std::process::exit(0);
        }
    });
    for c in l.incoming().flatten() {
        let mut w = c.try_clone().unwrap();
        let mut line = String::new();
        if BufReader::new(c).read_line(&mut line).is_err() {
            continue;
        }
        let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
        let (code, body) = if path == "/health" {
            (200, "{\"ok\":true}".to_string())
        } else if path == "/orders" {
            (200, format!("[{}]", ORDERS.iter().map(|o| format!("\"{}\"", o.0)).collect::<Vec<_>>().join(",")))
        } else if let Some(id) = path.strip_prefix("/orders/") {
            match ORDERS.iter().find(|o| o.0 == id) {
                Some(o) => (200, format!("{{\"id\":\"{}\",\"customer\":\"{}\",\"total_cents\":{},\"status\":\"{}\"}}", o.0, o.1, o.2, o.3)),
                None => (404, "{\"error\":\"no such order\"}".into()),
            }
        } else {
            (404, "{\"error\":\"not found\"}".into())
        };
        let _ = write!(w, "HTTP/1.0 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    }
}
