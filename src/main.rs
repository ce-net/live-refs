//! live-refs: ce-refs connecting anything to anything. `live-refs sim` runs the walk on four local processes.
mod cal;
mod ids;
mod node;
mod sim;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("sim") | None => {
            let out = std::path::PathBuf::from(a.iter().position(|x| x == "--out").and_then(|i| a.get(i + 1)).cloned().unwrap_or("proof".into()));
            if let Err(e) = sim::sim(&out) {
                eprintln!("live-refs sim: {e}");
                std::process::exit(1);
            }
            match sim::verify(&out) {
                Ok(s) => println!("proof: {s} ({}/run.jsonl)", out.display()),
                Err(e) => {
                    eprintln!("proof does not verify: {e}");
                    std::process::exit(1)
                }
            }
        }
        Some("node") => node::run(std::path::Path::new(&a[2])),
        Some("verify") => match sim::verify(std::path::Path::new(a.get(2).map(String::as_str).unwrap_or("proof"))) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1)
            }
        },
        Some("ids") => println!("{}", serde_json::to_string_pretty(&ids::identity()).unwrap()),
        Some(x) => {
            eprintln!("usage: live-refs [sim [--out DIR] | verify [DIR] | ids]   (unknown: {x})");
            std::process::exit(2)
        }
    }
}
