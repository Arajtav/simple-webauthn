use std::io::{self, BufRead};

use passkeys::*;
use serde::de::DeserializeOwned;
use serde_json;

fn read_json<T: DeserializeOwned>(stdin: &mut impl BufRead) -> T {
    let mut input = String::new();

    loop {
        let mut line = String::new();
        let n = stdin.read_line(&mut line).unwrap();

        if n == 0 {
            panic!("unexpected EOF");
        }

        if line.trim().is_empty() && !input.trim().is_empty() {
            break;
        }

        input.push_str(&line);
    }

    serde_json::from_str(input.trim()).unwrap()
}

fn main() {
    let rp_id = "localhost".to_owned();

    let rp = Rp {
        name: "localhost".to_owned(),
        id: rp_id.clone(),
    };

    let origin = "http://localhost:3000".to_owned();

    let user = User {
        id: b"test".to_vec(),
        name: "test".to_owned(),
        display_name: "test".to_owned(),
    };

    let mut stdin = io::stdin().lock();

    let (request, state) = start_registration(rp, origin.clone(), user);
    println!("{}", serde_json::to_string_pretty(&request).unwrap());
    eprintln!("{state:#?}");

    let response = read_json(&mut stdin);
    let cred = verify_registration(response, state).unwrap();

    let (request, state) = start_authentication(rp_id, origin, Requirement::Required);
    println!("{}", serde_json::to_string_pretty(&request).unwrap());
    eprintln!("{state:#?}");

    let response = read_json(&mut stdin);

    println!("{:#?}", verify_authentication(response, state, &[cred]));
}
