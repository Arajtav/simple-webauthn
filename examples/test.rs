use std::io::{self, Read};

use passkeys::*;
use serde_json;

fn main() {
    let rp = Rp {
        name: "localhost".to_owned(),
        id: "localhost".to_owned(),
    };

    let origin = "http://localhost:3000".to_owned();

    let user = User {
        id: b"test".to_vec(),
        name: "test".to_owned(),
        display_name: "test".to_owned(),
    };

    let (request, state) = start_registration(rp, origin, user);
    println!("{}", serde_json::to_string_pretty(&request).unwrap());
    eprintln!("{state:#?}");

    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let input = input.trim();

    let response = serde_json::from_str(input).unwrap();
    println!("{:#?}", verify_registration(&response, &state));
}
