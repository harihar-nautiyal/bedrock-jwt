use std::io;

fn main() {
    println!("Enter the 3 JWT tokens, one per line, followed by an empty line:");

    let mut tokens = Vec::new();
    for _ in 0..3 {
        let mut token = String::new();
        io::stdin().read_line(&mut token).expect("Failed to read line");
        tokens.push(token.trim().to_string());
    }

    println!("Enter the Mojang public key:");
    let mut mojang_key = String::new();
    io::stdin().read_line(&mut mojang_key).expect("Failed to read line");
    let mojang_key = mojang_key.trim();

    let token_slices: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();

    match bedrock_jwt::verifier::verify_chain(&token_slices, &mojang_key) {
        Ok(claims) => {
            println!("\n--- Verified Player Data ---");
            println!("  Display Name: {}", claims.display_name);
            println!("  UUID:         {}", claims.uuid);
            println!("  XUID:         {}", claims.xuid);
            println!("-----------------------------");
        }
        Err(e) => {
            eprintln!("\nFATAL ERROR: Verification failed. Details: {}", e);
            std::process::exit(1);
        }
    }
}