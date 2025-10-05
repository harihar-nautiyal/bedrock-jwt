# bedrock-jwt

A Rust library for verifying JWT tokens for Minecraft: Bedrock Edition.

This library provides functionality to verify the authenticity of a chain of JWT tokens
provided by a client, ensuring that the player's identity is valid and trusted.

## Features

- JWT chain verification
- Player data extraction
- Public key handling from Base64 encoded strings

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
bedrock-jwt = { git = "https://github.com/harihar-nautiyal/bedrock-jwt.git" }
```

The primary entry point for this library is the `verify_chain` function, which takes a slice
of JWT tokens and a Mojang public key to perform verification.

```rust,no_run
use bedrock_jwt::verifier::{verify_chain, PlayerClaims};

fn main() {
    let tokens = vec![
        "first_jwt_token",
        "second_jwt_token",
        "third_jwt_token",
    ];
    let mojang_public_key = "your_mojang_public_key";

    match verify_chain(&tokens, mojang_public_key) {
        Ok(claims) => {
            println!("Successfully verified player: {}", claims.display_name);
        }
        Err(e) => {
            eprintln!("Verification failed: {}", e);
        }
    }
}
```

## Building

To build the library, run:

```bash
cargo build
```

## Running the example

The `main.rs` file contains an example of how to use the library. It reads the JWT tokens and the Mojang public key from standard input and then verifies the chain.

To run the example:

```bash
cargo run
```

Then, paste the three JWT tokens, each on a new line, followed by the Mojang public key on a new line.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
''
