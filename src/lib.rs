//! # bedrock-jwt
//! A library for verifying JWT tokens for Minecraft: Bedrock Edition.
//!
//! This library provides functionality to verify the authenticity of a chain of JWT tokens
//! provided by a client, ensuring that the player's identity is valid and trusted.
//!
//! ## Features
//!
//! - JWT chain verification
//! - Player data extraction
//! - Public key handling from Base64 encoded strings
//!
//! ## Usage
//!
//! The primary entry point for this library is the `verify_chain` function, which takes a slice
//! of JWT tokens and a Mojang public key to perform verification.
//!
//! ```rust,no_run
//! use bedrock_jwt::verifier::{verify_chain, PlayerClaims};
//!
//! let tokens = vec![
//!     "first_jwt_token",
//!     "second_jwt_token",
//!     "third_jwt_token",
//! ];
//! let mojang_public_key = "your_mojang_public_key";
//!
//! match verify_chain(&tokens, mojang_public_key) {
//!     Ok(claims) => {
//!         println!("Successfully verified player: {}", claims.display_name);
//!     }
//!     Err(e) => {
//!         eprintln!("Verification failed: {}", e);
//!     }
//! }
//! ```

pub mod verifier;

pub use verifier::*;