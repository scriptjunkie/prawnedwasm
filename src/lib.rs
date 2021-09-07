//  Prawned
//  Crypto routines for an HTML-based anonymity network
//  Copyright (C) 2021  Matthew Weeks
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as
//  published by the Free Software Foundation, either version 3 of the
//  License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
use wasm_bindgen::prelude::*;
use rand_core::CryptoRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, ecdh::EphemeralSecret};
use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier};
use js_sys::{Uint8Array, Uint32Array};
use aes_gcm_siv::Aes256GcmSiv; // Or `Aes128GcmSiv`
use aes_gcm_siv::aead::{AeadInPlace, NewAead, generic_array::GenericArray};
use aes_gcm_siv::aead::heapless::{Vec, consts::U2048, consts::U12};
use std::convert::TryFrom;

//"Random" number generator that just echos the seed it has been given
struct SeedRng([u32; 8]);
impl CryptoRng for SeedRng {}
impl rand_core::block::BlockRngCore for SeedRng {
    type Item = u32;
    type Results = [u32; 8];
    fn generate(&mut self, results: &mut Self::Results) {
        *results = self.0
    }
}

fn seed_to_rng(seed: Uint32Array) -> rand_core::block::BlockRng<SeedRng> {
    let mut backing = [0; 8];
    backing.iter_mut().enumerate().for_each(|(i, b)| *b = seed.get_index(i as u32));
    rand_core::block::BlockRng::<SeedRng>::new(SeedRng(backing))
}

fn secret_from_seed(seed: Uint32Array) -> EphemeralSecret {
    EphemeralSecret::random(seed_to_rng(seed))
}
#[wasm_bindgen]
pub fn seed_to_ecdh_pub(seed: Uint32Array, pubkey: Uint8Array) {
    let pk_point = secret_from_seed(seed).public_key().to_encoded_point(true);
    pk_point.as_bytes().iter().enumerate().for_each(|(i,b)| pubkey.set_index(i as u32, *b));
}

fn sign_secret_from_seed(seed: Uint32Array) -> SigningKey {
    SigningKey::random(seed_to_rng(seed))
}
#[wasm_bindgen]
pub fn seed_to_ecdsa_pub(seed: Uint32Array, pk: Uint8Array) {
    let pub_pt = sign_secret_from_seed(seed).verify_key().to_encoded_point(true);
    pub_pt.as_bytes().iter().enumerate().for_each(|(i,b)| pk.set_index(i as u32, *b));
}

#[wasm_bindgen]
pub fn seed_sign(seed: Uint32Array, message: Uint8Array, sig: Uint8Array) -> bool {
    if message.length() > 2048 {
        return false;
    }
    let mut msgbuf = [0; 2048];
    for i in 0..message.length() {
        msgbuf[i as usize] = message.get_index(i);
    }
    let signature = sign_secret_from_seed(seed).sign(&msgbuf[..message.length() as usize]);
    signature.as_ref().iter().enumerate().for_each(|(i,b)| sig.set_index(i as u32, *b));
    true
}

#[wasm_bindgen]
pub fn pk_verif(pk: Uint8Array, message: Uint8Array, sig: Uint8Array) -> bool {
    if message.length() > 2048 {
        return false;
    }
    let mut msgbuf = [0; 2048];
    for i in 0..message.length() as usize {
        msgbuf[i] = message.get_index(i as u32);
    }
    let mut verif_key_bytes = [0; 33];
    verif_key_bytes.iter_mut().enumerate().for_each(|(i, b)| *b = pk.get_index(i as u32)); //copy to [u8]
    let verify_key_res = VerifyingKey::from_sec1_bytes(&verif_key_bytes); // Convert to VerifyingKey
    let verify_key = if let Ok(s) = verify_key_res { s } else { return false; };
    
    let mut sig_bytes = [0; 64];
    sig_bytes.iter_mut().enumerate().for_each(|(i, b)| *b = sig.get_index(i as u32)); //copy to [u8]
    let sig = if let Ok(s) = Signature::try_from(&sig_bytes[..]) { s } else { return false; }; //to Signature
    
    verify_key.verify(&msgbuf[..message.length() as usize], &sig).is_ok()
}

#[wasm_bindgen]
pub fn shared_secret(seed: Uint32Array, other_pubkey_bytes: Uint8Array, result: Uint8Array) -> u32 {
    let mut otherk = [0; 33];
    otherk.iter_mut().enumerate().for_each(|(i, b)| *b = other_pubkey_bytes.get_index(i as u32));
    let other_pub = PublicKey::from_sec1_bytes(&otherk).expect("bad key"); //TODO: handle
    let shared = secret_from_seed(seed).diffie_hellman(&other_pub);
    let shared_bytes = shared.as_bytes();
    for (i, byt) in shared_bytes.iter().enumerate() {
        result.set_index(i as u32, *byt);
    }
    shared_bytes.len() as u32
}

//gets key, nonce, cipher, and buffer from input
type KNCB = (Aes256GcmSiv, GenericArray<u8, U12>, Vec<u8, U2048>);
fn kncb(key: Uint8Array, nonce: Uint8Array, input: &Uint8Array, blen: u32) -> KNCB {
    let mut keyb = [0; 32];
    keyb.iter_mut().enumerate().for_each(|(i, b)| *b = key.get_index(i as u32));
    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&keyb));
    let mut nonceb = [0; 12];
    nonceb.iter_mut().enumerate().for_each(|(i, b)| *b = nonce.get_index(i as u32));
    let noncea = GenericArray::from_slice(&nonceb); // 96-bits; unique per message
    let mut buffer: Vec<u8, U2048> = Vec::new();
    for i in 0..blen as usize {
        buffer.extend_from_slice(&[input.get_index(i as u32)][..]).expect("too large!");
    }
    (cipher, *noncea, buffer)
}

#[wasm_bindgen]
pub fn encaes256gsiv(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ptlen: u32) -> u32 {
    let (cipher, noncea, mut buffer) = kncb(key, nonce, &plaintext, ptlen);
    if let Err(_) = cipher.encrypt_in_place(&noncea, b"", &mut buffer){ return 0; }
    for i in 0..buffer.len() {
        plaintext.set_index(i as u32, buffer[i]);
    }
    buffer.len() as u32
}

#[wasm_bindgen]
pub fn decaes256gsiv(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ctlen: u32) -> u32 {
    let (cipher, noncea, mut buffer) = kncb(key, nonce, &plaintext, ctlen);
    if let Err(_) = cipher.decrypt_in_place(&noncea, b"", &mut buffer){ return 0; }
    for i in 0..buffer.len() {
        plaintext.set_index(i as u32, buffer[i]);
    }
    buffer.len() as u32
}
