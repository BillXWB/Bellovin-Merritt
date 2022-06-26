// https://ieeexplore.ieee.org/document/213269

use std::iter::repeat_with;
use std::net::TcpStream;

use aead::generic_array::typenum::Unsigned;
use aead::NewAead;
use aes_gcm_siv::{Aes256GcmSiv, Key};
use log::debug;
use rand::{random, thread_rng};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

use crate::error::into_io_error;
use crate::hash::hash_password;
use crate::io::{read_encrypted, write_encrypted};
use crate::tcp::{receive, send};

pub mod error;
pub mod hash;
pub mod io;
pub mod tcp;

const CHALLENGE_LENGTH: usize = 64;
const RSA_LENGTH: usize = 4096;

// Alice
pub fn send_secret(
    stream: &mut TcpStream,
    identifier: &str,
    secret: &str,
) -> std::io::Result<Option<Vec<u8>>> {
    let key = hash_password(secret)?;
    debug!("使用 P：{:?}", key);
    // RPK.1
    debug!("生成 E_A、D_A 中...");
    let d_a = RsaPrivateKey::new(&mut thread_rng(), RSA_LENGTH).map_err(into_io_error)?;
    let e_a = RsaPublicKey::from(&d_a);
    debug!("生成 E_A：{:?}", e_a);
    debug!("生成 D_A: {:?}", d_a);
    let e_a = bincode::serialize(&e_a).map_err(into_io_error)?;
    send(stream, identifier.as_bytes())?;
    write_encrypted::<Aes256GcmSiv>(&key, &e_a, |message| send(stream, message))?;
    // RPK.2
    let key = read_encrypted::<Aes256GcmSiv>(&key, || receive(stream))?
        .and_then(|key| {
            d_a.decrypt(PaddingScheme::new_oaep::<sha3::Sha3_512>(), &key)
                .ok()
        })
        .map(|key| Key::clone_from_slice(&key));
    let key = if let Some(key) = key {
        key
    } else {
        return Ok(None);
    };
    debug!("接收 R：{:?}", key);
    // RPK.3
    let challenge_a: Vec<_> = repeat_with(random).take(CHALLENGE_LENGTH).collect();
    debug!("生成 challenge_A：{:?}", challenge_a);
    write_encrypted::<Aes256GcmSiv>(&key, &challenge_a, |message| send(stream, message))?;
    // RPK.4
    if !read_encrypted::<Aes256GcmSiv>(&key, || receive(stream))?
        .map_or(false, |challenge| challenge == challenge_a)
    {
        return Ok(None);
    }
    let challenge_b = read_encrypted::<Aes256GcmSiv>(&key, || receive(stream))?;
    let challenge_b = if let Some(challenge_b) = challenge_b {
        challenge_b
    } else {
        return Ok(None);
    };
    debug!("接收 challenge_B：{:?}", challenge_b);
    // RPK.5
    write_encrypted::<Aes256GcmSiv>(&key, &challenge_b, |message| send(stream, message))?;
    Ok(Some(key.to_vec()))
}

// Bob
pub fn verify_secret(
    stream: &mut TcpStream,
    secret: &str,
) -> std::io::Result<Option<(String, Vec<u8>)>> {
    let key = hash_password(secret)?;
    debug!("使用 P：{:?}", key);
    // RPK.1
    let identifier = receive(stream)?;
    let identifier = if let Ok(identifier) = String::from_utf8(identifier) {
        identifier
    } else {
        return Ok(None);
    };
    debug!("接收 A：{}", identifier);
    let e_a = read_encrypted::<Aes256GcmSiv>(&key, || receive(stream))?
        .and_then(|e_a| bincode::deserialize(&e_a).ok());
    let e_a: RsaPublicKey = if let Some(e_a) = e_a {
        e_a
    } else {
        return Ok(None);
    };
    debug!("接收 E_A：{:?}", e_a);
    // RPK.2
    let r: Vec<_> = repeat_with(random)
        .take(<Aes256GcmSiv as NewAead>::KeySize::to_usize())
        .collect();
    write_encrypted::<Aes256GcmSiv>(
        &key,
        &e_a.encrypt(
            &mut thread_rng(),
            PaddingScheme::new_oaep::<sha3::Sha3_512>(),
            &r,
        )
        .map_err(into_io_error)?,
        |message| send(stream, message),
    )?;
    let key = Key::from_slice(&r);
    debug!("生成 R：{:?}", key);
    // RPK.3
    let challenge_a = read_encrypted::<Aes256GcmSiv>(key, || receive(stream))?;
    let challenge_a = if let Some(challenge_a) = challenge_a {
        challenge_a
    } else {
        return Ok(None);
    };
    debug!("接收 challenge_A：{:?}", challenge_a);
    // RPK.4
    write_encrypted::<Aes256GcmSiv>(key, &challenge_a, |message| send(stream, message))?;
    let challenge_b: Vec<_> = repeat_with(random).take(CHALLENGE_LENGTH).collect();
    debug!("生成 challenge_B：{:?}", challenge_b);
    write_encrypted::<Aes256GcmSiv>(key, &challenge_b, |message| send(stream, message))?;
    // RPK.5
    if !read_encrypted::<Aes256GcmSiv>(key, || receive(stream))?
        .map_or(false, |challenge| challenge == challenge_b)
    {
        Ok(None)
    } else {
        Ok(Some((identifier, key.to_vec())))
    }
}
