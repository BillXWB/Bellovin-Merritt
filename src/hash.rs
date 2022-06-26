use std::io;

use aead::generic_array::typenum::Unsigned;
use aead::NewAead;
use aes_gcm_siv::{Aes256GcmSiv, Key};
use argon2::Argon2;
use lazy_static::lazy_static;
use password_hash::Salt;

use crate::into_io_error;

lazy_static! {
    static ref ARGON2: Argon2<'static> = Argon2::default();
    static ref EMPTY_SALT: String = String::from_iter(['0'; Salt::RECOMMENDED_LENGTH]);
}

pub fn hash_password(password: &str) -> io::Result<Key<<Aes256GcmSiv as NewAead>::KeySize>> {
    let mut key = vec![u8::default(); <Aes256GcmSiv as NewAead>::KeySize::to_usize()];
    ARGON2
        .hash_password_into(password.as_bytes(), EMPTY_SALT.as_bytes(), &mut key)
        .map_err(into_io_error)?;
    Ok(Key::clone_from_slice(&key))
}
