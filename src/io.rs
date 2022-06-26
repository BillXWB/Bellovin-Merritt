use std::io;
use std::io::Write;
use std::iter::repeat_with;

use aead::generic_array::typenum::Unsigned;
use aead::{Aead, AeadCore, Key, NewAead, Nonce};
use rand::random;

use crate::error::into_io_error;

pub fn input(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut line = String::default();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

pub fn read_encrypted<Cipher: Aead + NewAead>(
    key: &Key<Cipher>,
    mut read: impl FnMut() -> io::Result<Vec<u8>>,
) -> io::Result<Option<Vec<u8>>> {
    let nonce = read()?;
    let message = if nonce.len() != <Cipher as AeadCore>::NonceSize::to_usize() {
        None
    } else {
        let nonce = Nonce::<Cipher>::from_slice(&nonce);
        let message = read()?;
        let cipher = Cipher::new(key);
        cipher.decrypt(nonce, message.as_ref()).ok()
    };
    Ok(message)
}

pub fn write_encrypted<Cipher: Aead + NewAead>(
    key: &Key<Cipher>,
    message: &[u8],
    mut write: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let nonce: Vec<_> = repeat_with(random)
        .take(<Cipher as AeadCore>::NonceSize::to_usize())
        .collect();
    write(&nonce)?;
    let nonce = Nonce::<Cipher>::from_slice(&nonce);
    let cipher = Cipher::new(key);
    let message = cipher.encrypt(nonce, message).map_err(into_io_error)?;
    write(&message)
}
