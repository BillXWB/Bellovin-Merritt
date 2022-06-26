use std::io;
use std::io::{Read, Write};
use std::mem::size_of;
use std::net::TcpStream;

pub fn send(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    let length = message.len() as u64;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(message)?;
    Ok(())
}

pub fn receive(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut length = [u8::default(); size_of::<u64>()];
    stream.read_exact(&mut length)?;
    let length = u64::from_be_bytes(length);
    let mut message = vec![u8::default(); length as _];
    stream.read_exact(&mut message)?;
    Ok(message)
}
