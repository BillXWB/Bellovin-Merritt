use std::error::Error;
use std::io;

pub fn into_io_error<E>(error: E) -> io::Error
where
    E: Into<Box<dyn Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, error)
}
