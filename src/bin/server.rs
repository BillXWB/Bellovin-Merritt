use std::net::TcpListener;
use std::{env, io};

use log::{debug, info};

use bellovin_merritt::io::input;
use bellovin_merritt::verify_secret;

fn main() -> io::Result<()> {
    env_logger::init();
    let port = env::args()
        .nth(1)
        .expect("用法：./server <port>")
        .parse::<u16>()
        .expect("非法端口号");
    let listener = TcpListener::bind(("localhost", port))?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        info!("连接成功！");
        let secret = input("密码：")?;
        if let Some((username, key)) = verify_secret(&mut stream, &secret)? {
            info!("验证成功：{}", username);
            debug!("会话密钥：{:?}", key);
        } else {
            info!("验证失败！");
        }
    }
    Ok(())
}
