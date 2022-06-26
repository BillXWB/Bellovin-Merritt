use std::net::TcpStream;
use std::{env, io};

use log::{debug, info};

use bellovin_merritt::io::input;
use bellovin_merritt::send_secret;

fn main() -> io::Result<()> {
    env_logger::init();
    let port = env::args()
        .nth(1)
        .expect("用法：./client <port>")
        .parse::<u16>()
        .expect("非法端口号");
    let username = input("用户名：")?;
    let password = input("密码：")?;
    let mut stream = TcpStream::connect(("localhost", port))?;
    info!("连接成功！");
    if let Some(key) = send_secret(&mut stream, &username, &password)? {
        info!("登录成功！");
        debug!("会话密钥：{:?}", key);
    } else {
        info!("登录失败。");
    }
    Ok(())
}
