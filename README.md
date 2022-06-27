# Bellovin-Merritt 密钥交换

用了 [env_logger](https://crates.io/crates/env_logger "crates.io") 输出算法过程，设置环境变量 `RUST_LOG` 为 `debug`.

```shell
cargo run --release --bin server -- <port>
cargo run --release --bin client -- <port>
```

client 对应论文中的 Alice，server 对应论文中的 Bob. 输入的口令经过 Argon2id 生成论文所说的 P，对称加密用的 AES-GCM-SIV，公钥加密用的 RSA（没有找到其它算法好用的 crate...）。