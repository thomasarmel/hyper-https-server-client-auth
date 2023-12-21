# Rust - Hyper HTTPS server with client-cert authentication example

---

*This code is a rewrite of the [excellent example of **aramperes**](https://github.com/aramperes/hyper-server-ssl-auth-example).
I basically rewrote it to use the latest version of all crates and remove the `openssl` dependency, which can be a pain to install.*

---

This is an example of a HTTPS server with client-cert authentication using crates [hyper](https://hyper.rs/) and [Rustls](https://github.com/rustls/rustls).
The client certificate serial number is replied in the response.

crates used:
- **rustls 0.22.1**
- **tokio 1.35.1**
- **tokio-rustls 0.25.0**
- **hyper 1.1.0**
- **hyper-util 0.1.2**
- **rustls-pemfile 2.0.0**
- **http-body-util 0.1.0**
- **x509-certificate 0.23.1**

## How to run

Just change, in `src/main.rs`, the path to your server certificate and key, and the path to your CA certificate used to sign the client certificate.:
- `CLIENT_CA_CERT_PATH`
- `SERVER_CERT_PATH`
- `SERVER_KEY_PATH`

You can also change the interface on which the server will listen: `LISTEN_ADDR`.

Then, run the server with `cargo run`.