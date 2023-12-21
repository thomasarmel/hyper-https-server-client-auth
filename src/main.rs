use std::net::SocketAddr;
use std::convert::Infallible;
use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::TcpListener;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{WebPkiClientVerifier};
use x509_certificate::X509Certificate;

// Change these constants depending on your usage
const LISTEN_ADDR: &'static str = "127.0.0.1:3000";
const CLIENT_CA_CERT_PATH: &'static str = "<YOUR CLIENT CA HERE>.crt";
const SERVER_CERT_PATH: &'static str = "<YOUR SERVER CERT HERE>.crt";
const SERVER_KEY_PATH: &'static str = "<YOUR SERVER KEY HERE>.key";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = LISTEN_ADDR.parse::<SocketAddr>().unwrap();

    let tls_server_config = get_ssl_config()?;
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server_config));

    // We create a TcpListener and bind it
    let listener = TcpListener::bind(addr).await?;

    // We start a loop to continuously accept incoming connections
    loop {
        println!("Waiting for incoming connection");
        let Ok(stream) = tls_acceptor.accept(listener.accept().await?.0).await else {
            println!("Error accepting connection, maybe client certificate is missing?");
            continue;
        };
        println!("Received connection from peer {}", stream.get_ref().0.peer_addr().unwrap());
        let (_, server_session) = stream.get_ref();
        let client_cert = X509Certificate::from_der(
            server_session.peer_certificates().unwrap().first().unwrap())
            .unwrap();
        let client_cert_serial_str = Arc::new(format!("{:02X?}", client_cert.serial_number_asn1().as_slice()));

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            let response_service = service_fn(|req: Request<hyper::body::Incoming>| {
                let local_client_cert_serial_str = Arc::clone(&client_cert_serial_str);
                async move {
                    Ok::<_, Infallible>(hello(req, local_client_cert_serial_str).await.unwrap())
                }
            });
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(io, response_service)
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn hello(_: Request<hyper::body::Incoming>, certificate_str: Arc<String>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("Hello, authenticated client!\nYour client certificate serial is: ".to_owned() + &certificate_str + "\n"))))
}

fn get_ssl_config() -> Result<ServerConfig, std::io::Error> {
    // Trusted CA for client certificates
    let mut roots = RootCertStore::empty();
    let ca_cert = load_cert(CLIENT_CA_CERT_PATH)?.first().unwrap().clone();
    roots.add(ca_cert).map_err(|_| {
        std::io::Error::new(ErrorKind::Other, "error adding CA certificate")
    })?;

    let client_verifier = WebPkiClientVerifier::builder(roots.into())
        .build()
        .unwrap();
    let private_key = load_pkey(SERVER_KEY_PATH)?.remove(0);
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(load_cert(SERVER_CERT_PATH).unwrap(), private_key)
        .unwrap();

    Ok(config)
}

/// Load the server certificate
fn load_cert(filename: &str) -> Result<Vec<CertificateDer>, std::io::Error> {
    let certfile = File::open(filename).map_err(|_| {
        std::io::Error::new(ErrorKind::Other, "error opening certificate file")
    })?;
    let mut reader = BufReader::new(certfile);
    let certs = rustls_pemfile::certs(&mut reader)
        .into_iter()
        .collect::<Result<Vec<CertificateDer>, _>>()?;
    Ok(certs)
}

/// Load the server private key
fn load_pkey(filename: &str) -> Result<Vec<PrivateKeyDer>, std::io::Error> {
    let keyfile = File::open(filename)?;
    let mut reader = BufReader::new(keyfile);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .into_iter()
        .map(|pk| {
            match pk {
                Ok(key) => Ok(PrivateKeyDer::from(key)),
                Err(e) => Err(e)
            }
        })
        .collect::<Result<Vec<PrivateKeyDer>, _>>()?;
    Ok(keys)
}