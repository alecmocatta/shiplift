//! Main entrypoint for interacting with the Docker API.
//!
//! API Reference: <https://docs.docker.com/engine/api/v1.41/>

use std::{collections::HashMap, env, io, path::Path};

use futures_util::{stream::Stream, TryStreamExt};
use hyper::{client::HttpConnector, Body, Client, Method};
use mime::Mime;
use serde::{de, Deserialize, Serialize};
use url::form_urlencoded;

use crate::{
    container::Containers,
    errors::{Error, Result},
    image::Images,
    network::Networks,
    service::Services,
    transport::{Headers, Payload, Transport},
    volume::Volumes,
    Uri,
};

#[cfg(feature = "chrono")]
use crate::datetime::{datetime_from_nano_timestamp, datetime_from_unix_timestamp};
#[cfg(feature = "chrono")]
use chrono::{DateTime, Utc};

use hyper_rustls::HttpsConnector;
use tokio_rustls::rustls::{
    internal::pemfile,
    sign::{CertifiedKey, RSASigningKey},
    Certificate, ClientConfig, PrivateKey, ResolvesClientCert, SignatureScheme,
};
use std::sync::Arc;
use std::path::PathBuf;
use std::fs;

use log::warn;

#[cfg(feature = "unix-socket")]
use hyperlocal::UnixConnector;

/// Entrypoint interface for communicating with docker daemon
#[derive(Clone)]
pub struct Docker {
    transport: Transport,
}

fn get_docker_for_tcp(tcp_host_str: String) -> std::result::Result<Docker, Box<dyn std::error::Error + Send + Sync>> {
    if !tcp_host_str.starts_with("http://") {
        // Set up HTTP.
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        // Set up SSL parameters.
        let mut config = ClientConfig::new();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.ct_logs = Some(&ct_logs::LOGS);

        // Look up any certs managed by the operating system.
        config.root_store = match rustls_native_certs::load_native_certs() {
            Ok(store) => store,
            Err((Some(store), err)) => {
                warn!("could not load all certificates: {}", err);
                store
            }
            Err((None, err)) => {
                warn!("cannot access native certificate store: {}", err);
                config.root_store
            }
        };

        // Add any webpki certs, too, in case the OS is useless.
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        // Install our Docker CA if we have one.
        if should_enable_tls() {
            let ca_path = docker_ca_pem_path()?;
            let mut rdr = open_buffered(&ca_path)?;
            config
                .root_store
                .add_pem_file(&mut rdr)
                .map_err(|_| format!("error reading {}", ca_path.display()))?;
        }

        // Install a client certificate resolver to find our client cert (if we need one).
        config.client_auth_cert_resolver = Arc::new(DockerClientCertResolver);

        // If we are attempting to connec to the docker daemon via tcp
        // we need to convert the scheme to `https` to let hyper connect.
        // Otherwise, hyper will reject the connection since it does not
        // recongnize `tcp` as a valid `http` scheme.
        let tcp_host_str = if tcp_host_str.starts_with("tcp://") {
            tcp_host_str.replace("tcp://", "https://")
        } else {
            tcp_host_str
        };

        Ok(Docker {
            transport: Transport::EncryptedTcp {
                client: Client::builder()
                    .build(HttpsConnector::from((http, config))),
                host: tcp_host_str,
            },
        })
    } else {
        let mut http = HttpConnector::new();
        http.enforce_http(false);

        Ok(Docker {
            transport: Transport::Tcp {
                client: Client::builder().build(http),
                host: tcp_host_str,
            },
        })
    }
}

/// A client certificate resolver that looks up Docker client certs the same way
/// the official CLI tools do.
struct DockerClientCertResolver;

impl ResolvesClientCert for DockerClientCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<CertifiedKey> {
        if self.has_certs() {
            match docker_client_key() {
                Ok(key) => Some(key),
                Err(err) => {
                    warn!("error reading Docker client keys: {}", err);
                    None
                }
            }
        } else {
            None
        }
    }

    fn has_certs(&self) -> bool {
        should_enable_tls()
    }
}

fn should_enable_tls() -> bool {
    env::var("DOCKER_TLS_VERIFY").is_ok()
}

/// The default directory in which to look for our Docker certificate files.
fn default_cert_path() -> std::result::Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let from_env = env::var("DOCKER_CERT_PATH").or_else(|_| env::var("DOCKER_CONFIG"));
    if let Ok(ref path) = from_env {
        Ok(Path::new(path).to_owned())
    } else {
        let home = dirs::home_dir().ok_or_else(|| "no cert path")?;
        Ok(home.join(".docker"))
    }
}

/// Path to `ca.pem`.
fn docker_ca_pem_path() -> std::result::Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let dir = default_cert_path()?;
    Ok(dir.join("ca.pem"))
}

/// Our Docker client credentials, if we have them.
fn docker_client_key() -> std::result::Result<CertifiedKey, Box<dyn std::error::Error + Send + Sync>> {
    let dir = default_cert_path()?;

    // Look up our certificates.
    let mut all_certs = certs(&dir.join("cert.pem"))?;
    all_certs.extend(certs(&dir.join("ca.pem"))?.into_iter());

    // Look up our keys.
    let key_path = dir.join("key.pem");
    let mut all_keys = keys(&key_path)?;
    let key = if all_keys.len() == 1 {
        all_keys.remove(0)
    } else {
        return Err(format!(
            "expected 1 private key in {}, found {}",
            key_path.display(),
            all_keys.len()
        )
        .into());
    };
    let signing_key = RSASigningKey::new(&key)
        .map_err(|_| format!("could not parse signing key from {}", key_path.display()))?;

    Ok(CertifiedKey::new(
        all_certs,
        Arc::new(Box::new(signing_key)),
    ))
}

/// Fetch any certificates stored at `path`.
fn certs(path: &Path) -> std::result::Result<Vec<Certificate>, Box<dyn std::error::Error + Send + Sync>> {
    let mut rdr = open_buffered(path)?;
    Ok(pemfile::certs(&mut rdr).map_err(|_| format!("cannot read {}", path.display()))?)
}

/// Fetch any keys stored at `path`.
fn keys(path: &Path) -> std::result::Result<Vec<PrivateKey>, Box<dyn std::error::Error + Send + Sync>> {
    // Look for pcks8 keys.
    let mut rdr = open_buffered(path)?;
    let mut keys = pemfile::pkcs8_private_keys(&mut rdr)
        .map_err(|_| format!("cannot read {}", path.display()))?;

    // Re-open and look for RSA keys.
    rdr = open_buffered(path)?;
    keys.extend(
        pemfile::rsa_private_keys(&mut rdr)
            .map_err(|_| format!("cannot read {}", path.display()))?,
    );
    Ok(keys)
}

/// Open a path and return a buffered reader.
fn open_buffered(path: &Path) -> std::result::Result<io::BufReader<fs::File>, Box<dyn std::error::Error + Send + Sync>> {
    let f = fs::File::open(path).map_err(|_| format!("cannot open {}", path.display()))?;
    Ok(io::BufReader::new(f))
}

// https://docs.docker.com/reference/api/docker_remote_api_v1.17/
impl Docker {
    /// constructs a new Docker instance for a docker host listening at a url specified by an env var `DOCKER_HOST`,
    /// falling back on unix:///var/run/docker.sock
    pub fn new() -> Docker {
        match env::var("DOCKER_HOST").ok() {
            Some(host) => {
                #[cfg(feature = "unix-socket")]
                if let Some(path) = host.strip_prefix("unix://") {
                    return Docker::unix(path);
                }
                let host = host.parse().expect("invalid url");
                Docker::host(host)
            }
            #[cfg(feature = "unix-socket")]
            None => Docker::unix("/var/run/docker.sock"),
            #[cfg(not(feature = "unix-socket"))]
            None => panic!("Unix socket support is disabled"),
        }
    }

    /// Creates a new docker instance for a docker host
    /// listening on a given Unix socket.
    #[cfg(feature = "unix-socket")]
    pub fn unix<S>(socket_path: S) -> Docker
    where
        S: Into<String>,
    {
        Docker {
            transport: Transport::Unix {
                client: Client::builder()
                    .pool_max_idle_per_host(0)
                    .build(UnixConnector),
                path: socket_path.into(),
            },
        }
    }

    /// constructs a new Docker instance for docker host listening at the given host url
    pub fn host(host: Uri) -> Docker {
        let tcp_host_str = format!(
            "{}://{}:{}",
            host.scheme_str().unwrap(),
            host.host().unwrap().to_owned(),
            host.port_u16().unwrap_or(80)
        );

        match host.scheme_str() {
            #[cfg(feature = "unix-socket")]
            Some("unix") => Docker {
                transport: Transport::Unix {
                    client: Client::builder().build(UnixConnector),
                    path: host.path().to_owned(),
                },
            },

            #[cfg(not(feature = "unix-socket"))]
            Some("unix") => panic!("Unix socket support is disabled"),

            _ => get_docker_for_tcp(tcp_host_str).unwrap(),
        }
    }

    /// Exports an interface for interacting with docker images
    pub fn images(&'_ self) -> Images<'_> {
        Images::new(self)
    }

    /// Exports an interface for interacting with docker containers
    pub fn containers(&'_ self) -> Containers<'_> {
        Containers::new(self)
    }

    /// Exports an interface for interacting with docker services
    pub fn services(&'_ self) -> Services<'_> {
        Services::new(self)
    }

    pub fn networks(&'_ self) -> Networks<'_> {
        Networks::new(self)
    }

    pub fn volumes(&'_ self) -> Volumes<'_> {
        Volumes::new(self)
    }

    /// Returns version information associated with the docker daemon
    pub async fn version(&self) -> Result<Version> {
        self.get_json("/version").await
    }

    /// Returns information associated with the docker daemon
    pub async fn info(&self) -> Result<Info> {
        self.get_json("/info").await
    }

    /// Returns a simple ping response indicating the docker daemon is accessible
    pub async fn ping(&self) -> Result<String> {
        self.get("/_ping").await
    }

    /// Returns a stream of docker events
    pub fn events<'docker>(
        &'docker self,
        opts: &EventsOptions,
    ) -> impl Stream<Item = Result<Event>> + Unpin + 'docker {
        let mut path = vec!["/events".to_owned()];
        if let Some(query) = opts.serialize() {
            path.push(query);
        }
        let reader = Box::pin(
            self.stream_get(path.join("?"))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
        )
        .into_async_read();

        let codec = futures_codec::LinesCodec {};

        Box::pin(
            futures_codec::FramedRead::new(reader, codec)
                .map_err(Error::IO)
                .and_then(|s: String| async move {
                    serde_json::from_str(&s).map_err(Error::SerdeJsonError)
                }),
        )
    }

    //
    // Utility functions to make requests
    //

    pub(crate) async fn get(
        &self,
        endpoint: &str,
    ) -> Result<String> {
        self.transport
            .request(Method::GET, endpoint, Payload::None, Headers::None)
            .await
    }

    pub(crate) async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
    ) -> Result<T> {
        let raw_string = self
            .transport
            .request(Method::GET, endpoint, Payload::None, Headers::None)
            .await?;

        Ok(serde_json::from_str::<T>(&raw_string)?)
    }

    pub(crate) async fn post(
        &self,
        endpoint: &str,
        body: Option<(Body, Mime)>,
    ) -> Result<String> {
        self.transport
            .request(Method::POST, endpoint, body, Headers::None)
            .await
    }

    pub(crate) async fn put(
        &self,
        endpoint: &str,
        body: Option<(Body, Mime)>,
    ) -> Result<String> {
        self.transport
            .request(Method::PUT, endpoint, body, Headers::None)
            .await
    }

    pub(crate) async fn post_json<T, B>(
        &self,
        endpoint: impl AsRef<str>,
        body: Option<(B, Mime)>,
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: Into<Body>,
    {
        let string = self
            .transport
            .request(Method::POST, endpoint, body, Headers::None)
            .await?;

        Ok(serde_json::from_str::<T>(&string)?)
    }

    pub(crate) async fn post_json_headers<'a, T, B, H>(
        &self,
        endpoint: impl AsRef<str>,
        body: Option<(B, Mime)>,
        headers: Option<H>,
    ) -> Result<T>
    where
        T: serde::de::DeserializeOwned,
        B: Into<Body>,
        H: IntoIterator<Item = (&'static str, String)> + 'a,
    {
        let string = self
            .transport
            .request(Method::POST, endpoint, body, headers)
            .await?;

        Ok(serde_json::from_str::<T>(&string)?)
    }

    pub(crate) async fn delete(
        &self,
        endpoint: &str,
    ) -> Result<String> {
        self.transport
            .request(Method::DELETE, endpoint, Payload::None, Headers::None)
            .await
    }

    pub(crate) async fn delete_json<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
    ) -> Result<T> {
        let string = self
            .transport
            .request(Method::DELETE, endpoint, Payload::None, Headers::None)
            .await?;

        Ok(serde_json::from_str::<T>(&string)?)
    }

    /// Send a streaming post request.
    ///
    /// Use stream_post_into_values if the endpoint returns JSON values
    pub(crate) fn stream_post<'a, H>(
        &'a self,
        endpoint: impl AsRef<str> + 'a,
        body: Option<(Body, Mime)>,
        headers: Option<H>,
    ) -> impl Stream<Item = Result<hyper::body::Bytes>> + 'a
    where
        H: IntoIterator<Item = (&'static str, String)> + 'a,
    {
        self.transport
            .stream_chunks(Method::POST, endpoint, body, headers)
    }

    /// Send a streaming post request that returns a stream of JSON values
    ///
    /// Assumes that each received chunk contains one or more JSON values
    pub(crate) fn stream_post_into<'a, H, T>(
        &'a self,
        endpoint: impl AsRef<str> + 'a,
        body: Option<(Body, Mime)>,
        headers: Option<H>,
    ) -> impl Stream<Item = Result<T>> + 'a
    where
        H: IntoIterator<Item = (&'static str, String)> + 'a,
        T: de::DeserializeOwned,
    {
        self.stream_post(endpoint, body, headers)
            .and_then(|chunk| async move {
                let stream = futures_util::stream::iter(
                    serde_json::Deserializer::from_slice(&chunk)
                        .into_iter()
                        .collect::<Vec<_>>(),
                )
                .map_err(Error::from);

                Ok(stream)
            })
            .try_flatten()
    }

    pub(crate) fn stream_get<'a>(
        &'a self,
        endpoint: impl AsRef<str> + Unpin + 'a,
    ) -> impl Stream<Item = Result<hyper::body::Bytes>> + 'a {
        let headers = Some(Vec::default());
        self.transport
            .stream_chunks(Method::GET, endpoint, Option::<(Body, Mime)>::None, headers)
    }

    pub(crate) async fn stream_post_upgrade<'a>(
        &'a self,
        endpoint: impl AsRef<str> + 'a,
        body: Option<(Body, Mime)>,
    ) -> Result<impl futures_util::io::AsyncRead + futures_util::io::AsyncWrite + 'a> {
        self.transport
            .stream_upgrade(Method::POST, endpoint, body)
            .await
    }
}

impl Default for Docker {
    fn default() -> Self {
        Self::new()
    }
}

/// Options for filtering streams of Docker events
#[derive(Default, Debug)]
pub struct EventsOptions {
    params: HashMap<&'static str, String>,
}

impl EventsOptions {
    pub fn builder() -> EventsOptionsBuilder {
        EventsOptionsBuilder::default()
    }

    /// serialize options as a string. returns None if no options are defined
    pub fn serialize(&self) -> Option<String> {
        if self.params.is_empty() {
            None
        } else {
            Some(
                form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(&self.params)
                    .finish(),
            )
        }
    }
}

#[derive(Copy, Clone)]
pub enum EventFilterType {
    Container,
    Image,
    Volume,
    Network,
    Daemon,
}

fn event_filter_type_to_string(filter: EventFilterType) -> &'static str {
    match filter {
        EventFilterType::Container => "container",
        EventFilterType::Image => "image",
        EventFilterType::Volume => "volume",
        EventFilterType::Network => "network",
        EventFilterType::Daemon => "daemon",
    }
}

/// Filter options for image listings
pub enum EventFilter {
    Container(String),
    Event(String),
    Image(String),
    Label(String),
    Type(EventFilterType),
    Volume(String),
    Network(String),
    Daemon(String),
}

/// Builder interface for `EventOptions`
#[derive(Default)]
pub struct EventsOptionsBuilder {
    params: HashMap<&'static str, String>,
    events: Vec<String>,
    containers: Vec<String>,
    images: Vec<String>,
    labels: Vec<String>,
    volumes: Vec<String>,
    networks: Vec<String>,
    daemons: Vec<String>,
    types: Vec<String>,
}

impl EventsOptionsBuilder {
    /// Filter events since a given timestamp
    pub fn since(
        &mut self,
        ts: &u64,
    ) -> &mut Self {
        self.params.insert("since", ts.to_string());
        self
    }

    /// Filter events until a given timestamp
    pub fn until(
        &mut self,
        ts: &u64,
    ) -> &mut Self {
        self.params.insert("until", ts.to_string());
        self
    }

    pub fn filter(
        &mut self,
        filters: Vec<EventFilter>,
    ) -> &mut Self {
        let mut params = HashMap::new();
        for f in filters {
            match f {
                EventFilter::Container(n) => {
                    self.containers.push(n);
                    params.insert("container", self.containers.clone())
                }
                EventFilter::Event(n) => {
                    self.events.push(n);
                    params.insert("event", self.events.clone())
                }
                EventFilter::Image(n) => {
                    self.images.push(n);
                    params.insert("image", self.images.clone())
                }
                EventFilter::Label(n) => {
                    self.labels.push(n);
                    params.insert("label", self.labels.clone())
                }
                EventFilter::Volume(n) => {
                    self.volumes.push(n);
                    params.insert("volume", self.volumes.clone())
                }
                EventFilter::Network(n) => {
                    self.networks.push(n);
                    params.insert("network", self.networks.clone())
                }
                EventFilter::Daemon(n) => {
                    self.daemons.push(n);
                    params.insert("daemon", self.daemons.clone())
                }
                EventFilter::Type(n) => {
                    let event_type = event_filter_type_to_string(n).to_string();
                    self.types.push(event_type);
                    params.insert("type", self.types.clone())
                }
            };
        }
        self.params
            .insert("filters", serde_json::to_string(&params).unwrap());
        self
    }

    pub fn build(&self) -> EventsOptions {
        EventsOptions {
            params: self.params.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Version {
    pub version: String,
    pub api_version: String,
    pub git_commit: String,
    pub go_version: String,
    pub os: String,
    pub arch: String,
    pub kernel_version: String,
    #[cfg(feature = "chrono")]
    pub build_time: DateTime<Utc>,
    #[cfg(not(feature = "chrono"))]
    pub build_time: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Info {
    pub containers: u64,
    pub images: u64,
    pub driver: String,
    pub docker_root_dir: String,
    pub driver_status: Vec<Vec<String>>,
    #[serde(rename = "ID")]
    pub id: String,
    pub kernel_version: String,
    // pub Labels: Option<???>,
    pub mem_total: u64,
    pub memory_limit: bool,
    #[serde(rename = "NCPU")]
    pub n_cpu: u64,
    pub n_events_listener: u64,
    pub n_goroutines: u64,
    pub name: String,
    pub operating_system: String,
    // pub RegistryConfig:???
    pub swap_limit: bool,
    pub system_time: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    #[serde(rename = "Type")]
    pub typ: String,
    #[serde(rename = "Action")]
    pub action: String,
    #[serde(rename = "Actor")]
    pub actor: Actor,
    pub status: Option<String>,
    pub id: Option<String>,
    pub from: Option<String>,
    #[cfg(feature = "chrono")]
    #[serde(deserialize_with = "datetime_from_unix_timestamp")]
    pub time: DateTime<Utc>,
    #[cfg(not(feature = "chrono"))]
    pub time: u64,
    #[cfg(feature = "chrono")]
    #[serde(deserialize_with = "datetime_from_nano_timestamp", rename = "timeNano")]
    pub time_nano: DateTime<Utc>,
    #[cfg(not(feature = "chrono"))]
    #[serde(rename = "timeNano")]
    pub time_nano: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Actor {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Attributes")]
    pub attributes: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "unix-socket")]
    #[test]
    fn unix_host_env() {
        use super::Docker;
        use std::env;
        env::set_var("DOCKER_HOST", "unix:///docker.sock");
        let d = Docker::new();
        match d.transport {
            crate::transport::Transport::Unix { path, .. } => {
                assert_eq!(path, "/docker.sock");
            }
            _ => {
                panic!("Expected transport to be unix.");
            }
        }
        env::set_var("DOCKER_HOST", "http://localhost:8000");
        let d = Docker::new();
        match d.transport {
            crate::transport::Transport::Tcp { host, .. } => {
                assert_eq!(host, "http://localhost:8000");
            }
            _ => {
                panic!("Expected transport to be http.");
            }
        }
    }
}
