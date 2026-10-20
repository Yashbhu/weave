//! tun device handling.
//!
//! opens the interface and reads/writes single ip packets. udp and forwarding
//! live in the other modules.
//!
//! needs root. on macos the device is a utun and the name is utunN, or leave it
//! out and let the kernel choose.

use std::future::Future;
use std::io;
use std::net::Ipv4Addr;

/// read side of a tun interface. one call returns one packet.
pub trait PacketReader: Send + 'static {
    /// read one packet into `buf`, returns its length.
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

/// write side of a tun interface. one call writes one packet.
pub trait PacketWriter: Send + 'static {
    /// write one packet.
    fn send<'a>(&'a mut self, packet: &'a [u8])
        -> impl Future<Output = io::Result<()>> + Send + 'a;
}

/// interface configuration.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// requested name; `None` lets the kernel choose.
    pub name: Option<String>,
    /// overlay address for this node.
    pub address: Ipv4Addr,
    /// peer's overlay address.
    pub destination: Ipv4Addr,
    /// netmask; a single host is `255.255.255.255`.
    pub netmask: Ipv4Addr,
    /// interface mtu.
    pub mtu: u16,
    /// let the platform library set up routes.
    pub enable_routing: bool,
}

/// an opened tun interface.
pub struct TunDevice {
    device: tun::AsyncDevice,
}

impl TunDevice {
    /// create and configure the interface. needs root.
    pub fn open(config: &TunConfig) -> io::Result<Self> {
        let mut tun_config = tun::Configuration::default();
        if let Some(name) = &config.name {
            tun_config.tun_name(name);
        }
        tun_config
            .address(config.address)
            .destination(config.destination)
            .netmask(config.netmask)
            .mtu(config.mtu)
            .up();
        tun_config.platform_config(|platform| {
            platform.enable_routing(config.enable_routing);
        });

        let device = tun::create_as_async(&tun_config).map_err(io::Error::other)?;
        Ok(Self { device })
    }

    /// split into a reader and a writer.
    pub fn split(self) -> io::Result<(TunReader, TunWriter)> {
        let (writer, reader) = self.device.split()?;
        Ok((TunReader { reader }, TunWriter { writer }))
    }
}

/// read side.
pub struct TunReader {
    reader: tun::DeviceReader,
}

/// write side.
pub struct TunWriter {
    writer: tun::DeviceWriter,
}

#[allow(clippy::manual_async_fn)] // explicit `Send` bound is needed for spawn
impl PacketReader for TunReader {
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        async move { tokio::io::AsyncReadExt::read(&mut self.reader, buf).await }
    }
}

#[allow(clippy::manual_async_fn)] // explicit `Send` bound is needed for spawn
impl PacketWriter for TunWriter {
    fn send<'a>(
        &'a mut self,
        packet: &'a [u8],
    ) -> impl Future<Output = io::Result<()>> + Send + 'a {
        async move { tokio::io::AsyncWriteExt::write_all(&mut self.writer, packet).await }
    }
}
