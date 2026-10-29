use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use murmur_compat::sing_buf::Buffer;
use murmur_sing::metadata::{socksaddr_from_net, Socksaddr};
use murmur_sing::network::{
    NetPacketReader, NetPacketWriter, NetworkPacketConn, PacketConn as SingPacketConn, PacketReadWaiter, PacketReader,
    PacketWriter, ReadWaitOptions, ReadWaitable,
};
use murmur_std_compat::net::{Addr, PacketConn as NetPacketConn, UdpAddr};

use super::protocol::{build_padding_ip, parse16_bytes_ip, skip_n, BodyCursor, HttpConn, APP_NAME};

fn take_array<const N: usize>(buffer: &mut Buffer) -> io::Result<[u8; N]> {
    buffer.read_bytes(N)?.try_into().map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "short udp header"))
}

pub(crate) struct PacketConnBase {
    pub(crate) inner: Arc<HttpConn>,
    read_wait_options: Mutex<ReadWaitOptions>,
}

impl PacketConnBase {
    fn new(inner: Arc<HttpConn>) -> Self {
        Self { inner, read_wait_options: Mutex::new(ReadWaitOptions::default()) }
    }

    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        *self.read_wait_options.lock() = options;
        false
    }
}

pub struct ClientPacketConn(pub(crate) PacketConnBase);

impl std::fmt::Debug for ClientPacketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientPacketConn").finish_non_exhaustive()
    }
}

impl ClientPacketConn {
    pub(crate) fn new(inner: Arc<HttpConn>) -> Self {
        Self(PacketConnBase::new(inner))
    }

    pub const fn front_headroom(&self) -> usize {
        4 + 16 + 2 + 16 + 2 + 1 + u8::MAX as usize
    }

    pub async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        self.0.inner.wait_created().await.map_err(io::Error::other)?;
        self.read_packet_from_server(buffer).await
    }

    pub async fn write_packet(&self, buffer: Buffer, destination: Socksaddr) -> io::Result<()> {
        self.write_packet_to_server(buffer, destination).await
    }

    async fn read_packet_from_server(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        let mut header = murmur_compat::sing_buf::new_size(4 + 16 + 2 + 16 + 2);
        let cap = header.cap();
        let result = async {
            header.read_full_from(&mut BodyCursor(&self.0.inner), cap).await?;
            let length = u32::from_be_bytes(take_array::<4>(&mut header)?);
            let source_address_buffer: [u8; 16] = take_array::<16>(&mut header)?;
            let source_addr = parse16_bytes_ip(source_address_buffer);
            let source_port = u16::from_be_bytes(take_array::<2>(&mut header)?);
            header.read_bytes(16 + 2)?;
            let payload_len = usize::try_from(i64::from(length) - (16 + 2 + 16 + 2))
                .map_err(|_| io::Error::other(format!("invalid udp length: {length}")))?;
            buffer.read_full_from(&mut BodyCursor(&self.0.inner), payload_len).await?;
            Ok(Socksaddr::from_ip(source_addr, source_port))
        }
        .await;
        header.release();
        result
    }

    async fn write_packet_to_server(&self, buffer: Buffer, source: Socksaddr) -> io::Result<()> {
        let mut buffer = buffer;
        if !source.is_ip() {
            buffer.release();
            return Err(io::Error::other("only support IP"));
        }
        let app_name = APP_NAME.get(..usize::from(u8::MAX)).unwrap_or(APP_NAME);
        let app_name_len = u8::try_from(app_name.len()).map_err(|_| io::Error::other("app name too long"))?;
        let payload_len = buffer.len();
        let header_len = 4 + 16 + 2 + 16 + 2 + 1 + usize::from(app_name_len);
        let length_field = u32::try_from(16 + 2 + 16 + 2 + 1 + usize::from(app_name_len) + payload_len)
            .map_err(|_| io::Error::other("udp packet too large"))?;
        let Some(source_addr) = source.addr else {
            buffer.release();
            return Err(io::Error::other("only support IP"));
        };
        let destination_address = build_padding_ip(source_addr);

        let mut header_bytes = Vec::with_capacity(header_len);
        header_bytes.extend_from_slice(&length_field.to_be_bytes());
        header_bytes.extend_from_slice(&[0u8; 18]);
        header_bytes.extend_from_slice(&destination_address);
        header_bytes.extend_from_slice(&source.port.to_be_bytes());
        header_bytes.push(app_name_len);
        header_bytes.extend_from_slice(app_name.as_bytes());

        let header_in_buffer = buffer.start() >= header_len;
        if header_in_buffer {
            buffer.extend_header(header_len).copy_from_slice(&header_bytes);
        } else if let Err(err) = self.0.inner.write_flush(&header_bytes).await {
            buffer.release();
            return Err(err);
        }
        let result = self.0.inner.write_flush(buffer.bytes()).await;
        buffer.release();
        result.map(|_| ())
    }
}

#[async_trait]
impl NetPacketConn for ClientPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut buffer = murmur_compat::sing_buf::with(buf.to_vec());
        let destination = self.read_packet(&mut buffer).await?;
        let n = buffer.len();
        let Some(destination_slice) = buf.get_mut(..n) else {
            buffer.release();
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet larger than the caller's buffer"));
        };
        destination_slice.copy_from_slice(buffer.bytes());
        buffer.release();
        Ok((
            n,
            Box::new(
                destination
                    .udp_addr()
                    .unwrap_or_else(|| UdpAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)),
            ),
        ))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.write_packet(murmur_compat::sing_buf::as_(buf.to_vec()), socksaddr_from_net(Some(addr))).await?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.inner.net_addr.local_addr_result()
    }

    fn close(&self) -> io::Result<()> {
        let inner = Arc::clone(&self.0.inner);
        tokio::spawn(async move {
            let _ = inner.close();
        });
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.inner.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.inner.set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.inner.set_deadline(deadline)
    }
}

impl ReadWaitable for ClientPacketConn {
    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        self.0.initialize_read_waiter(options)
    }
}

#[async_trait]
impl PacketReadWaiter for ClientPacketConn {
    async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)> {
        let mut buffer = self.0.read_wait_options.lock().new_packet_buffer();
        match self.read_packet(&mut buffer).await {
            Ok(destination) => {
                self.0.read_wait_options.lock().post_return(&mut buffer);
                Ok((buffer, destination))
            }
            Err(err) => {
                buffer.release();
                Err(err)
            }
        }
    }
}

#[async_trait]
impl PacketReader for ClientPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        Self::read_packet(self, buffer).await
    }
}

#[async_trait]
impl NetPacketReader for ClientPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        NetPacketConn::read_from(self, p).await
    }
}

#[async_trait]
impl PacketWriter for ClientPacketConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        Self::write_packet(self, buffer.to_owned_buffer(), destination.clone()).await
    }
}

#[async_trait]
impl NetPacketWriter for ClientPacketConn {
    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        NetPacketConn::write_to(self, p, addr).await
    }
}

#[async_trait]
impl SingPacketConn for ClientPacketConn {
    async fn close(&self) -> io::Result<()> {
        NetPacketConn::close(self)
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        NetPacketConn::local_addr(self)
    }
}

#[async_trait]
impl NetworkPacketConn for ClientPacketConn {
    async fn close(&self) -> io::Result<()> {
        NetPacketConn::close(self)
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        NetPacketConn::local_addr(self)
    }
}

pub struct ServerPacketConn(pub(crate) PacketConnBase);

impl std::fmt::Debug for ServerPacketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerPacketConn").finish_non_exhaustive()
    }
}

impl ServerPacketConn {
    pub(crate) fn new(inner: Arc<HttpConn>) -> Self {
        Self(PacketConnBase::new(inner))
    }

    pub const fn front_headroom(&self) -> usize {
        4 + 16 + 2 + 16 + 2
    }

    pub async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        self.0.inner.wait_created().await.map_err(io::Error::other)?;
        self.read_packet_from_client(buffer).await
    }

    pub async fn write_packet(&self, buffer: Buffer, destination: Socksaddr) -> io::Result<()> {
        self.write_packet_to_client(buffer, destination).await
    }

    async fn read_packet_from_client(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        let mut header = murmur_compat::sing_buf::new_size(4 + 16 + 2 + 16 + 2 + 1);
        let cap = header.cap();
        let result = async {
            header.read_full_from(&mut BodyCursor(&self.0.inner), cap).await?;
            let length = u32::from_be_bytes(take_array::<4>(&mut header)?);
            header.read_bytes(16 + 2)?;
            let destination_address_buffer: [u8; 16] = take_array::<16>(&mut header)?;
            let destination_addr = parse16_bytes_ip(destination_address_buffer);
            let destination_port = u16::from_be_bytes(take_array::<2>(&mut header)?);
            let app_name_len = header.read_byte()?;
            if app_name_len > 0 {
                skip_n(&self.0.inner, usize::from(app_name_len)).await?;
            }
            let payload_len = usize::try_from(i64::from(length) - (16 + 2 + 16 + 2 + 1 + i64::from(app_name_len)))
                .map_err(|_| io::Error::other(format!("invalid udp length: {length}")))?;
            buffer.read_full_from(&mut BodyCursor(&self.0.inner), payload_len).await?;
            Ok(Socksaddr::from_ip(destination_addr, destination_port))
        }
        .await;
        header.release();
        result
    }

    async fn write_packet_to_client(&self, buffer: Buffer, source: Socksaddr) -> io::Result<()> {
        let mut buffer = buffer;
        if !source.is_ip() {
            buffer.release();
            return Err(io::Error::other("only support IP"));
        }
        let payload_len = buffer.len();
        let header_len = 4 + 16 + 2 + 16 + 2;
        let length_field =
            u32::try_from(16 + 2 + 16 + 2 + payload_len).map_err(|_| io::Error::other("udp packet too large"))?;
        let Some(source_addr) = source.addr else {
            buffer.release();
            return Err(io::Error::other("only support IP"));
        };
        let source_address = build_padding_ip(source_addr);
        let destination_address = [0u8; 16];
        let destination_port: u16 = 0;

        let mut header_bytes = Vec::with_capacity(header_len);
        header_bytes.extend_from_slice(&length_field.to_be_bytes());
        header_bytes.extend_from_slice(&source_address);
        header_bytes.extend_from_slice(&source.port.to_be_bytes());
        header_bytes.extend_from_slice(&destination_address);
        header_bytes.extend_from_slice(&destination_port.to_be_bytes());

        let header_in_buffer = buffer.start() >= header_len;
        if header_in_buffer {
            buffer.extend_header(header_len).copy_from_slice(&header_bytes);
        } else if let Err(err) = self.0.inner.write_flush(&header_bytes).await {
            buffer.release();
            return Err(err);
        }
        let result = self.0.inner.write_flush(buffer.bytes()).await;
        buffer.release();
        result.map(|_| ())
    }
}

#[async_trait]
impl NetPacketConn for ServerPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut buffer = murmur_compat::sing_buf::with(buf.to_vec());
        let destination = self.read_packet(&mut buffer).await?;
        let n = buffer.len();
        let Some(destination_slice) = buf.get_mut(..n) else {
            buffer.release();
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet larger than the caller's buffer"));
        };
        destination_slice.copy_from_slice(buffer.bytes());
        buffer.release();
        Ok((
            n,
            Box::new(
                destination
                    .udp_addr()
                    .unwrap_or_else(|| UdpAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)),
            ),
        ))
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.write_packet(murmur_compat::sing_buf::as_(buf.to_vec()), socksaddr_from_net(Some(addr))).await?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.inner.net_addr.local_addr_result()
    }

    fn close(&self) -> io::Result<()> {
        let inner = Arc::clone(&self.0.inner);
        tokio::spawn(async move {
            let _ = inner.close();
        });
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.inner.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.inner.set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.inner.set_deadline(deadline)
    }
}

impl ReadWaitable for ServerPacketConn {
    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        self.0.initialize_read_waiter(options)
    }
}

#[async_trait]
impl PacketReadWaiter for ServerPacketConn {
    async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)> {
        let mut buffer = self.0.read_wait_options.lock().new_packet_buffer();
        match self.read_packet(&mut buffer).await {
            Ok(destination) => {
                self.0.read_wait_options.lock().post_return(&mut buffer);
                Ok((buffer, destination))
            }
            Err(err) => {
                buffer.release();
                Err(err)
            }
        }
    }
}

#[async_trait]
impl PacketReader for ServerPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        Self::read_packet(self, buffer).await
    }
}

#[async_trait]
impl NetPacketReader for ServerPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        NetPacketConn::read_from(self, p).await
    }
}

#[async_trait]
impl PacketWriter for ServerPacketConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        Self::write_packet(self, buffer.to_owned_buffer(), destination.clone()).await
    }
}

#[async_trait]
impl NetPacketWriter for ServerPacketConn {
    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        NetPacketConn::write_to(self, p, addr).await
    }
}

#[async_trait]
impl SingPacketConn for ServerPacketConn {
    async fn close(&self) -> io::Result<()> {
        NetPacketConn::close(self)
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        NetPacketConn::local_addr(self)
    }
}

#[async_trait]
impl NetworkPacketConn for ServerPacketConn {
    async fn close(&self) -> io::Result<()> {
        NetPacketConn::close(self)
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        NetPacketConn::local_addr(self)
    }
}
