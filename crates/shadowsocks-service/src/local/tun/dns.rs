use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use bytes::{BufMut, BytesMut};
use etherparse::PacketBuilder;
use hickory_resolver::proto::op::Message;
use shadowsocks::config::Mode;
use shadowsocks::relay::Address;
use crate::local::context::ServiceContext;
use crate::local::dns::{NameServerAddr, server::DnsClient};
use crate::local::loadbalancing::PingBalancer;

pub struct TunDnsBuilder {
    context: Arc<ServiceContext>,
    mode: Mode,
    listen_addr: SocketAddr,
    local_addr: NameServerAddr,
    remote_addr: Address,
    balancer: PingBalancer,
    client_cache_size: usize,
}

impl TunDnsBuilder {
    pub fn new(
        context: Arc<ServiceContext>,
        listen_addr: SocketAddr,
        local_addr: NameServerAddr,
        remote_addr: Address,
        balancer: PingBalancer,
        client_cache_size: usize,
    ) -> Self {
        Self {
            context,
            mode: Mode::UdpOnly,
            listen_addr,
            local_addr,
            remote_addr,
            balancer,
            client_cache_size,
        }
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    pub fn build(self) -> TunDns {
        let client = Arc::new(DnsClient::new(
            self.context.clone(),
            self.balancer,
            self.mode,
            self.client_cache_size,
        ));

        TunDns{
            listen_addr: self.listen_addr,
            local_dns_addr: self.local_addr,
            remote_dns_addr: self.remote_addr,
            client,
        }
    }
}

pub struct TunDns {
    pub listen_addr: SocketAddr,
    pub local_dns_addr: NameServerAddr,
    pub remote_dns_addr: Address,
    client: Arc<DnsClient>,
}

impl TunDns {
    // Determine whether to intercept and handle the dns packet
    // The packet dst should equal to the listen addr (which is the TUN device address)
    pub fn should_handle(&self, dst_addr: &SocketAddr) -> bool {
        self.listen_addr.eq(dst_addr)
    }

    pub async fn handle_udp(
        &self, src_addr: &SocketAddr, dst_addr: &SocketAddr, payload: &[u8]
    ) -> Option<BytesMut> {
        // Check whether if the packet should be handled by TunDns
        if !self.should_handle(dst_addr) {
            return None;
        }

        let message = Message::from_vec(payload)
            .map_err(|err| {
                log::error!("failed to parse DNS packet: {}", err);
            })
            .ok()?;

        let answer = match self.resolve(message).await {
            Ok(answer) => answer,
            Err(err) => {
                log::error!("failed to resolve query: {}", err);
                return None;
            }
        };

        // Build reply packet
        let packet = self.udp_reply_packet(answer, src_addr);
        packet
    }

    async fn resolve(&self, message: Message) -> io::Result<Message>{
        self.client.resolve(
            message,
            &self.local_dns_addr,
            &self.remote_dns_addr,
        ).await
    }

    fn udp_reply_packet(&self, answer: Message, dst_addr: &SocketAddr) -> Option<BytesMut> {
        // src_addr = listening device, dst_addr = query src_addr)
        let src_addr = &self.listen_addr;

        let packet: Option<BytesMut> = match (src_addr, dst_addr) {
            (SocketAddr::V4(peer), SocketAddr::V4(remote)) => {
                let builder = PacketBuilder::ipv4(
                    peer.ip().octets(), remote.ip().octets(), 20,
                ).udp(peer.port(), remote.port());

                let data = match answer.to_vec() {
                    Ok(data) => data,
                    Err(err) => {
                        log::error!("failed to serialize dns query to data: {}", err);
                        return None;
                    }
                };

                let packet = BytesMut::with_capacity(builder.size(data.len()));
                let mut packet_writer = packet.writer();
                builder.write(&mut packet_writer, &data).expect("PacketBuilder::write");

                Some(packet_writer.into_inner())
            }
            _ => None,
        };

        packet
    }
}

