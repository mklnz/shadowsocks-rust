use log::{error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use bytes::{BufMut, BytesMut};
use etherparse::PacketBuilder;
use hickory_resolver::proto::op::Message;
use tokio::sync::mpsc;
use shadowsocks::config::Mode;
use shadowsocks::relay::Address;
use crate::local::context::ServiceContext;
use crate::local::dns::{NameServerAddr, server::DnsClient};
use crate::local::loadbalancing::PingBalancer;

pub struct TunDnsBuilder {
    context: Arc<ServiceContext>,
    mode: Mode,
    filter_addrs: Vec<SocketAddr>,
    local_addr: NameServerAddr,
    remote_addr: Address,
    balancer: PingBalancer,
    client_cache_size: usize,
}

impl TunDnsBuilder {
    pub fn new(
        context: Arc<ServiceContext>,
        filter_addrs: Vec<SocketAddr>,
        local_addr: NameServerAddr,
        remote_addr: Address,
        balancer: PingBalancer,
        client_cache_size: usize,
    ) -> Self {
        Self {
            context,
            mode: Mode::UdpOnly,
            filter_addrs,
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

        let (tun_tx, tun_rx) = mpsc::channel(64);

        let udp = Arc::new(TunDnsUdp{
            local_dns_addr: self.local_addr,
            remote_dns_addr: self.remote_addr,
            tun_tx,
            client
        });

        TunDns{ filter_addrs: self.filter_addrs, udp, tun_rx }
    }
}

pub struct TunDns {
    pub filter_addrs: Vec<SocketAddr>,
    udp: Arc<TunDnsUdp>,
    tun_rx: mpsc::Receiver<BytesMut>,
}

impl TunDns {
    // Determine whether to intercept and handle the dns packet
    // The packet dst should equal to the listen addr (which is the TUN device address)
    pub fn should_handle(&self, dst_addr: &SocketAddr) -> bool {
        self.filter_addrs.contains(dst_addr)
    }

    pub async fn handle_udp(
        &self, src_addr: &SocketAddr, dst_addr: &SocketAddr, payload: &[u8]
    ) {
        let dst_addr = dst_addr.to_owned();
        let src_addr = src_addr.to_owned();
        let payload = payload.to_owned();
        let udp = self.udp.clone();

        info!("spawning dns query task, src: {}, dst: {}", &src_addr, &dst_addr);
        tokio::spawn(async move {
            udp.handle(&src_addr, &dst_addr, &payload).await;
        });
    }

    pub async fn recv_packet(&mut self) -> BytesMut {
        match self.tun_rx.recv().await {
            Some(b) => b,
            None => unreachable!("channel closed unexpectedly"),
        }
    }
}

struct TunDnsUdp {
    local_dns_addr: NameServerAddr,
    remote_dns_addr: Address,
    tun_tx: mpsc::Sender<BytesMut>,
    client: Arc<DnsClient>,
}

impl TunDnsUdp {
    async fn handle(&self, src_addr: &SocketAddr, dst_addr: &SocketAddr, payload: &[u8]) {
        let message = match Message::from_vec(&payload) {
            Ok(m) => m,
            Err(err) => {
                error!("[TunDns] failed to parse DNS packet: {}", err);
                return;
            }
        };

        log::info!("[TunDns] performing dns query for {:?}", message.query());

        let answer = match self.client.resolve(
            message,
            &self.local_dns_addr,
            &self.remote_dns_addr,
        ).await {
            Ok(answer) => answer,
            Err(err) => {
                error!("[TunDns] failed to resolve query: {}", err);
                return;
            }
        };

        log::info!("[TunDns] dns query answer: {:?}", answer.answers());

        // Reply packet has src/dst reversed
        let packet = self.build_reply_packet(answer, &dst_addr, &src_addr);
        if let Some(packet) = packet {
            let _ = self.tun_tx.send(packet).await;
        }
    }

    fn build_reply_packet(&self, answer: Message, src_addr: &SocketAddr, dst_addr: &SocketAddr) -> Option<BytesMut> {
        let packet: Option<BytesMut> = match (src_addr, dst_addr) {
            (SocketAddr::V4(peer), SocketAddr::V4(remote)) => {
                let builder = PacketBuilder::ipv4(
                    peer.ip().octets(), remote.ip().octets(), 20,
                ).udp(peer.port(), remote.port());

                let data = match answer.to_vec() {
                    Ok(data) => data,
                    Err(err) => {
                        error!("[TunDns] failed to convert dns query to data: {}", err);
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
