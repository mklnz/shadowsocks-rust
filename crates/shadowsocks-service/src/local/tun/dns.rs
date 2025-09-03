use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use bytes::{BufMut, BytesMut};
use etherparse::PacketBuilder;
use futures::future;
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
    listen_addrs: Vec<SocketAddr>,
    local_addr: NameServerAddr,
    remote_addr: Address,
    balancer: PingBalancer,
    client_cache_size: usize,
}

impl TunDnsBuilder {
    pub fn new(
        context: Arc<ServiceContext>,
        listen_addrs: Vec<SocketAddr>,
        local_addr: NameServerAddr,
        remote_addr: Address,
        balancer: PingBalancer,
        client_cache_size: usize,
    ) -> Self {
        Self {
            context,
            mode: Mode::UdpOnly,
            listen_addrs,
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

        if self.listen_addrs.len() > 0 {
            let (tun_tx, tun_rx) = mpsc::channel(64);

            let udp = Arc::new(TunDnsUdp{
                local_dns_addr: self.local_addr,
                remote_dns_addr: self.remote_addr,
                tun_tx,
                client
            });

            TunDns{
                listen_addrs: self.listen_addrs,
                udp: Some(udp),
                tun_rx: Some(tun_rx),
            }
        } else {
            // If no listen_addrs, then return blank TunDns which does nothing
            TunDns::new()
        }
    }
}

pub struct TunDns {
    pub listen_addrs: Vec<SocketAddr>,
    pub udp: Option<Arc<TunDnsUdp>>,
    pub tun_rx: Option<mpsc::Receiver<BytesMut>>,
}

impl TunDns {
    pub fn new() -> Self {
        TunDns{
            listen_addrs: vec![],
            udp: None,
            tun_rx: None,
        }
    }

    // If no listening addrs, then TunDns is not enabled
    pub fn is_enabled(&self) -> bool {
        self.listen_addrs.len() > 0
    }

    // Determine whether to intercept and handle the dns packet
    // The packet dst should equal to the listen addr (which is the TUN device address)
    pub fn should_handle(&self, dst_addr: &SocketAddr) -> bool {
        self.listen_addrs.contains(dst_addr)
    }

    pub async fn handle_udp(
        &self, src_addr: &SocketAddr, dst_addr: &SocketAddr, payload: &[u8]
    ) {
        let dst_addr = dst_addr.to_owned();
        let src_addr = src_addr.to_owned();
        let payload = payload.to_owned();
        let udp = self.udp.clone();

        log::trace!("spawning dns query task, src: {}, dst: {}", &src_addr, &dst_addr);
        tokio::spawn(async move {
            if let Some(udp) = udp {
                udp.handle(&src_addr, &dst_addr, &payload).await;
            }
        });
    }

    // Wait for dns answer packets, if no tun_rx (tun dns is not enabled),
    // then return future pending which never resolves
    pub fn recv_packet(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Option<BytesMut>> + Send + '_>> {
        if let Some(tun_rx) = self.tun_rx.as_mut() {
            Box::pin(tun_rx.recv())
        } else {
            Box::pin(future::pending::<Option<BytesMut>>())
        }
    }
}

pub struct TunDnsUdp {
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
                log::error!("[TunDns] failed to parse DNS packet: {}", err);
                return;
            }
        };

        log::trace!("[TunDns] performing dns query for {:?}", message.query());

        let answer = match self.client.resolve(
            message,
            &self.local_dns_addr,
            &self.remote_dns_addr,
        ).await {
            Ok(answer) => answer,
            Err(err) => {
                log::error!("[TunDns] failed to resolve query: {}", err);
                return;
            }
        };

        log::trace!("[TunDns] dns query answer: {:?}", answer.answers());

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
                        log::error!("[TunDns] failed to convert dns query to data: {}", err);
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
