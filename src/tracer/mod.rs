use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use rand::{thread_rng, Rng};

use crate::{
    general::{IPProtocol, Layer, TcpFlag},
    preset::Preset,
    session::Session,
    util::{self},
};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum TracerDirection {
    Forward,
    Backward,
}

#[derive(Default, Clone, Debug)]
pub struct Tracer {
    inner: Session,
    pub payloads: Vec<Vec<u8>>,

    connected: bool,
    sequence_enabled: bool,
    record: bool,
    fragmented: bool,
    padding: (bool, usize),
    fcs: bool,

    os: HashMap<u8, Preset>,

    proto: IPProtocol,

    l4_owner_sequence_nonce: u32, // a.k.a., it equals a client sequence for TCP
    l4_peer_sequence_nonce: u32,  // a.k.a., it equals a server sequence for TCP

    ts_val: u32,
    ts_echo: u32,

    ts_started: u128,
}

pub trait PacketSend {
    fn sendp(&mut self, app_data: &[u8]) -> Vec<Vec<u8>>;
}

impl PacketSend for Tracer {
    fn sendp(&mut self, app_data: &[u8]) -> Vec<Vec<u8>> {
        self.send(app_data, false)
    }
}

impl Tracer {
    #[inline]
    pub fn uptime() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    fn new_with_default() -> Self {
        let sess = Session::create_ether(0x0800);
        Self {
            inner: sess,
            payloads: Vec::new(),
            sequence_enabled: true,
            connected: false,
            fragmented: true,
            proto: IPProtocol::NONE,
            padding: (true, 60),
            fcs: false,
            record: false,
            ts_val: 0,
            ts_echo: 0,
            ts_started: Self::uptime(),
            ..Default::default()
        }
    }

    pub fn protocol(&mut self) -> IPProtocol {
        self.proto
    }

    pub fn new_with_session(sess: Session) -> Self {
        let proto = sess.protocol;
        let mut tracer = Self::new_with_default();
        tracer.inner = sess;
        tracer.proto = proto;
        tracer
    }

    pub fn new_with_l2(etype: u16) -> Self {
        let sess = Session::create_ether(etype);
        let mut tracer = Self::new_with_default();
        tracer.inner = sess;
        tracer
    }

    pub fn new_with_l4(proto: IPProtocol, owner_port: u16, peer_port: u16) -> Self {
        let inner = match proto {
            IPProtocol::ICMP => Session::create_icmp(),
            IPProtocol::TCP => Session::create_tcp(owner_port, peer_port),
            IPProtocol::UDP => Session::create_udp(owner_port, peer_port),
            _ => {
                panic!("Unsupport IPProtocol")
            }
        };
        Self {
            inner,
            payloads: Vec::new(),
            sequence_enabled: true,
            connected: false,
            fragmented: true,
            proto,
            padding: (true, 60),
            fcs: false,
            record: false,
            ..Default::default()
        }
    }

    pub fn direction(&self) -> TracerDirection {
        if self.inner.is_reverse() {
            TracerDirection::Backward
        } else {
            TracerDirection::Forward
        }
    }

    pub fn regi_os(&mut self, flags: u8, value: &Preset) {
        self.os.insert(flags, value.clone());
    }

    pub fn unregi_os(&mut self, flags: u8) -> Option<Preset> {
        self.os.remove(&flags)
    }

    pub fn into_session(&mut self, sess: Session) {
        self.inner = sess;
        self.proto = self.inner.protocol;
    }

    pub fn set_mode_fix_l4_tcp_sequence(&mut self, enable: bool) {
        self.sequence_enabled = enable;
    }

    ///
    /// Switches the ability to insert padding data into the suffix
    /// if it falls short of the minimum length of the Ethernet layer.
    ///
    /// The minimum required length is typically known to be 60 bytes.
    ///
    pub fn set_mode_padding(&mut self, enable: bool) {
        self.padding.0 = enable;
    }

    ///
    /// Switches on the ability to append 4 bytes of FCS (Frame Check Sequence)
    /// to the end of packets.
    ///
    /// FCS is usually removed from the NIC, and the actual payload is
    /// passed to the OS level. Switching on this feature should be done
    /// with caution.
    ///
    pub fn set_mode_fcs(&mut self, enable: bool) {
        self.fcs = enable;
    }

    pub fn set_mode_fragment(&mut self, enable: bool) {
        self.fragmented = enable;
    }

    ///
    /// Determines the minimum length of the Ethernet layer.
    ///
    /// The value is usually known to be 60 bytes. Changing this value
    /// should be done with caution, as it may not work properly with
    /// other network devices.
    ///
    pub fn set_mode_padding_min(&mut self, pktlen: usize) {
        self.padding.1 = pktlen;
    }

    pub fn set_mode_ipv4_checksum(&mut self, enable: bool) {
        self.inner.set_mode_ipv4_checksum(enable);
    }

    ///
    ///
    ///
    ///
    ///
    pub fn to_pcap(&self, filename: &str) -> std::io::Result<()> {
        util::write_pcap(self.payloads.to_vec(), filename)
    }

    pub fn set_mode_tcp_checksum(&mut self, enable: bool) {
        self.inner.set_mode_transport_checksum(enable);
    }

    pub fn set_mode_udp_checksum(&mut self, enable: bool) {
        self.inner.set_mode_transport_checksum(enable);
    }

    pub fn set_mode_record_packet(&mut self, enable: bool) {
        self.record = enable;
    }

    pub fn as_session(&mut self) -> &mut Session {
        &mut self.inner
    }

    pub fn as_session_ref(&self) -> &Session {
        &self.inner
    }

    pub fn initialize_seq_ack(&mut self) {
        let mut thread_rng = rand::thread_rng();
        self.l4_owner_sequence_nonce = thread_rng.gen_range(1..=std::u32::MAX);
        self.l4_peer_sequence_nonce = thread_rng.gen_range(1..=std::u32::MAX);
    }

    ///
    /// Switch the current owner and peer, and reassemble the packet again.
    ///
    pub fn switch_direction(&mut self, rebuild: bool) {
        std::mem::swap(&mut self.ts_val, &mut self.ts_echo);
        self.inner.reverse_session(rebuild); // Swapping direction
    }

    pub fn update_timestamp(&mut self) {
        self.ts_val = ((Self::uptime() - self.ts_started)) as u32;
    }

    pub fn initialize_timestamp(&mut self) {
        self.ts_val = 0;
        self.ts_echo = 0;
    }

    fn reset_tcp_info(&mut self) {
        self.connected = false;
        match self.direction() {
            // prevent re-used port
            TracerDirection::Forward => self.inner.l4_sport += 1,
            TracerDirection::Backward => {
                let mut port = self.inner.l4_dport as u32 + 1;
                if port > 65535 {
                    port = 1025;
                }
                self.inner.l4_dport = port as u16;
                self.switch_direction(true); // reset direction because need to handshake owner -> peer.
            }
        }
    }

    ///
    /// Transmits the 3-way handshake supported by the TCP protocol.
    /// Other protocols do not perform any function.
    ///
    pub fn sendp_handshake(&mut self) -> Vec<Vec<u8>> {
        if self.proto == IPProtocol::TCP {
            if self.connected {
                // NEED TO RESET?
                self.switch_direction(false);
                self.sendp_tcp_finish();

                self.switch_direction(false);
                self.sendp_tcp_finish();

                self.reset_tcp_info();
            }

            self.initialize_seq_ack();

            // force set sequence and acknowledge number
            self.set_mode_fix_l4_tcp_sequence(false);
            self.inner.l4_tcp_sequence = self.l4_owner_sequence_nonce;
            self.inner.l4_tcp_acknowledgment = 0; // init value is zero

            self.initialize_timestamp();

            let p1 = self.build_tcp_packet(TcpFlag::Syn.into(), &[]);
            self.switch_direction(false);
            self.set_mode_fix_l4_tcp_sequence(true);
            self.l4_owner_sequence_nonce += 1;

            let p2 = self.build_tcp_packet(TcpFlag::Syn | TcpFlag::Ack, &[]);

            self.l4_peer_sequence_nonce += 1;
            self.switch_direction(false);

            self.inner.l4_tcp_sequence = self.l4_peer_sequence_nonce;
            self.inner.l4_tcp_acknowledgment = self.l4_owner_sequence_nonce;

            let p3 = self.build_tcp_packet(TcpFlag::Ack.into(), &[]);

            self.connected = true;
            let total = [p1, p2, p3];
            if self.record {
                self.payloads.extend(total.clone());
            }
            total.to_vec()
        } else {
            vec![]
        }
    }

    pub fn sendp_tcp_syn(&mut self, with_payload: &[u8]) -> Vec<u8> {
        if self.proto == IPProtocol::TCP {
            let result = self.build_tcp_packet(TcpFlag::Syn.into(), with_payload);
            if self.record {
                self.payloads.push(result.clone());
            }
            result
        } else {
            vec![]
        }
    }

    pub fn sendp_tcp_ack(&mut self, with_payload: &[u8]) -> Vec<u8> {
        if self.proto == IPProtocol::TCP {
            let result = self.build_tcp_packet(TcpFlag::Ack.into(), with_payload);
            if self.sequence_enabled {
                if with_payload.len() > 0 {
                    if !self.inner.is_reverse() {
                        self.l4_owner_sequence_nonce += self.inner.data().len() as u32;
                    } else {
                        self.l4_peer_sequence_nonce += self.inner.data().len() as u32;
                    }
                }
            }
            if self.record {
                self.payloads.push(result.clone());
            }
            result
        } else {
            vec![]
        }
    }

    pub fn send(&mut self, with_payload: &[u8], recv_ack: bool) -> Vec<Vec<u8>> {
        self.send_advanced(with_payload, recv_ack, TcpFlag::Push | TcpFlag::Ack)
    }

    ///
    /// Send a packet with application data.
    ///
    /// An acknowledge packet will be sended when [`recv_ack`] flag was enabled,
    /// but that transmission is ignored where [`IPProtocol`] enum is not
    /// [`IPProtocol::TCP`].
    ///
    /// [`IPProtocol`]: crate::general::IPProtocol
    /// [`IPProtocol::TCP`]: crate::general::IPProtocol::TCP
    ///
    pub fn send_advanced(&mut self, with_payload: &[u8], recv_ack: bool, with_flags: u8) -> Vec<Vec<u8>> {
        let mut vecs: Vec<Vec<u8>> = vec![];
        if self.proto > IPProtocol::NONE {
            if self.fragmented {
                // downgrade L3 layer & and check imcoming payload length has maximum MTU.
                self.inner.rebuild_capacity(crate::general::Layer::L3);
                let l3_snaplen = self.inner.l3_ptr().len();
                let payload_len = with_payload.len();
                if l3_snaplen + payload_len > self.inner.mtu() {
                    let mut max_payload_len = 1500 - l3_snaplen;
                    let mut start_offset = 0;

                    // we need to consider sending a first fragmentation in UDP.
                    if self.proto == IPProtocol::UDP {
                        self.inner.l3_ipv4_iden = thread_rng().gen(); // Set new identification number.
                        self.inner.l3_fragment = (false, false, true, 0);

                        self.inner.set_mode_automatic_length(false);

                        unsafe {
                            self.inner.modify_l4_udp_length((payload_len + 8) as u16);
                            // included UDP header length
                        }
                        self.inner.build(&with_payload[..max_payload_len - 8]);

                        self.inner.set_mode_automatic_length(true);

                        let result = self.export_packet();
                        if self.record {
                            self.payloads.push(result.clone());
                        }
                        vecs.push(result);
                        start_offset = max_payload_len - 8;
                    } else if self.proto == IPProtocol::TCP {
                        max_payload_len -= unsafe { self.inner.catch_l4_tcp_length() };
                    }

                    let mut remain_exist = true;
                    let div_count = if (payload_len - start_offset) % max_payload_len > 0 {
                        ((payload_len - start_offset) / max_payload_len) + 1
                    } else {
                        remain_exist = false;
                        (payload_len - start_offset) / max_payload_len
                    };

                    for d in 0..div_count {
                        let mut last = false;
                        let bottom = start_offset + (max_payload_len * d);
                        let top = if d + 1 == div_count {
                            last = true;
                            if remain_exist {
                                payload_len
                            } else {
                                start_offset + (max_payload_len * (d + 1))
                            }
                        } else {
                            start_offset + (max_payload_len * (d + 1))
                        };

                        let slice_pl = &with_payload[bottom..top];
                        match self.proto {
                            IPProtocol::TCP => {
                                let result = if last {
                                    self.send(slice_pl, true)
                                } else {
                                    vec![self.sendp_tcp_ack(slice_pl)]
                                };
                                vecs.extend(result);
                            }
                            IPProtocol::UDP => {
                                self.inner.l3_fragment = (false, false, !last, (bottom + 8) as u16);
                                self.inner.build_l3(slice_pl);
                                let result = self.export_packet();
                                if self.record {
                                    self.payloads.push(result.clone());
                                }
                                vecs.push(result);
                            }
                            IPProtocol::ICMP => {
                                todo!("Didn't implemented ICMP case.");
                            }
                            _ => unreachable!(),
                        }
                    }
                    return vecs;
                } else {
                    // nothing else, just default process.
                }
            }
        }

        match self.proto {
            IPProtocol::TCP => {
                let total_pl = self.build_tcp_packet(with_flags, with_payload);
                if self.record {
                    self.payloads.push(total_pl.clone());
                }
                vecs.push(total_pl);
                if self.sequence_enabled {
                    let segment_len = self.inner.data().len() as u32;
                    if !self.inner.is_reverse() {
                        self.l4_owner_sequence_nonce += segment_len;
                    } else {
                        self.l4_peer_sequence_nonce += segment_len;
                    }
                }
                if recv_ack {
                    self.switch_direction(false);
                    let pl2 = self.sendp_tcp_ack(&[]);
                    vecs.push(pl2);
                    self.switch_direction(true);
                }
            }
            IPProtocol::UDP => {
                self.inner.l3_fragment = (false, false, false, 0); // Not fragment data.
                self.inner.l3_ipv4_iden = thread_rng().gen();
                let total_pl = self.build_and_packet(with_payload);
                if self.record {
                    self.payloads.push(total_pl.clone());
                }
                vecs.push(total_pl);
            }
            // included ICMP.
            _ => {
                // it is L2 session (guess) or unsupport IPProtocol
                if self.inner.current_layer() <= Layer::L2 {
                    let total_pl = self.build_and_packet_raw(with_payload);
                    if self.record {
                        self.payloads.push(total_pl.clone());
                    }
                    vecs.push(total_pl);
                }
            }
        }
        vecs
    }

    ///
    /// Sends a TCP-reset packet. Does nothing for [`IPProtocol`] other than TCP.
    /// If the handshake is valid, the connection is considered broken.
    ///
    /// [`IPProtocol`]: crate::general::IPProtocol
    ///
    pub fn sendp_tcp_reset(&mut self) -> Vec<u8> {
        let mut result = vec![];
        if self.proto == IPProtocol::TCP {
            result = self.build_tcp_packet(TcpFlag::Reset | TcpFlag::Ack, &[]);
            if self.record {
                self.payloads.push(result.clone());
            }
            self.reset_tcp_info();
        }
        result
    }

    ///
    /// Sends a TCP-finish packet. Does nothing for [`IPProtocol`] other than TCP.
    /// If the handshake is valid, the connection is considered broken.
    ///
    /// [`IPProtocol`]: crate::general::IPProtocol
    ///
    pub fn sendp_tcp_finish(&mut self) -> Vec<u8> {
        let mut result = vec![];
        if self.proto == IPProtocol::TCP {
            result = self.build_tcp_packet(TcpFlag::Fin | TcpFlag::Ack, &[]);
            if self.record {
                self.payloads.push(result.clone());
            }
            self.reset_tcp_info();
        }
        result
    }

    fn build_tcp_packet(&mut self, flags: u8, with_payload: &[u8]) -> Vec<u8> {
        self.update_timestamp();

        self.inner.l4_tcp_flags = flags;
        self.inner.l4_tcp_option_tsval = self.ts_val;
        self.inner.l4_tcp_option_tsecho = self.ts_echo;

        if let Some(os) = self.os.get(&self.inner.l4_tcp_flags) {
            os.reflect_to_session(self.inner.l4_tcp_flags, &mut self.inner);
        }

        if self.sequence_enabled {
            if self.inner.is_reverse() {
                self.inner.l4_tcp_sequence = self.l4_peer_sequence_nonce;
                self.inner.l4_tcp_acknowledgment = self.l4_owner_sequence_nonce;
            } else {
                self.inner.l4_tcp_sequence = self.l4_owner_sequence_nonce;
                self.inner.l4_tcp_acknowledgment = self.l4_peer_sequence_nonce;
            }
        }
        let result = self.build_and_packet(with_payload);
        result
    }

    fn build_and_packet(&mut self, with_payload: &[u8]) -> Vec<u8> {
        println!("payload_len = {:?}", with_payload.len());
        self.inner.build(with_payload);
        let result = self.export_packet();
        let with_flags = self.inner.l4_tcp_flags;
        if with_flags & TcpFlag::Fin as u8 > 0 || with_flags & TcpFlag::Reset as u8 > 0 {
            self.reset_tcp_info();
        }
        result
    }

    fn build_and_packet_raw(&mut self, with_payload: &[u8]) -> Vec<u8> {
        self.inner.build_l2(with_payload);
        self.export_packet()
    }

    fn export_packet(&mut self) -> Vec<u8> {
        let mut result = self.inner.payload().to_vec();
        self.with_packet_suffix(&mut result);
        result
    }

    fn with_packet_suffix(&self, payload: &mut Vec<u8>) {
        if self.padding.0 {
            let pad_len = self.padding.1 as i32 - payload.len() as i32;
            if pad_len > 0 {
                let pad = vec![0_u8; pad_len as usize];
                payload.extend(&pad);
            }
        }
        if self.fcs {
            let fcs_value = util::calc_fcs(payload);
            payload.extend(fcs_value.to_le_bytes());
        }
    }
}

pub mod http_tracer;