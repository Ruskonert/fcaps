use std::{
    collections::HashMap,
    fmt::Debug,
    io::{Error, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{
    general::{FragmentInfo, IPProtocol, Layer, TcpFlag, TcpOption}, preset::Preset, util
};

pub const L2_ETHERNET_SIZE: usize = 14;
pub const L3_IPV4_HEADER_SIZE: usize = 20;
pub const L3_IPV6_HEADER_SIZE: usize = 40;

///
/// PseudoHeader is a fake header assumed for calculating checksum
/// in L4 layer such as TCP, UDP.
///
pub struct PseudoHeader<'a> {
    data: &'a [u8],
    ipv6: bool,
}

impl<'a> PseudoHeader<'a> {
    ///
    /// Create instances based on the entire payload corresponding to layers L2 to L4.
    ///
    pub fn from_payload(payload: &'a [u8], ipv6: bool) -> Result<Self, Error> {
        if ipv6 {
            if payload.len() < L2_ETHERNET_SIZE + L3_IPV6_HEADER_SIZE {
                Err(Error::new(ErrorKind::Other, "Oops! invaild payload"))
            } else {
                Ok(Self {
                    data: payload,
                    ipv6,
                })
            }
        } else {
            if payload.len() < L2_ETHERNET_SIZE + L3_IPV4_HEADER_SIZE {
                Err(Error::new(ErrorKind::Other, "Oops! invaild payload"))
            } else {
                Ok(Self {
                    data: payload,
                    ipv6,
                })
            }
        }
    }

    ///
    ///
    ///
    fn pseudo(&self, pl: &mut [u8], protocol: u16) {
        // ipv6 & TCP, UDP
        if pl.len() == 40 {
            let src_ip_offset = L2_ETHERNET_SIZE + 8;
            let dst_ip_offset = L2_ETHERNET_SIZE + 24;
            let src_ip_ptr = &self.data[src_ip_offset..src_ip_offset + 16];
            let dst_ip_ptr = &self.data[dst_ip_offset..dst_ip_offset + 16];
            pl[..16].copy_from_slice(src_ip_ptr);
            pl[16..32].copy_from_slice(dst_ip_ptr);
            let length: u32 = (self.data.len() - L2_ETHERNET_SIZE - L3_IPV6_HEADER_SIZE)
                .try_into()
                .unwrap();
            pl[32..36].copy_from_slice(&length.to_be_bytes());
            pl[36..39].copy_from_slice(&[0, 0, 0]);
            pl[39] = protocol as u8;
        }
        // ipv4
        else if pl.len() == 12 {
            let src_ip_offset = L2_ETHERNET_SIZE + 12;
            let dst_ip_offset = L2_ETHERNET_SIZE + 16;
            let src_ip_ptr = &self.data[src_ip_offset..src_ip_offset + 4];
            let dst_ip_ptr = &self.data[dst_ip_offset..dst_ip_offset + 4];
            pl[..4].copy_from_slice(src_ip_ptr);
            pl[4..8].copy_from_slice(dst_ip_ptr);
            pl[8..10].copy_from_slice(&protocol.to_be_bytes()); // Protocol: UDP

            let length: u16 = (self.data.len() - L2_ETHERNET_SIZE - L3_IPV4_HEADER_SIZE)
                .try_into()
                .unwrap();
            pl[10..12].copy_from_slice(&length.to_be_bytes());
        } else {
        }
    }

    ///
    /// Generates a UDP-based pseudo.
    ///
    pub fn pseudo_udp(&self) -> Vec<u8> {
        let mut pseudo_payload = if self.ipv6 {
            [0; 40].to_vec()
        } else {
            [0; 12].to_vec()
        };
        self.pseudo(&mut pseudo_payload, IPProtocol::UDP.into());
        return pseudo_payload;
    }

    ///
    /// Generates a TCP-based pseudo.
    ///
    pub fn pseudo_tcp(&self) -> Vec<u8> {
        let mut pseudo_payload = if self.ipv6 {
            [0; 40].to_vec()
        } else {
            [0; 12].to_vec()
        };
        self.pseudo(&mut pseudo_payload, IPProtocol::TCP.into());
        return pseudo_payload;
    }
}

#[derive(Default, Clone)]
pub struct Session {
    // L2 material
    pub l2_src_mac: [u8; 6],
    pub l2_dst_mac: [u8; 6],
    l2_etype: u16,

    // L3 material (IPv4, IPv6)
    pub l3_dsc: u8,
    pub l3_ecn: u8,
    pub l3_ipv4_iden: u16,
    pub l3_ipv4_ttl: u8,
    pub l3_ipv6_flow_label: u32,
    pub l3_ipv6_hop: u8,
    pub l3_fragment: FragmentInfo,

    pub l3_src_ip: [u8; 16], // ipv6 support
    pub l3_dst_ip: [u8; 16], // ipv6 support

    pub protocol: IPProtocol,

    // L4 material (TCP, UDP)
    pub l4_sport: u16,
    pub l4_dport: u16,

    // TCP material
    pub l4_tcp_options: HashMap<u8, Vec<TcpOption>>,
    pub l4_tcp_flags: u8,
    pub l4_tcp_flags_ecn: bool,
    pub l4_tcp_sequence: u32,
    pub l4_tcp_acknowledgment: u32,
    pub l4_tcp_window_size: u16,
    pub l4_tcp_urgent_ptr: u16,

    pub fp: HashMap<u8, Preset>, // flag 0 is undefined (Not TCP case)

    // internal management only
    mtu: usize,

    src_ip_capacity: u8,
    dst_ip_capacity: u8,

    reverse: bool,

    ipv4_checksum: bool,
    transport_checksum: bool,
    automatic_length: bool,

    payload_offset: usize,

    build_layer: Layer,
    intl: Vec<u8>,
    capacity: usize,
}

impl Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r_intl = &self.intl[..self.capacity];
        let sip = &self.l3_src_ip[..self.src_ip_capacity.into()];
        let dip = &self.l3_dst_ip[..self.dst_ip_capacity.into()];
        f.debug_struct("Session")
            .field("l2_src_mac", &self.l2_src_mac)
            .field("l2_dst_mac", &self.l2_dst_mac)
            .field("l2_etype", &self.l2_etype)
            .field("l3_ipv4_iden", &self.l3_ipv4_iden)
            .field("l3_ipv4_ttl", &self.l3_ipv4_ttl)
            .field("l3_ipv6_flow_label", &self.l3_ipv6_flow_label)
            .field("l3_ipv6_hop", &self.l3_ipv6_hop)
            .field("l3_src_ip", &sip)
            .field("l3_dst_ip", &dip)
            .field("protocol", &self.protocol)
            .field("l4_sport", &self.l4_sport)
            .field("l4_dport", &self.l4_dport)
            .field("l4_tcp_options", &self.l4_tcp_options)
            .field("l4_tcp_flags", &self.l4_tcp_flags)
            .field("l4_tcp_sequence", &self.l4_tcp_sequence)
            .field("l4_tcp_acknowledgment", &self.l4_tcp_acknowledgment)
            .field("l4_tcp_window_size", &self.l4_tcp_window_size)
            .field("l4_tcp_urgent_ptr", &self.l4_tcp_urgent_ptr)
            .field("mtu", &self.mtu)
            .field("ipv4_checksum", &self.ipv4_checksum)
            .field("transport_checksum", &self.transport_checksum)
            .field("payload_offset", &self.payload_offset)
            .field("build_layer", &self.build_layer)
            .field("intl", &r_intl)
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl<'a> Session {
    pub fn l2_ptr(&'a self) -> &'a [u8] {
        if self.build_layer >= Layer::L2 {
            &self.intl[..self.capacity]
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l2_unsafe_ptr(&'a self) -> &'a [u8] {
        if self.build_layer >= Layer::L2 {
            &self.intl[..]
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l3_ptr(&'a self) -> &'a [u8] {
        if self.build_layer >= Layer::L2 {
            &self.intl[L2_ETHERNET_SIZE..self.capacity]
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l3_unsafe_ptr(&'a self) -> &'a [u8] {
        if self.build_layer >= Layer::L2 {
            &self.intl[L2_ETHERNET_SIZE..]
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l4_ptr(&'a self) -> &'a [u8] {
        if self.build_layer >= Layer::L3 {
            if self.is_ether_ipv4() {
                &self.intl[L2_ETHERNET_SIZE + L3_IPV4_HEADER_SIZE..self.capacity]
            } else if self.is_ether_ipv6() {
                &self.intl[L2_ETHERNET_SIZE + L3_IPV6_HEADER_SIZE..self.capacity]
            } else {
                panic!("Unexpected point, undefined layer")
            }
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l4_unsafe_ptr(&'a self) -> &'a [u8] {
        if self.build_layer >= Layer::L3 {
            if self.is_ether_ipv4() {
                &self.intl[L2_ETHERNET_SIZE + L3_IPV4_HEADER_SIZE..]
            } else if self.is_ether_ipv6() {
                &self.intl[L2_ETHERNET_SIZE + L3_IPV6_HEADER_SIZE..]
            } else {
                panic!("Unexpected point at L3 layer")
            }
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l2_mut_ptr(&'a mut self) -> &'a mut [u8] {
        if self.build_layer >= Layer::L2 {
            &mut self.intl[..self.capacity]
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l2_mut_unsafe_ptr(&'a mut self) -> &'a mut [u8] {
        if self.build_layer >= Layer::L2 {
            &mut self.intl[..]
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l3_mut_ptr(&'a mut self) -> &'a mut [u8] {
        if self.build_layer >= Layer::L2 {
            &mut self.intl[L2_ETHERNET_SIZE..self.capacity]
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l3_mut_unsafe_ptr(&'a mut self) -> &'a mut [u8] {
        if self.build_layer >= Layer::L2 {
            &mut self.intl[L2_ETHERNET_SIZE..]
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l4_mut_ptr(&'a mut self) -> &'a mut [u8] {
        if self.build_layer >= Layer::L3 {
            if self.is_ether_ipv4() {
                &mut self.intl[L2_ETHERNET_SIZE + L3_IPV4_HEADER_SIZE..self.capacity]
            } else if self.is_ether_ipv6() {
                &mut self.intl[L2_ETHERNET_SIZE + L3_IPV6_HEADER_SIZE..self.capacity]
            } else {
                panic!("Unexpected point, undefined layer")
            }
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn l4_mut_unsafe_ptr(&'a mut self) -> &'a mut [u8] {
        if self.build_layer >= Layer::L3 {
            if self.is_ether_ipv4() {
                &mut self.intl[L2_ETHERNET_SIZE + L3_IPV4_HEADER_SIZE..]
            } else if self.is_ether_ipv6() {
                &mut self.intl[L2_ETHERNET_SIZE + L3_IPV6_HEADER_SIZE..]
            } else {
                panic!("Unexpected point at L3 layer")
            }
        } else {
            panic!("Unexpected point")
        }
    }

    pub fn data(&'a self) -> &'a [u8] {
        if self.payload_offset > self.capacity {
            panic!("Unexpected point");
        }
        let a = &self.intl[self.payload_offset..self.capacity];
        a
    }

    pub fn data_mut(&'a mut self) -> &'a mut [u8] {
        if self.payload_offset > self.capacity {
            panic!("Unexpected point");
        }
        let a = &mut self.intl[self.payload_offset..self.capacity];
        a
    }

    pub fn payload(&'a self) -> &'a [u8] {
        self.l2_ptr()
    }

    pub fn payload_mut(&'a mut self) -> &'a mut [u8] {
        self.l2_mut_ptr()
    }

    ///
    /// Returns a pointer to the raw payload managed internally.
    ///
    pub unsafe fn raw(&'a self) -> &'a [u8] {
        &self.intl[..]
    }

    //
    // Returns a mutable pointer to the raw payload managed internally.
    //
    pub unsafe fn raw_mut(&'a mut self) -> &'a mut [u8] {
        &mut self.intl[..]
    }
}

impl Session {
    // <---------------- :start: Construct ---------------->
    pub fn create_default() -> Self {
        let mut target: Self = Default::default();
        target.reverse = false;
        target.ipv4_checksum = true;
        target.transport_checksum = true;
        target.automatic_length = true;
        target.l3_ipv4_ttl = 128;
        target.l3_ipv6_flow_label = 0x12345;
        target.l3_ipv6_hop = 64;
        target.l3_ipv4_iden = 0xabcd;
        target.l3_fragment = (false, false, false, 0);
        target.mtu = 1500;
        target.protocol = IPProtocol::NONE;
        target.intl = Vec::with_capacity((target.mtu + L2_ETHERNET_SIZE).into());
        for _ in 0..(target.mtu + L2_ETHERNET_SIZE) {
            target.intl.push(0);
        }
        target
    }

    pub fn from_payload(payload: &[u8]) -> Option<Self> {
        let mut sess = Self::create_default();
        if payload.len() >= 14 {
            sess.l2_src_mac[..].copy_from_slice(&payload[..6]);
            sess.l2_dst_mac[..].copy_from_slice(&payload[6..12]);

            unsafe {
                let etype = payload[12..14].as_ptr() as *const u16;
                match *etype {
                    // ipv4 or ipv6
                    0x0800 | 0x86DD => {
                        sess.l2_etype = *etype;
                        let offset = Self::from_l3(&mut sess, *etype, &payload[14..]);
                        if offset > 14 {
                            Self::from_l4(&mut sess, &payload[offset..]);
                        }
                    }
                    _ => {
                        sess.l2_etype = *etype;
                        sess.build_l2(&payload[14..]);
                    }
                }
            }
            Some(sess)
        } else {
            None
        }
    }

    fn from_l3(session: &mut Session, etype: u16, payload: &[u8]) -> usize {
        let mut offset = 14;
        unsafe {
            match etype {
                0x0800 => if session.catch_l3_ip_version_prefix() != (4, 20) {},
                0x86DD => {}
                _ => {
                    unreachable!()
                }
            }
        }
        offset
    }

    fn from_l4(session: &mut Session, payload: &[u8]) -> usize {
        14
    }

    pub fn create_ether(etype: u16) -> Self {
        let mut target = Self::create_default();
        target.mac_default();
        target.l2_etype = etype;
        target.build_l2(&[]);
        target
    }

    pub fn create_icmp() -> Self {
        let mut target = Self::create_default();
        target.mac_default();
        target.ip_default(false);
        target.protocol = IPProtocol::ICMP;
        target.build(&[]);
        target
    }

    pub fn create_tcp(src_port: u16, dst_port: u16) -> Self {
        let mut target = Self::create_default();
        target.mac_default();
        target.ip_default(false);
        target.protocol = IPProtocol::TCP;
        target.l4_sport = src_port;
        target.l4_dport = dst_port;
        target.l4_tcp_window_size = 512;
        target.l4_tcp_flags = TcpFlag::Syn.into();
        target.l4_tcp_sequence = 0;
        target.l4_tcp_acknowledgment = 0;
        target.l4_tcp_urgent_ptr = 0;
        target.build(&[]);
        target
    }

    pub fn create_udp(src_port: u16, dst_port: u16) -> Self {
        let mut target = Self::create_default();
        target.mac_default();
        target.ip_default(false);
        target.protocol = IPProtocol::UDP;
        target.l4_sport = src_port;
        target.l4_dport = dst_port;
        target.build(&[]);
        target
    }
    // <---------------- :end: Construct ---------------->

    // <---------------- :start: Default ---------------->
    pub fn mac_default(&mut self) {
        self.l2_src_mac = [0x00, 0x01, 0x33, 0x44, 0x55, 0x66];
        self.l2_dst_mac = [0x00, 0x01, 0x43, 0x54, 0x65, 0x76];
    }

    pub fn ip_default(&mut self, is_ipv6: bool) {
        if !is_ipv6 {
            let default_src = [192, 168, 0, 1];
            let default_dst = [192, 168, 0, 100];

            self.assign_src_ip_raw(&default_src);
            self.assign_dst_ip_raw(&default_dst);
        } else {
            self.assign_src_ip("2001:0DB8::1428:57ab");
            self.assign_dst_ip("2001:0DB8::1428:57ac");
        }
    }
    // <---------------- :end: Default ---------------->

    // <---------------- :start: update material ---------------->
    #[inline]
    fn try_convert_to_ip(some_ip: &str) -> Option<Vec<u8>> {
        let v = Some(if let Ok(v) = Ipv4Addr::from_str(some_ip) {
            v.octets().to_vec()
        } else {
            if let Ok(v) = Ipv6Addr::from_str(some_ip) {
                v.octets().to_vec()
            } else {
                return None;
            }
        });
        v
    }

    pub fn assign_src_ip_raw(&mut self, some_ip: &[u8]) -> bool {
        match some_ip.len() {
            4 => {
                self.l3_src_ip[..some_ip.len()].copy_from_slice(&some_ip);
                self.src_ip_capacity = 4;
                true
            }
            16 => {
                self.l3_src_ip[..some_ip.len()].copy_from_slice(&some_ip);
                self.src_ip_capacity = 16;
                true
            }
            _ => false,
        }
    }

    pub fn assign_dst_ip_raw(&mut self, some_ip: &[u8]) -> bool {
        match some_ip.len() {
            4 => {
                self.l3_dst_ip[..some_ip.len()].copy_from_slice(&some_ip);
                self.dst_ip_capacity = 4;
                true
            }
            16 => {
                self.l3_dst_ip[..some_ip.len()].copy_from_slice(&some_ip);
                self.dst_ip_capacity = 16;
                true
            }
            _ => false,
        }
    }

    pub fn assign_src_ip(&mut self, ip: &str) -> bool {
        if let Some(ip_vec) = Session::try_convert_to_ip(ip) {
            self.l3_src_ip[..ip_vec.len()].copy_from_slice(&ip_vec);
            self.src_ip_capacity = ip_vec.len() as u8;
            true
        } else {
            false
        }
    }

    pub fn assign_dst_ip(&mut self, ip: &str) -> bool {
        if let Some(ip_vec) = Session::try_convert_to_ip(ip) {
            self.l3_dst_ip[..ip_vec.len()].copy_from_slice(&ip_vec);
            self.dst_ip_capacity = ip_vec.len() as u8;
            true
        } else {
            false
        }
    }

    pub fn assign_src_mac(&mut self, mac: &str) -> bool {
        let mac_part: Vec<&str> = mac.split(":").map(|k| k).collect();
        if mac_part.len() != 6 {
            return false;
        }
        for (idx, part) in mac_part.iter().enumerate() {
            if let Ok(v) = u8::from_str_radix(part, 16) {
                self.l2_src_mac[idx] = v;
            } else {
                return false;
            }
        }
        return true;
    }

    pub fn assign_tcp_option_with_padding(&mut self, tcp_flag: u8, opt: TcpOption) {
        let options = self.l4_tcp_options.entry(tcp_flag).or_insert(Vec::new());
        match opt {
            TcpOption::WindowScale(_) => {
                options.push(TcpOption::NoOperation);
                options.push(opt);
            }
            TcpOption::Timestamp(_, _) | TcpOption::SACKPermitted => {
                options.push(TcpOption::NoOperation);
                options.push(TcpOption::NoOperation);
                options.push(opt);
            }
            TcpOption::SelectiveAcknowledgment(_) => {
                let vecs = opt.to_bytes();
                let modular = vecs.len() % 4;
                if modular > 0 {
                    for _ in 0..(4 - modular) {
                        options.push(TcpOption::NoOperation);
                    }
                }
                options.push(opt);
            }
            _ => {
                options.push(opt);
            }
        }
    }

    pub fn assign_tcp_option(&mut self, tcp_flag: u8, opt: TcpOption) {
        let options = self.l4_tcp_options.entry(tcp_flag).or_insert(Vec::new());
        options.push(opt);
    }

    pub fn current_tcp_option(&mut self, flags: u8) -> Option<&mut Vec<TcpOption>> {
        self.l4_tcp_options.get_mut(&flags)
    }

    pub fn clear_tcp_option(&mut self, flags: Option<u8>) {
        if let Some(flags) = flags {
            self.l4_tcp_options.remove(&flags);
        }
        else {
            self.l4_tcp_options.clear();
        }
    }

    pub fn assign_dst_mac(&mut self, mac: &str) -> bool {
        let mac_part: Vec<&str> = mac.split(":").map(|k| k).collect();
        if mac_part.len() != 6 {
            return false;
        }
        for (idx, part) in mac_part.iter().enumerate() {
            if let Ok(v) = u8::from_str_radix(part, 16) {
                self.l2_dst_mac[idx] = v;
            } else {
                return false;
            }
        }
        return true;
    }

    #[inline]
    fn or_insert_payload(&mut self, pl: &[u8]) -> bool {
        if pl.len() > 0 {
            if self.capacity + pl.len() - L2_ETHERNET_SIZE <= self.mtu {
                self.payload_offset = self.capacity.try_into().unwrap();
                self.intl[self.capacity..self.capacity + pl.len()].copy_from_slice(pl);
                self.capacity += pl.len();
                true
            } else {
                println!(
                    "MTU is {}, but payload size is {}, capacity={}",
                    self.mtu,
                    pl.len(),
                    self.capacity
                );
                false
            }
        } else {
            true
        }
    }

    // <---------------- :end: update material ---------------->

    // <---------------- :start: L2 build & modify payload ---------------->
    pub fn build_l2(&mut self, with_payload: &[u8]) {
        self.rebuild_capacity(Layer::L1);

        self.intl[..6].copy_from_slice(&self.l2_dst_mac);
        self.intl[6..12].copy_from_slice(&self.l2_src_mac);
        self.capacity = L2_ETHERNET_SIZE;
        self.build_l2_intl_ethertype();

        if self.or_insert_payload(with_payload) {
            self.build_layer = Layer::L2;
        }
    }

    fn build_l2_intl_ethertype(&mut self) {
        if self.l2_etype != 0x0000 {
            unsafe {
                let etype_ptr = self.intl[12..].as_mut_ptr() as *mut u16;
                *etype_ptr = self.l2_etype.to_be();
            }
        } else {
        }
    }
    // <---------------- :end: L2 build & modify payload ---------------->

    // <---------------- :start: L3 (IPv4, IPv6) build & modify payload ---------------->
    fn heuristic_ip_ethertype(&mut self) {
        if self.src_ip_capacity == 16 && self.dst_ip_capacity == 16 {
            self.l2_etype = 0x86DD; // IPv6
        } else if self.src_ip_capacity == 4 && self.dst_ip_capacity == 4 {
            self.l2_etype = 0x0800; // IPv4
        } else {
            // another type.
            println!(
                "Heuristic failed for scanning IP Ethertype, src_ip_len = {}, dst_ip_len ={}",
                self.src_ip_capacity, self.dst_ip_capacity
            );
        }
    }

    #[inline]
    unsafe fn modify_l3_ip_version_prefix(&mut self) {
        let l3_payload = self.intl[L2_ETHERNET_SIZE..].as_mut_ptr();
        if self.l2_etype == 0x0800 {
            let version = 4; // Version 4
            let header_length = 0b0101; // Header Length (20 bytes, 5)
            *l3_payload = ((version << 4) | header_length) & 0xFF;
        } else if self.l2_etype == 0x86DD {
            let l3_payload = self.intl[L2_ETHERNET_SIZE..].as_mut_ptr();
            let version = 6 << 4; // Version 6
            *l3_payload = version;
        } else {
            panic!("Can't modify IP Header for version & prefix.");
        }
    }

    unsafe fn catch_l3_ip_version_prefix(&mut self) -> (u8, u8) {
        let l3_payload = self.intl[L2_ETHERNET_SIZE..].as_mut_ptr();
        ((*l3_payload & 0xF0 >> 4), ((*l3_payload) & 0x0F * 4))
    }

    #[inline]
    fn modify_l3_ipv6_flow_label(&mut self, flow_iden: u32) {
        let start = L2_ETHERNET_SIZE;
        let end = start + 4;

        let mut payload_arr = [0u8; 4];
        payload_arr.copy_from_slice(&self.intl[start..end]);

        let mut payload = u32::from_be_bytes(payload_arr);
        let version_ecn_dsp = payload & 0xFFF00000;
        let flow_iden = flow_iden & 0x000FFFFF;

        payload = version_ecn_dsp | flow_iden;

        let new_payload_arr = payload.to_be_bytes();
        self.intl[start..end].copy_from_slice(&new_payload_arr);
    }

    #[inline]
    pub unsafe fn modify_l3_ipv6_hop_limit(&mut self, hop_limit: u8) {
        let l3_payload = self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().add(6);
        *l3_payload = hop_limit;
    }

    #[inline]
    pub unsafe fn modify_l3_ip_dsc_ecn(&mut self, dsc: u8, ecn: u8) {
        /*
        Differentiated Services Field.
        0000 00.. = Differentiated Services Codepoint: Default (0)
        .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
        */
        let ptr = self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().wrapping_add(1);
        *ptr = (dsc << 6) | (ecn & 0x03);
    }

    #[inline]
    pub unsafe fn modify_l3_ip_length(&mut self, length: u16) {
        let ptr = if self.is_ether_ipv4() {
            self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().wrapping_add(2) as *mut u16
        } else if self.is_ether_ipv6() {
            self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().wrapping_add(4) as *mut u16
        } else {
            panic!("Can't modify Header Length Field");
        };
        *ptr = length.to_be();
    }

    #[inline]
    pub unsafe fn modify_l3_ipv4_idenification(&mut self, idenification: u16) {
        let ptr = self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().wrapping_add(4) as *mut u16;
        *ptr = idenification.to_be();
    }

    #[inline]
    pub unsafe fn modify_l3_ipv4_fragment(&mut self, resv: bool, dont_fragment: bool, more_fragment: bool, fragment_offset: u16) {
        let ptr = self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().wrapping_add(6) as *mut u16;
        let a: u16 = if more_fragment { 1 } else { 0 };
        let b: u16 = if dont_fragment { 2 } else { 0 };
        let c: u16 = if resv { 4 } else { 0 };
        let flags = a | b | c;
        let ff_value: u16 = ((flags << 13) | ((fragment_offset / 8) & 0x1FFF)) & 0xFFFF;
        *ptr = ff_value.to_be();
    }

    #[inline]
    pub unsafe fn catch_l3_ipv4_fragment(&mut self) -> FragmentInfo {
        let ptr = self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().wrapping_add(6) as *mut u16;
        let resv = *ptr & 0x0800 > 0;
        let df = *ptr & 0x0400 > 0;
        let mf = *ptr & 0x0200 > 0;
        let fragment_offset = *ptr & 0x1FF;
        (resv, df, mf, fragment_offset)
    }

    #[inline]
    pub unsafe fn modify_l3_ipv4_ttl(&mut self, ttl: u8) {
        let ptr = self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().wrapping_add(8);
        *ptr = ttl;
    }

    #[inline]
    unsafe fn modify_l3_ip_protocol(&mut self, proto: IPProtocol) {
        let ptr = if self.is_ether_ipv4() {
            self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().wrapping_add(9)
        } else if self.is_ether_ipv6() {
            self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().wrapping_add(6)
        } else {
            panic!("Can't modify protocol value");
        };
        match proto {
            IPProtocol::ICMP | IPProtocol::TCP | IPProtocol::UDP => {
                *ptr = proto as u8;
            }
            _ => {
                panic!("Unsupport protocol type.");
            }
        }
    }

    #[inline]
    pub unsafe fn modify_l3_ipv4_checksum(&mut self, checksum: u16) {
        let ptr = self.intl[L2_ETHERNET_SIZE..].as_mut_ptr().wrapping_add(10) as *mut u16;
        *ptr = checksum.to_be();
    }

    #[inline]
    fn modify_l3_ip_src(&mut self, some_ip: &[u8]) {
        if self.is_ether_ipv4() {
            let offset = L2_ETHERNET_SIZE + 12;
            let ptr = self.intl[offset..offset + 4].as_mut();
            ptr.copy_from_slice(&some_ip[..4]);
        } else if self.is_ether_ipv6() {
            let offset = L2_ETHERNET_SIZE + 8;
            let ptr = self.intl[offset..offset + 16].as_mut();
            ptr.copy_from_slice(&some_ip[..16]);
        } else {
        }
    }

    #[inline]
    fn modify_l3_ip_dst(&mut self, ip: &[u8]) {
        if self.is_ether_ipv4() {
            let offset = L2_ETHERNET_SIZE + 16;
            let ptr = self.intl[offset..offset + 4].as_mut();
            ptr.copy_from_slice(&ip[..4]);
        } else if self.is_ether_ipv6() {
            let offset = L2_ETHERNET_SIZE + 24;
            let ptr = self.intl[offset..offset + 16].as_mut();
            ptr.copy_from_slice(&ip[..16]);
        } else {
        }
    }

    pub fn build_l3(&mut self, with_payload: &[u8]) {
        if self.build_layer < Layer::L2 {
            println!("Need to complete build L2 layer at first.");
            return;
        }
        self.rebuild_capacity(Layer::L2);

        self.heuristic_ip_ethertype(); // Let assume it is assigned Ipv4 or Ipv6.
        if self.is_ether_ipv4() || self.is_ether_ipv6() {
            self.build_l2_intl_ethertype();
            unsafe {
                self.modify_l3_ip_version_prefix();
                self.modify_l3_ip_dsc_ecn(self.l3_dsc, self.l3_ecn);

                let src_ip = self.l3_src_ip.to_owned();
                let dst_ip = self.l3_dst_ip.to_owned();

                self.modify_l3_ip_src(&src_ip);
                self.modify_l3_ip_dst(&dst_ip);

                if self.is_ether_ipv4() {
                    self.modify_l3_ip_length(L3_IPV4_HEADER_SIZE.try_into().unwrap()); // Let assume initial length has 20 bytes

                    self.modify_l3_ipv4_idenification(self.l3_ipv4_iden);
                    self.modify_l3_ipv4_fragment(self.l3_fragment.0, self.l3_fragment.1, self.l3_fragment.2, self.l3_fragment.3);
                    self.modify_l3_ipv4_ttl(self.l3_ipv4_ttl);
                    self.modify_l3_ipv4_checksum(0);
                } else if self.is_ether_ipv6() {
                    self.modify_l3_ip_length(0); // Let assume initial length payload has 0 byte
                    self.modify_l3_ipv6_flow_label(self.l3_ipv6_flow_label);
                    self.modify_l3_ipv6_hop_limit(self.l3_ipv6_hop);
                } else {
                    println!("What case is it?");
                }

                match self.protocol {
                    IPProtocol::ICMP | IPProtocol::TCP | IPProtocol::UDP => {
                        self.modify_l3_ip_protocol(self.protocol);
                    }
                    _ => {
                        println!("What protocol is it?");
                    }
                }
            }

            if self.is_ether_ipv4() {
                self.capacity += L3_IPV4_HEADER_SIZE;
            } else if self.is_ether_ipv6() {
                self.capacity += L3_IPV6_HEADER_SIZE;
            }

            if self.or_insert_payload(with_payload) {
                unsafe {
                    self.build_layer = Layer::L3;
                    self.modify_l3_ip_length(
                        (self.capacity - L2_ETHERNET_SIZE).try_into().unwrap(),
                    );

                    /* The Checksum has only available on IPv4 Header. */
                    if self.ipv4_checksum {
                        let checksum = util::calc_checksum(&self.l3_ptr()[..L3_IPV4_HEADER_SIZE]);
                        self.modify_l3_ipv4_checksum(checksum);
                    }
                }
            }
        } else {
            // it is neither Ipv4 and Ipv6.
            // Another ethertype.
        }
    }
    // <---------------- :end: L3 build & modify payload ---------------->

    // <---------------- :Start: L4 build & modify payload ---------------->

    #[inline]
    pub unsafe fn modify_l4_checksum(&mut self, checksum: u16) {
        let ptr = self.l4_mut_ptr().as_mut_ptr();
        match self.protocol {
            IPProtocol::TCP => {
                let checksum_ptr = ptr.wrapping_add(16) as *mut u16;
                *checksum_ptr = checksum.to_be();
            }
            IPProtocol::UDP => {
                let checksum_ptr = ptr.wrapping_add(6) as *mut u16;
                *checksum_ptr = checksum.to_be();
            }
            _ => {}
        }
    }

    #[inline]
    pub unsafe fn modify_l4_source_port(&mut self, sport: u16) {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let sport_ptr = ptr as *mut u16;
        *sport_ptr = sport.to_be();
    }

    pub unsafe fn catch_l4_source_port(&self) -> u16 {
        let ptr = self.l4_unsafe_ptr().as_ptr();
        let sport_ptr = ptr as *mut u16;
        *sport_ptr
    }

    #[inline]
    pub unsafe fn modify_l4_destination_port(&mut self, dport: u16) {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let dport_ptr = ptr.wrapping_add(2) as *mut u16;
        *dport_ptr = dport.to_be();
    }

    pub unsafe fn catch_l4_destination_port(&self) -> u16 {
        let ptr = self.l4_unsafe_ptr().as_ptr();
        let dport_ptr = ptr.wrapping_add(2) as *mut u16;
        *dport_ptr
    }

    #[inline]
    pub unsafe fn modify_l4_tcp_sequence_number(&mut self, sequence: u32) {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let slice = std::slice::from_raw_parts_mut(ptr, 12); // or appropriate length
        let sequence_bytes = sequence.to_be_bytes();
        slice[4..8].copy_from_slice(&sequence_bytes);
    }

    #[inline]
    pub unsafe fn modify_l4_tcp_ack_number(&mut self, acknowledgment: u32) {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let slice = std::slice::from_raw_parts_mut(ptr, 12); // or appropriate length
        let ack_bytes = acknowledgment.to_be_bytes();
        slice[8..12].copy_from_slice(&ack_bytes);
    }

    #[inline]
    pub unsafe fn modify_l4_tcp_length(&mut self, with_tcp_option: &[u8]) -> usize {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let length_ptr = ptr.wrapping_add(12);
        let mut current_length = with_tcp_option.len() + 20;
        *length_ptr = if current_length % 4 != 0 {
            current_length = 20;
            // ignore TCP option.
            5 << 4 // 20 bytes
        } else {
            ((current_length / 4) << 4).try_into().unwrap()
        };
        current_length
    }

    pub unsafe fn catch_l4_tcp_length(&self) -> usize {
        let ptr = self.l4_unsafe_ptr().as_ptr();
        let length_ptr = ptr.wrapping_add(12);
        (((*length_ptr & 0xf0) >> 4) * 4).into()
    }

    #[inline]
    pub unsafe fn modify_l4_tcp_option(&mut self, with_tcp_option: &[u8]) {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let slice = std::slice::from_raw_parts_mut(ptr.wrapping_add(20), with_tcp_option.len());
        for i in 0..slice.len() {
            slice[i] = with_tcp_option[i];
        }
    }

    #[inline]
    pub unsafe fn modify_l4_udp_length(&mut self, length: u16) {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let length_ptr = ptr.wrapping_add(4) as *mut u16;
        *length_ptr = length.to_be();
    }

    #[inline]
    pub unsafe fn catch_l4_udp_length(&self) -> u16 {
        let ptr = self.l4_unsafe_ptr().as_ptr();
        let length_ptr = ptr.wrapping_add(4) as *mut u16;
        *length_ptr
    }

    /**
     * Caution: Accuracy ECN and Reserved bits present in bits 9-12 cannot be modified using this function.
     */
    #[inline]
    pub unsafe fn modify_l4_tcp_flags(&mut self, flags: u8) {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let flags_ptr = ptr.wrapping_add(13);
        *flags_ptr = flags;
    }

    #[inline]
    pub unsafe fn modify_l4_tcp_flags_ecn(&mut self, ecn: bool) {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let flags_ptr = ptr.wrapping_add(12);
        if ecn {
            *flags_ptr |= 0x10; // ECN Flags
        }
        else {
            *flags_ptr |= 0xEF; // ECN Flags is disabled
        }
    }

    #[inline]
    pub unsafe fn modify_l4_tcp_window_size(&mut self, window_size: u16) {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let windows_ptr = ptr.wrapping_add(14) as *mut u16;
        *windows_ptr = window_size.to_be();
    }

    #[inline]
    pub unsafe fn modify_l4_tcp_urgent_ptr(&mut self, ptr_value: u16) {
        let ptr = self.l4_mut_unsafe_ptr().as_mut_ptr();
        let urgent_ptr = ptr.wrapping_add(18) as *mut u16;
        *urgent_ptr = ptr_value.to_be();
    }

    pub fn build_l4(&mut self, with_payload: &[u8]) {
        if self.build_layer < Layer::L3 {
            println!("Need to complete build L3 layer at first.");
            return;
        }

        self.rebuild_capacity(Layer::L3);

        unsafe {
            match self.protocol {
                IPProtocol::TCP | IPProtocol::UDP => {
                    self.modify_l4_source_port(self.l4_sport);
                    self.modify_l4_destination_port(self.l4_dport);
                }
                _ => {}
            }

            match self.protocol {
                IPProtocol::TCP => {
                    self.modify_l4_tcp_sequence_number(self.l4_tcp_sequence);
                    self.modify_l4_tcp_ack_number(self.l4_tcp_acknowledgment);
                    // Make TCP option payload & modify TCP Header length (default is 20)
                    let mut tcp_options_pl = vec![];
                    if self.l4_tcp_options.len() > 0 {
                        if let Some(options) = self.l4_tcp_options.get(&self.l4_tcp_flags) {
                            for opt in options {
                                tcp_options_pl.extend(opt.to_bytes());
                            }
                        }
                    }
                    self.modify_l4_tcp_length(&tcp_options_pl);
                    self.modify_l4_tcp_flags(self.l4_tcp_flags);
                    if self.l4_tcp_flags_ecn {
                        self.modify_l4_tcp_flags_ecn(true);
                    }
                    self.modify_l4_tcp_window_size(self.l4_tcp_window_size);
                    self.modify_l4_checksum(0); // initial checksum is zero.

                    //
                    // if self.l4_tcp_urgent_ptr > 0 {
                    //     // URG flags need to enable if urgent pointer is more than 0.
                    //     self.modify_l4_tcp_flags(self.l4_tcp_flags | TcpFlag::Urgent as u8);
                    // }

                    self.modify_l4_tcp_urgent_ptr(self.l4_tcp_urgent_ptr);

                    self.capacity += 20; // TCP default Header Length

                    if tcp_options_pl.len() > 0 {
                        self.modify_l4_tcp_option(&tcp_options_pl);
                        self.capacity += tcp_options_pl.len(); // TCP Option Length
                    }

                    if self.or_insert_payload(with_payload) {

                        self.build_layer = Layer::L4;
                        if self.transport_checksum {
                            let checksum = self.catch_l4_checksum(IPProtocol::TCP);
                            self.modify_l4_checksum(checksum);
                        }

                        if self.is_ether_ipv4() {
                            self.modify_l3_ip_length(
                                (self.capacity - L2_ETHERNET_SIZE).try_into().unwrap(),
                            );
                        } else if self.is_ether_ipv6() {
                            self.modify_l3_ip_length(
                                (self.capacity - L2_ETHERNET_SIZE - L3_IPV6_HEADER_SIZE)
                                    .try_into()
                                    .unwrap(),
                            );
                        }

                        if self.ipv4_checksum {
                            if self.is_ether_ipv4() {
                                // need to reset checksum for calculating
                                self.modify_l3_ipv4_checksum(0);
                                self.modify_l3_ipv4_checksum(util::calc_checksum(
                                    &self.l3_ptr()[..L3_IPV4_HEADER_SIZE],
                                ));
                            }
                        }
                    }
                }
                IPProtocol::UDP => {
                    self.modify_l4_checksum(0); // initial checksum is zero.
                    self.capacity += 8; // UDP Header Length

                    if self.or_insert_payload(with_payload) {
                        self.build_layer = Layer::L4;
                        if self.automatic_length {
                            if self.is_ether_ipv4() {
                                self.modify_l4_udp_length(
                                    (self.capacity - L2_ETHERNET_SIZE - L3_IPV4_HEADER_SIZE) as u16,
                                );
                            } else if self.is_ether_ipv6() {
                                self.modify_l4_udp_length(
                                    (self.capacity - L2_ETHERNET_SIZE - L3_IPV6_HEADER_SIZE) as u16,
                                );
                            }
                        }
                        if self.transport_checksum {
                            let checksum = self.catch_l4_checksum(IPProtocol::UDP);
                            self.modify_l4_checksum(checksum);
                        }

                        if self.is_ether_ipv4() {
                            self.modify_l3_ip_length(
                                (self.capacity - L2_ETHERNET_SIZE).try_into().unwrap(),
                            );
                        } else if self.is_ether_ipv6() {
                            self.modify_l3_ip_length(
                                (self.capacity - L2_ETHERNET_SIZE - L3_IPV6_HEADER_SIZE)
                                    .try_into()
                                    .unwrap(),
                            );
                        }

                        if self.ipv4_checksum {
                            if self.is_ether_ipv4() {
                                // need to reset checksum for calculating
                                self.modify_l3_ipv4_checksum(0);
                                self.modify_l3_ipv4_checksum(util::calc_checksum(
                                    &self.l3_ptr()[..L3_IPV4_HEADER_SIZE],
                                ));
                            }
                        }
                    }
                }
                IPProtocol::ICMP => {
                    // @@@ TODO
                }
                _ => {
                    // alternative
                }
            }
        }
    }

    fn catch_l4_checksum(&self, protocol: IPProtocol) -> u16 {
        let ph = PseudoHeader::from_payload(self.l2_ptr(), self.is_ether_ipv6()).unwrap();
        let mut vrt_header = match protocol {
            IPProtocol::TCP => ph.pseudo_tcp().to_vec(),
            IPProtocol::UDP => ph.pseudo_udp().to_vec(),
            _ => {
                panic!("Unsupport checksum for current protocol")
            }
        };
        vrt_header.extend(self.l4_ptr());
        return util::calc_checksum(&vrt_header);
    }

    // <---------------- :end: L4 build & modify payload ---------------->

    pub fn rebuild_capacity(&mut self, layer: Layer) {
        self.capacity = match layer {
            Layer::L1 => 0,
            Layer::L2 => L2_ETHERNET_SIZE,
            Layer::L3 => {
                if self.is_ether_ipv4() {
                    L2_ETHERNET_SIZE + L3_IPV4_HEADER_SIZE
                } else if self.is_ether_ipv6() {
                    L2_ETHERNET_SIZE + L3_IPV6_HEADER_SIZE
                } else {
                    panic!("Unsupported L3 Layer type, what case?")
                }
            }
            _ => {
                panic!("Unsupported Layer")
            }
        }
    }

    pub fn build(&mut self, with_payload: &[u8]) {
        self.build_l2(&[]);
        if self.build_layer == Layer::L2 {
            self.build_l3(&[]);
            if self.build_layer == Layer::L3 {
                self.build_l4(with_payload);
            }
        }
    }

    pub fn is_ether_ipv4(&self) -> bool {
        self.l2_etype == 0x0800
    }

    pub fn is_ether_ipv6(&self) -> bool {
        self.l2_etype == 0x86DD
    }

    pub fn set_mode_ipv4_checksum(&mut self, enabled: bool) {
        self.ipv4_checksum = enabled;
    }

    pub fn set_mode_transport_checksum(&mut self, enabled: bool) {
        self.transport_checksum = enabled;
    }

    pub fn set_mode_automatic_length(&mut self, enabled: bool) {
        self.automatic_length = enabled;
    }

    pub fn reverse_session(&mut self, rebuild: bool) {
        if self.build_layer == Layer::L1 || self.build_layer >= Layer::L5 {
            return;
        }

        if self.build_layer >= Layer::L2 {
            std::mem::swap(&mut self.l2_src_mac, &mut self.l2_dst_mac);
            if self.build_layer >= Layer::L3 {
                std::mem::swap(&mut self.l3_src_ip, &mut self.l3_dst_ip);
                std::mem::swap(&mut self.src_ip_capacity, &mut self.dst_ip_capacity);
                if self.build_layer >= Layer::L4 {
                    std::mem::swap(&mut self.l4_sport, &mut self.l4_dport);
                }
            }
        }

        if rebuild {
            let payload = self.data().to_vec();
            self.build(&payload);
        }

        self.reverse = !self.reverse;
    }

    pub fn current_layer(&self) -> Layer {
        self.build_layer
    }

    pub fn is_reverse(&self) -> bool {
        self.reverse
    }

    pub fn pktlen(&self) -> usize {
        self.capacity
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    ///
    /// Modify the MTU size of the packet to reconstruct it.
    ///
    /// Normally 1500 bytes are used, ff change it to a
    /// different value, communication may not be smooth or
    /// the service may not be provided.
    ///
    /// <b>Caution: Modifying this value will result in the loss of
    /// the original data that was built, and you will need to
    /// rebuild them. </b>
    ///
    pub fn modify_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
        self.intl.resize(self.mtu, 0);
        if self.capacity > self.mtu {
            self.capacity = self.mtu;
        }
    }
}
