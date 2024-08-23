use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::general::IPProtocol;

#[repr(C, packed)]
pub struct PcapGlobalHeader {
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

#[repr(C, packed)]
pub struct PcapPacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

#[repr(C, packed)]
pub struct L2Mac {
    src: [u8; 6],
    dst: [u8; 6],
    etype: u16,
}

#[repr(C, packed)]
pub struct Ipv4Header {
    version_ihl: u8,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    flags_fragment: u16,
    ttl: u8,
    protocol: IPProtocol,
    checksum: u16,
    src_ip: u32,
    dst_ip: u32,
}

impl Ipv4Header {
    pub fn from_src_ip(&mut self, src: &[u8]) {
        if src.len() == 4 {
            unsafe {
                let ptr = *(src.as_ptr() as *const [u8; 4]);
                self.src_ip = std::mem::transmute::<[u8; 4], u32>(ptr)
            }
        }
    }

    pub fn from_dst_ip(&mut self, dst: &[u8]) {
        if dst.len() == 4 {
            unsafe {
                let ptr = *(dst.as_ptr() as *const [u8; 4]);
                self.dst_ip = std::mem::transmute::<[u8; 4], u32>(ptr)
            }
        }
    }

    pub fn to_slice_src_ip(&self) -> [u8; 4] {
        unsafe {
            let ptr = self.src_ip;
            std::mem::transmute_copy::<u32, [u8; 4]>(&ptr)
        }
    }

    pub fn to_slice_dst_ip(&self) -> [u8; 4] {
        unsafe {
            let ptr = self.dst_ip;
            std::mem::transmute_copy::<u32, [u8; 4]>(&ptr)
        }
    }
}

// TCP 헤더 구조체
#[repr(C, packed)]
pub struct TcpHeader {
    source_port: u16,
    destination_port: u16,
    sequence_number: u32,
    acknowledgment_number: u32,
    data_offset_flags: u16,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
}

#[repr(C, packed)]
pub struct UdpHeader {
    source_port: u16,
    destination_port: u16,
    length: u16,
    checksum: u16,
}

pub struct PcapWrapper {
    g_header: PcapGlobalHeader,
}

pub fn write_pcap(payloads: Vec<Vec<u8>>, filename: &str) -> std::io::Result<()> {
    let mut file = File::create(filename)?;

    // Global Header
    let global_header = [
        0xd4, 0xc3, 0xb2, 0xa1, // Magic Number (little endian)
        0x02, 0x00, // Version Major (2)
        0x04, 0x00, // Version Minor (4)
        0x00, 0x00, 0x00, 0x00, // Thiszone (0)
        0x00, 0x00, 0x00, 0x00, // Sigfigs (0)
        0xff, 0xff, 0x00, 0x00, // Snaplen (65535)
        0x01, 0x00, 0x00, 0x00, // Network (Ethernet)
    ];
    file.write_all(&global_header)?;

    for payload in payloads {
        // Current time for packet timestamp
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let seconds = since_the_epoch.as_secs() as u32;
        let microseconds = since_the_epoch.subsec_micros();

        // Packet Header
        let packet_header = [
            seconds.to_le_bytes(),                // Timestamp seconds
            microseconds.to_le_bytes(),           // Timestamp microseconds
            (payload.len() as u32).to_le_bytes(), // Included Length
            (payload.len() as u32).to_le_bytes(), // Original Length
        ]
        .concat();

        file.write_all(&packet_header)?;

        // Packet Data (Payload)
        file.write_all(&payload)?;
    }

    Ok(())
}
