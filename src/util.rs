use libc::{c_int, sysctl, sysinfo, timeval, CTL_KERN};
use std::fs::File;
use std::io::Write;
use std::mem::{self, MaybeUninit};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn calc_fcs(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        let current_byte = byte as u32;
        crc ^= current_byte;
        for _ in 0..8 {
            if crc & 1 != 0 {
                // See below: https://reveng.sourceforge.io/crc-catalogue/all.htm#crc.cat.crc-32-iso-hdlc
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

pub fn calc_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from(chunk[0]) << 8 | u16::from(chunk[1])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum = sum.wrapping_add(u32::from(word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
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

pub fn get_linux_uptime() -> Result<u64, String> {
    let mut info = MaybeUninit::<sysinfo>::uninit();
    let result = unsafe { libc::sysinfo(info.as_mut_ptr()) };
    if result == 0 {
        let info = unsafe { info.assume_init() };
        Ok(info.uptime as u64)
    } else {
        Err("Failed to get sysinfo".to_string())
    }
}
