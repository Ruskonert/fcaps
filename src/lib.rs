pub mod general;
pub mod pcap;
pub mod session;
pub mod tracer;
mod util;

#[cfg(test)]
mod test {
    use crate::{
        general::{IPProtocol, Layer, TcpFlag, TcpOption},
        pcap::write_pcap,
        session::Session,
        tracer::L4Tracer,
    };

    #[test]
    fn assert_write_pcap() {
        let mut tracer = L4Tracer::new(IPProtocol::TCP, 59230, 502);
        let result = tracer.sendp_handshake();
        let _ = write_pcap(result, "./new.pcap");
    }

    #[test]
    fn assert_write_pcap_with_tcp_ipv6() {
        let mut tracer = L4Tracer::new(IPProtocol::TCP, 59230, 502);
        let session = tracer.inner();
        session.ip_default(true);
        let result = tracer.sendp_handshake();
        let _ = write_pcap(result, "./new_tcp_ipv6.pcap");
    }

    #[test]
    fn assert_write_pcap_with_udp_ipv6() {
        let mut tracer = L4Tracer::new(IPProtocol::UDP, 59230, 502);
        let session = tracer.inner();
        session.ip_default(true);
        tracer.send(&[0x41, 0x41, 0x41], true);
        let _ = write_pcap(tracer.payloads, "./new_udp_ipv6.pcap");
    }

    #[test]
    fn assert_write_pcap2() {
        let mut tracer = L4Tracer::new(IPProtocol::TCP, 59230, 502);
        let session = tracer.inner();
        session.assign_tcp_option_with_padding(
            TcpFlag::Syn.into(),
            TcpOption::MaximumSegmentSize(1460),
        );
        session.assign_tcp_option_with_padding(TcpFlag::Syn.into(), TcpOption::WindowScale(8));
        session.assign_tcp_option_with_padding(TcpFlag::Syn.into(), TcpOption::SACKPermitted);

        for _ in 0..1000 {
            tracer.sendp_handshake();
            tracer.send(&[0x41, 0x41, 0x41], true);
            tracer.send(&[0x41, 0x41, 0x41], true);
            tracer.send(&[0x41, 0x41, 0x41], true);
            tracer.send(&[0x41, 0x41, 0x41], true);
            tracer.send(&[0x41, 0x41, 0x41], true);
            tracer.send(&[0x41, 0x41, 0x41], true);
            tracer.send(&[0x41, 0x41, 0x41], true);
            tracer.switch_direction(false);
            tracer.send(&[0x00, 0x00, 0x00, 0x00, 0x00], true);
            tracer.send(&[0x00, 0x00, 0x00, 0x00, 0x00], true);
        }
        println!("{:?}", write_pcap(tracer.payloads, "./new_2.pcap"));
    }

    #[test]
    fn assert_udp_fragmented_pcap() {
        let mut tracer = L4Tracer::new(IPProtocol::UDP, 59230, 1234);
        let mut vecs: Vec<u8> = Vec::with_capacity(8880);
        for i in 0..8880 {
            let k = i % (0x0a as u16);
            vecs.push(k as u8);
        }

        tracer.send(&[0x41, 0x41, 0x41], false);
        tracer.send(&vecs, true);
        tracer.switch_direction(false);

        tracer.send(&[0x41, 0x41, 0x41], false);
        tracer.send(&vecs, true);

        println!("{:?}", write_pcap(tracer.payloads, "./new_3.pcap"));
    }

    #[test]
    fn assert_tcp_segment_pcap() {
        let mut tracer = L4Tracer::new(IPProtocol::TCP, 59231, 1234);
        let mut vecs: Vec<u8> = Vec::with_capacity(8880);
        for i in 0..8880 {
            let k = i % (0x0a as u16);
            vecs.push(k as u8);
        }

        tracer.send(&[0x41, 0x41, 0x41], false);
        tracer.send(&vecs, true);
        tracer.switch_direction(false);

        tracer.send(&[0x41, 0x41, 0x41], false);
        tracer.send(&vecs, true);

        println!("{:?}", write_pcap(tracer.payloads, "./new_4.pcap"));
    }

    #[test]
    fn assert_tcp_payload_vaildation() {
        let mut session = Session::create_tcp(48612, 502);
        session.l4_tcp_flags = TcpFlag::Ack | TcpFlag::Push;
        session.l4_tcp_acknowledgment = 90123456;
        session.l4_tcp_sequence = 12345678;

        session.assign_src_mac("00:18:7d:ff:77:3a");
        session.assign_dst_mac("00:18:7d:32:21:10");
        session.build(&[0x41, 0x41, 0x41]);

        assert_eq!(session.current_layer(), Layer::L4);
        let payload1 = session.payload().to_vec();
        assert_eq!(
            &payload1,
            &[
                0, 24, 125, 50, 33, 16, 0, 24, 125, 255, 119, 58, 8, 0, 69, 0, 0, 43, 171, 205, 0,
                0, 128, 6, 13, 74, 192, 168, 0, 1, 192, 168, 0, 100, 189, 228, 1, 246, 0, 188, 97,
                78, 5, 95, 44, 192, 80, 24, 2, 0, 85, 206, 0, 0, 65, 65, 65
            ]
        );

        // change payload & flags!
        session.l4_tcp_flags = TcpFlag::Ack.into();
        session.rebuild(&[]);
        let payload2 = session.payload().to_vec();

        assert_eq!(
            &payload2,
            &[
                0, 24, 125, 50, 33, 16, 0, 24, 125, 255, 119, 58, 8, 0, 69, 0, 0, 40, 171, 205, 0,
                0, 128, 6, 13, 77, 192, 168, 0, 1, 192, 168, 0, 100, 189, 228, 1, 246, 0, 188, 97,
                78, 5, 95, 44, 192, 80, 16, 2, 0, 216, 26, 0, 0
            ]
        );
    }
}
