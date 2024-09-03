use std::{
    collections::HashMap,
    sync::Mutex};

use lazy_static::lazy_static;
use rand::{seq::SliceRandom, Rng};

use crate::{
    general::{FragmentInfo, IPProtocol, Layer, TcpFlag, TcpOption},
    session::Session,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PresetQuirk {
    DontFragment,       // ipv4 only
    NonZeroIdWithDF,    // ipv4 only
    NonZeroIdWithoutDF, // ipv4 only
    UseEcn,
    ReservedNotZero, // ipv4 only
    HasFlow,         // ipv6 only
    SequenceNumberZero,
    AcknowledgeNumberNonZeroWithNoFlag,
    HasUrgentFlag,
    UrgentPointerNonZeroWithNoFlag,
    HasPushFlag,
    SynTimeStampZero,
    SynTimeStampNonZero,
    TcpOptionNonZero,
    Malformed,
    ExcessiveWindowScaling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PresetWindowSizeOp {
    Multiple,
    Div,
    Modular,
}

impl PresetWindowSizeOp {
    pub fn symbol(&self) -> char {
        match self {
            PresetWindowSizeOp::Multiple => '*',
            PresetWindowSizeOp::Div => '/',
            PresetWindowSizeOp::Modular => '%',
        }
    }

    pub fn calc<
        T: std::ops::Mul<Output = T> + std::ops::Div<Output = T> + std::ops::Rem<Output = T>,
    >(
        &self,
        t1: T,
        t2: T,
    ) -> T {
        match self {
            PresetWindowSizeOp::Multiple => t1 * t2,
            PresetWindowSizeOp::Div => t1 / t2,
            PresetWindowSizeOp::Modular => t1 % t2,
        }
    }
}

impl From<&str> for PresetWindowSizeOp {
    fn from(value: &str) -> Self {
        let value = value.trim();
        match value {
            "*" => Self::Multiple,
            "%" => Self::Modular,
            "/" => Self::Div,
            _ => panic!("Unknown Scale Operator symbol"),
        }
    }
}

impl From<String> for PresetWindowSizeOp {
    fn from(value: String) -> Self {
        let value = value.trim();
        match value {
            "*" => Self::Multiple,
            "%" => Self::Modular,
            "/" => Self::Div,
            _ => panic!("Unknown Scale Operator symbol"),
        }
    }
}

impl From<char> for PresetWindowSizeOp {
    fn from(value: char) -> Self {
        match value {
            '*' => Self::Multiple,
            '%' => Self::Modular,
            '/' => Self::Div,
            _ => panic!("Unknown Scale Operator symbol"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PresetWindowSize {
    MSS,
    Number(u16),
    Op(PresetWindowSizeOp),
}

//
//
// Interpret the signature information that p0f has and
// define metadata presets that can be reflected in the Session.
//
// The signature structure in p0f is as follows:
//
// sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
//
//   ver        - signature for IPv4 ('4'), IPv6 ('6'), or both ('*').
//
//                NEW SIGNATURES: P0f documents the protocol observed on the wire,
//                but you should replace it with '*' unless you have observed some
//                actual differences between IPv4 and IPv6 traffic, or unless the
//                software supports only one of these versions to begin with.
//
//   ittl       - initial TTL used by the OS. Almost all operating systems use
//                64, 128, or 255; ancient versions of Windows sometimes used
//                32, and several obscure systems sometimes resort to odd values
//                such as 60.
//
//                NEW SIGNATURES: P0f will usually suggest something, using the
//                format of 'observed_ttl+distance' (e.g. 54+10). Consider using
//                traceroute to check that the distance is accurate, then sum up
//                the values. If initial TTL can't be guessed, p0f will output
//                'nnn+?', and you need to use traceroute to estimate the '?'.
//
//                A handful of userspace tools will generate random TTLs. In these
//                cases, determine maximum initial TTL and then add a - suffix to
//                the value to avoid confusion.
//
//   olen       - length of IPv4 options or IPv6 extension headers. Usually zero
//                for normal IPv4 traffic; always zero for IPv6 due to the
//                limitations of libpcap.
//
//                NEW SIGNATURES: Copy p0f output literally.
//
//   mss        - maximum segment size, if specified in TCP options. Special value
//                of '*' can be used to denote that MSS varies depending on the
//                parameters of sender's network link, and should not be a part of
//                the signature. In this case, MSS will be used to guess the
//                type of network hookup according to the [mtu] rules.
//
//                NEW SIGNATURES: Use '*' for any commodity OSes where MSS is
//                around 1300 - 1500, unless you know for sure that it's fixed.
//                If the value is outside that range, you can probably copy it
//                literally.
//
//   wsize      - window size. Can be expressed as a fixed value, but many
//                operating systems set it to a multiple of MSS or MTU, or a
//                multiple of some random integer. P0f automatically detects these
//                cases, and allows notation such as 'mss*4', 'mtu*4', or '%8192'
//                to be used. Wilcard ('*') is possible too.
//
//                NEW SIGNATURES: Copy p0f output literally. If frequent variations
//                are seen, look for obvious patterns. If there are no patterns,
//                '*' is a possible alternative.
//
//   scale      - window scaling factor, if specified in TCP options. Fixed value
//                or '*'.
//
//                NEW SIGNATURES: Copy literally, unless the value varies randomly.
//                Many systems alter between 2 or 3 scaling factors, in which case,
//                it's better to have several 'sig' lines, rather than a wildcard.
//
//   olayout    - comma-delimited layout and ordering of TCP options, if any. This
//                is one of the most valuable TCP fingerprinting signals. Supported
//                values:
//
//                eol+n  - explicit end of options, followed by n bytes of padding
//                nop    - no-op option
//                mss    - maximum segment size
//                ws     - window scaling
//                sok    - selective ACK permitted
//                sack   - selective ACK (should not be seen)
//                ts     - timestamp
//                ?n     - unknown option ID n
//
//                NEW SIGNATURES: Copy this string literally.
//
//   quirks     - comma-delimited properties and quirks observed in IP or TCP
//                headers:
//
//                df     - "don't fragment" set (probably PMTUD); ignored for IPv6
//                id+    - DF set but IPID non-zero; ignored for IPv6
//                id-    - DF not set but IPID is zero; ignored for IPv6
//                ecn    - explicit congestion notification support
//                0+     - "must be zero" field not zero; ignored for IPv6
//                flow   - non-zero IPv6 flow ID; ignored for IPv4
//
//                seq-   - sequence number is zero
//                ack+   - ACK number is non-zero, but ACK flag not set
//                ack-   - ACK number is zero, but ACK flag set
//                uptr+  - URG pointer is non-zero, but URG flag not set
//                urgf+  - URG flag used
//                pushf+ - PUSH flag used
//
//                ts1-   - own timestamp specified as zero
//                ts2+   - non-zero peer timestamp on initial SYN
//                opt+   - trailing non-zero data in options segment
//                exws   - excessive window scaling factor (> 14)
//                bad    - malformed TCP options
//
//                If a signature scoped to both IPv4 and IPv6 contains quirks valid
//                for just one of these protocols, such quirks will be ignored for
//                on packets using the other protocol. For example, any combination
//                of 'df', 'id+', and 'id-' is always matched by any IPv6 packet.
//
//   pclass     - payload size classification: '0' for zero, '+' for non-zero,
//                '*' for any. The packets we fingerprint right now normally have
//                no payloads, but some corner cases exist.
//
#[derive(Debug, Clone)]
pub struct Preset {
    pub os_name: String,
    pub ip_version: u8,
    pub ttl: u8,
    pub ip_option_len: u8,
    pub mss: u16,
    pub window_size: Vec<PresetWindowSize>,
    pub window_scale: u8,
    pub tcp_option: Vec<TcpOption>,
    pub quirks: Vec<PresetQuirk>,
    pub payload_class: u8,
}

impl Preset {
    ///
    /// Creates a Preset instance that can be used to sign a Session,
    /// The fingerprint information is based on `p0f`.
    ///
    /// For more detailed fingerprint information, see below:
    /// https://blog.cloudflare.com/introducing-the-p0f-bpf-compiler/
    ///
    /// For example, The fingerprint is given with the following text:
    /// `
    /// "4:64:0:*:mss*10,6:mss,sok,ts,nop,ws:df,id+:0"
    /// `,
    ///
    /// if the following conditions are met, it can assume
    /// that it is a Linux operating system:
    ///
    /// ```shell
    /// ; ip: ip version
    /// ; (ip[8] <= 64): ttl <= 64
    /// ; (ip[8] > 29): ttl > 29
    /// ; ((ip[0] & 0xf) == 5): IP options len == 0
    /// ; (tcp[14:2] == (tcp[22:2] * 10)): win size == mss * 10
    /// ; (tcp[39:1] == 6): win scale == 6
    /// ; ((tcp[12] >> 4) == 10): TCP data offset
    /// ; (tcp[20] == 2): olayout mss
    /// ; (tcp[24] == 4): olayout sok
    /// ; (tcp[26] == 8): olayout ts
    /// ; (tcp[36] == 1): olayout nop
    /// ; (tcp[37] == 3): olayout ws
    /// ; ((ip[6] & 0x40) != 0): df set
    /// ; ((ip[6] & 0x80) == 0): mbz zero
    /// ; ((ip[2:2] - ((ip[0] & 0xf) * 4) - ((tcp[12] >> 4) * 4)) == 0): payload len == 0
    /// ```
    ///
    /// Presets the required components within a session to satisfy
    /// the above conditions. This gives the session its own operating
    /// system characteristics.
    ///
    /// ```rust
    /// use fpcaps::preset::Preset;
    ///
    /// let mut preset = Preset::new("Linux_3_1", "4:64:0:*:mss*10,6:mss,sok,ts,nop,ws:df,id+:0");
    /// // Todo...
    /// ```
    ///
    pub fn new(os_name: &str, sig: &str) -> Self {
        println!("os_name: {}, sig: {}", os_name, sig);
        let mut spliter = sig.split(":");
        let ip_version = Self::dissect_ip_version(spliter.next().unwrap());
        let ttl = Self::dissect_ttl(spliter.next().unwrap());
        let ip_option_len = Self::dissect_ip_option_len(spliter.next().unwrap());
        let mss = Self::dissect_mss(spliter.next().unwrap());

        let spliter_ws: Vec<&str> = spliter.next().unwrap().split(",").map(|k| k).collect();
        if spliter_ws.len() != 2 {
            panic!("Can't dissect window size & window scale");
        }

        let window_size = Self::dissect_window_size(spliter_ws[0]);
        let window_scale = Self::dissect_window_scale(spliter_ws[1]);

        let tcp_option = Self::dissect_tcp_options(spliter.next().unwrap());
        let quirks = Self::dissect_tcp_quirks(spliter.next().unwrap());

        let payload_class = if let Some(pc) = spliter.next() {
            Self::dissect_payload_class(pc)
        } else {
            0
        };
        Self {
            os_name: os_name.to_string(),
            ip_version,
            ttl,
            ip_option_len,
            mss,
            window_size,
            window_scale,
            tcp_option,
            quirks,
            payload_class,
        }
    }

    #[inline]
    fn dissect_ip_version(s: &str) -> u8 {
        match s {
            "4" => 4,
            "6" => 6,
            "*" => 10,
            _ => panic!("Can't dissect ip version"),
        }
    }

    #[inline]
    fn dissect_ttl(s: &str) -> u8 {
        match u8::from_str_radix(s, 10) {
            Ok(n) => {
                match n {
                    32 | 60 | 64 | 128 | 255 => n,
                    _ => {
                        println!("Warning: Non-standard TTL value: {}, (well-known TTL: 32/60/64/128/255)", n);
                        n
                    }
                }
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[inline]
    fn dissect_ip_option_len(s: &str) -> u8 {
        match u8::from_str_radix(s, 10) {
            Ok(n) => n,
            Err(e) => {
                panic!("{}", e);
            }
        }
    }

    #[inline]
    fn dissect_mss(s: &str) -> u16 {
        match s {
            "" | "*" => 0, // it means depends on MSS in TCP Option.
            k => match u16::from_str_radix(k, 10) {
                Ok(mss) => mss,
                Err(_) => {
                    panic!("Can't dissect MSS, given: {}", k);
                }
            },
        }
    }

    fn dissect_window_size(s: &str) -> Vec<PresetWindowSize> {
        if s == "" || s == "*" {
            let deft = PresetWindowSize::Number(0);
            return vec![deft];
        }

        if s.to_lowercase() == "mss" {
            let deft = PresetWindowSize::MSS;
            return vec![deft];
        }

        let find_symbol = |expr: &str| {
            let input = ['%', '/', '*'];
            for c in expr.chars() {
                if input.contains(&c) {
                    return Some(PresetWindowSizeOp::from(c));
                }
            }
            None
        };
        if let Some(symbol) = find_symbol(s) {
            let mut vecs = vec![];
            let mut k = s.split(symbol.symbol());
            let mut v = k.next();
            while v != None {
                if let Ok(n) = u16::from_str_radix(v.unwrap(), 10) {
                    vecs.push(PresetWindowSize::Number(n));
                } else {
                    if v.unwrap().to_lowercase() == "mss" {
                        vecs.push(PresetWindowSize::MSS);
                    }
                }
                v = k.next();
            }
            vecs.push(PresetWindowSize::Op(symbol));
            vecs
        } else {
            match u16::from_str_radix(s, 10) {
                Ok(n) => {
                    let deft = PresetWindowSize::Number(n);
                    vec![deft]
                }
                Err(_) => {
                    panic!(
                        "Can't convert number during dissecting window size, given: {}",
                        s
                    );
                }
            }
        }
    }

    #[inline]
    fn dissect_window_scale(s: &str) -> u8 {
        match s {
            "" | "*" => 0,
            k => match u8::from_str_radix(k, 10) {
                Ok(mss) => mss,
                Err(_) => {
                    panic!("Can't dissect window scale, given: {}", k);
                }
            },
        }
    }

    #[inline]
    fn dissect_tcp_options(s: &str) -> Vec<TcpOption> {
        if s == "" {
            return vec![];
        }
        let mut spliter = s.split(",");
        let mut string = spliter.next();
        let mut result = vec![];
        while string != None {
            let opt = match string.unwrap().to_lowercase().as_str() {
                "eol+n" => TcpOption::EndOfOptionList, // @@@ TODO: eol+n dissect
                "nop" => TcpOption::NoOperation,
                "mss" => TcpOption::MaximumSegmentSize(0),
                "ws" => TcpOption::WindowScale(0),
                "sok" => TcpOption::SACKPermitted,
                "sack" => TcpOption::SelectiveAcknowledgment(vec![]),
                "ts" => TcpOption::Timestamp(0, 0),
                "?n" => TcpOption::Unknown,
                _ => panic!("Can't dissect tcp option!"),
            };
            result.push(opt);
            string = spliter.next();
        }
        result
    }

    #[inline]
    fn dissect_tcp_quirks(s: &str) -> Vec<PresetQuirk> {
        // Maybe it is payload class, or empty.
        if s == "0" || s == "" {
            return vec![];
        }
        let mut spliter = s.split(",");
        let mut string = spliter.next();
        let mut result = vec![];
        while string != None {
            let preset_quirk = match string.unwrap().to_lowercase().as_str() {
                "df" => PresetQuirk::DontFragment,
                "id+" => PresetQuirk::NonZeroIdWithDF,
                "id-" => PresetQuirk::NonZeroIdWithoutDF,
                "ecn" => PresetQuirk::UseEcn,
                "0+" => PresetQuirk::ReservedNotZero,
                "flow" => PresetQuirk::HasFlow,
                "seq-" => PresetQuirk::SequenceNumberZero,
                "ack+" => PresetQuirk::AcknowledgeNumberNonZeroWithNoFlag,
                "uptr+" => PresetQuirk::UrgentPointerNonZeroWithNoFlag,
                "urgf+" => PresetQuirk::HasUrgentFlag,
                "pushf+" => PresetQuirk::HasPushFlag,
                "ts1-" => PresetQuirk::SynTimeStampZero,
                "ts2+" => PresetQuirk::SynTimeStampNonZero,
                "opt+" => PresetQuirk::TcpOptionNonZero,
                "exws" => PresetQuirk::ExcessiveWindowScaling,
                "bad" => PresetQuirk::Malformed,
                _ => panic!("Can't dissect quirks option, name: {:?}", string),
            };
            let opt = preset_quirk;
            result.push(opt);
            string = spliter.next();
        }
        result
    }

    #[inline]
    fn dissect_payload_class(s: &str) -> u8 {
        match s {
            "" | "*" => 0,
            k => match u8::from_str_radix(k, 10) {
                Ok(mss) => mss,
                Err(_) => {
                    panic!("Can't dissect payload class, given: {}", k);
                }
            },
        }
    }

    pub fn reflect_to_session(&self, flags: u8, sess: &mut Session) -> bool {
        match self.ip_version {
            4 if sess.is_ether_ipv6() => return false,
            6 if sess.is_ether_ipv4() => return false,
            10 => {} // don't case
            _ => return false,
        }

        if sess.current_layer() >= Layer::L3 {
            unsafe {
                sess.modify_l3_ipv4_ttl(self.ttl);
            }
        }

        //
        // @@@ TODO:
        //
        // IPv4 Option is not exist in fcaps default.
        // But need to modify them ..?
        //
        // self.ip_option_len = ??
        //

        let mut perent_mss = if self.mss != 0 {
            Some(TcpOption::MaximumSegmentSize(self.mss))
        } else {
            None
        };
        let perent_scale;

        // TCP Only!
        if sess.protocol == IPProtocol::TCP {
            if self.window_size.len() > 0 {
                let mut ops = None;
                let mut mss = None;
                let mut number = None;
                for element in &self.window_size {
                    match element {
                        PresetWindowSize::MSS => mss = Some(element.clone()),
                        PresetWindowSize::Number(n) => {
                            if n == &0 {
                                // disable them (equals "*")
                                break;
                            }
                            number = Some(element.clone());
                        }
                        PresetWindowSize::Op(element) => {
                            ops = Some(element.clone());
                        }
                    }
                }
                if let Some(_) = mss {
                    if perent_mss == None {
                        // mss is not defined, but need to mss ??
                        println!("MSS is not undefined, but window size need to MSS, use default");
                        perent_mss = Some(TcpOption::MaximumSegmentSize(1460));
                    }

                    if number != None {
                        sess.l4_tcp_window_size =
                            if let Some(TcpOption::MaximumSegmentSize(n)) = perent_mss {
                                // window size = MSS * scale.
                                if let Some(PresetWindowSize::Number(n2)) = number {
                                    if let Some(ops) = ops {
                                        ops.calc(n, n2)
                                    } else {
                                        panic!("Can't apply them, because The ops was not existed")
                                    }
                                } else {
                                    unreachable!()
                                }
                            } else {
                                unreachable!()
                            };
                    }
                } else {
                    if number != None {
                        // Window size is fixed
                        sess.l4_tcp_window_size = if let Some(PresetWindowSize::Number(n)) = number
                        {
                            n
                        } else {
                            unreachable!()
                        }
                    }
                }
            }

            if self.window_scale > 0 {
                perent_scale = Some(TcpOption::WindowScale(self.window_scale));
            } else {
                perent_scale = None;
            }

            if self.tcp_option.len() > 0 {
                // need to
                sess.clear_tcp_option(Some(flags));
                for ref mut opt in self.tcp_option.clone() {
                    match opt {
                        TcpOption::EndOfOptionList
                        | TcpOption::NoOperation
                        | TcpOption::SelectiveAcknowledgment(_)
                        | TcpOption::SACKPermitted => {
                            sess.assign_tcp_option(flags, opt.clone(), false);
                        }
                        TcpOption::Timestamp(_, _) => {
                            sess.assign_tcp_option(flags, opt.clone(), false);
                        }
                        TcpOption::MaximumSegmentSize(_) => {
                            if let Some(mss) = &perent_mss {
                                sess.assign_tcp_option(flags, mss.clone(), false);
                            // use perent
                            } else {
                                // mss is need to them, but perent MSS value is not exist
                                println!("Warning: Signature is not given MSS, but Option session is needed to it, use default");
                                sess.assign_tcp_option(
                                    flags,
                                    TcpOption::MaximumSegmentSize(1460),
                                    false,
                                );
                            }
                        }
                        TcpOption::WindowScale(_) => {
                            if let Some(ps) = &perent_scale {
                                sess.assign_tcp_option(flags, ps.clone(), false);
                            // use perent
                            } else {
                                // WS is need to them, but perent WS value is not exist
                                println!("Warning: Signature is not given Windows Scale, but Option session is needed to it, use default");
                                sess.assign_tcp_option(flags, TcpOption::WindowScale(2), false);
                            }
                        }
                        TcpOption::Unknown => {}
                    }
                }
            }
        }

        if self.quirks.len() > 0 {
            for quirk in &self.quirks {
                match quirk {
                    PresetQuirk::DontFragment => {
                        let fi: &FragmentInfo = &sess.l3_fragment;
                        if !fi.1 {
                            let mut fi_new = sess.l3_fragment.clone();
                            fi_new.1 = true;
                            sess.l3_fragment = fi_new;
                        }
                    }
                    PresetQuirk::NonZeroIdWithDF => {
                        let fi: &FragmentInfo = &sess.l3_fragment;
                        if !fi.1 {
                            let mut fi_new = sess.l3_fragment.clone();
                            fi_new.1 = true;
                            sess.l3_fragment = fi_new;
                        }
                        if sess.l3_ipv4_iden == 0 {
                            sess.l3_ipv4_iden = rand::thread_rng().gen();
                        }
                    }
                    PresetQuirk::NonZeroIdWithoutDF => {
                        let fi: &FragmentInfo = &sess.l3_fragment;
                        if fi.1 {
                            let mut fi_new = sess.l3_fragment.clone();
                            fi_new.1 = false;
                            sess.l3_fragment = fi_new;
                        }
                        if sess.l3_ipv4_iden != 0 {
                            sess.l3_ipv4_iden = 0;
                        }
                    }
                    PresetQuirk::UseEcn => {
                        //
                        // ECN uses 2 bits to indicate the state of the packet:
                        //
                        // 00: ECN not used (default)
                        // 01: ECN-capable transport (congestion notification supported)
                        // 10: Congestion experienced
                        // 11: Reservation status
                        //
                        sess.l3_ecn = 1;
                    }
                    PresetQuirk::HasFlow => {
                        // oh, need to set the flow value.
                        if sess.l3_ipv6_flow_label == 0 {
                            sess.l3_ipv4_iden = rand::thread_rng().gen();
                        }
                    }
                    PresetQuirk::SequenceNumberZero => {
                        if sess.l4_tcp_sequence != 0 {
                            sess.l4_tcp_sequence = 0;
                            println!("Warning: TCP Sequence number is zero, name:seq-");
                        }
                    }
                    PresetQuirk::AcknowledgeNumberNonZeroWithNoFlag => {
                        if sess.l4_tcp_acknowledgment == 0 {
                            println!("Warning: TCP Acknowledgment is not undefined, Set randomize, name:0+");
                            sess.l4_tcp_acknowledgment = rand::thread_rng().gen();
                        }

                        if sess.l4_tcp_flags & TcpFlag::Ack as u8 > 0 {
                            sess.l4_tcp_flags &= &0xEF;
                        }
                    }
                    PresetQuirk::HasUrgentFlag => {
                        if sess.l4_tcp_flags & TcpFlag::Urgent as u8 == 0 {
                            sess.l4_tcp_flags |= TcpFlag::Urgent as u8;
                        }
                    }
                    PresetQuirk::UrgentPointerNonZeroWithNoFlag => {
                        if sess.l4_tcp_urgent_ptr == 0 {
                            println!("Warning: TCP Acknowledgment is not undefined, Set randomize, name:uptr+");
                            sess.l4_tcp_urgent_ptr = rand::thread_rng().gen();
                        }
                        if sess.l4_tcp_flags & TcpFlag::Urgent as u8 > 0 {
                            sess.l4_tcp_flags &= 0xDF;
                        }
                    }
                    PresetQuirk::HasPushFlag => {
                        if sess.l4_tcp_flags & TcpFlag::Push as u8 == 0 {
                            sess.l4_tcp_flags |= TcpFlag::Push as u8;
                        }
                    }
                    PresetQuirk::Malformed => {
                        println!(
                            "Warning: Current TCP option will be cleared due to quirk! name:bad"
                        );
                        sess.clear_tcp_option(Some(flags));

                        /* Anomaly TCP option! */
                        sess.assign_tcp_option(flags, TcpOption::WindowScale(0), false);
                        sess.assign_tcp_option(flags, TcpOption::WindowScale(0), false);
                        sess.assign_tcp_option(flags, TcpOption::WindowScale(0), false);
                        sess.assign_tcp_option(flags, TcpOption::WindowScale(0), false);
                    }
                    PresetQuirk::ExcessiveWindowScaling => {
                        let mut found = false;
                        if let Some(v) = sess.current_tcp_option(flags) {
                            if v.len() > 0 {
                                for to in v {
                                    if let TcpOption::WindowScale(v) = to {
                                        found = true;
                                        if *v < 14 {
                                            *v = 15;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        if !found {
                            sess.assign_tcp_option(flags, TcpOption::WindowScale(15), false);
                        }
                    }
                    // PresetQuirk::SynTimeStampZero => {
                    //     // Initial SYN only
                    //     if flags == TcpFlag::Syn as u8 {

                    //     }
                    //     else {
                    //         println!("Warning: Some Quirk element is not relected because this case is not Initial SYN, name:ts1-");
                    //     }
                    // }
                    // PresetQuirk::SynTimeStampNonZero => todo!(),
                    // PresetQuirk::TcpOptionNonZero => todo!(),
                    _ => {
                        println!("Warning: Some Quirk element is not relected, {:?}", quirk); // what is it..?
                        return false;
                    }
                }
            }
        }
        true
    }
}

lazy_static! {
    pub static ref SYN_ACK_OS_PRESET_STR: Mutex<HashMap<String, Vec<String>>> = {
        let mut presets = HashMap::new();

        // Linux 3.x
        let vecs = vec![
            "*:64:0:*:mss*10,0:mss:df:0".to_string(),
            "*:64:0:*:mss*10,0:mss,sok,ts:df:0".to_string(),
            "*:64:0:*:mss*10,0:mss,nop,nop,ts:df:0".to_string(),
            "*:64:0:*:mss*10,0:mss,nop,nop,sok:df:0".to_string(),
            "*:64:0:*:mss*10,*:mss,nop,ws:df:0".to_string(),
            "*:64:0:*:mss*10,*:mss,sok,ts,nop,ws:df:0".to_string(),
            "*:64:0:*:mss*10,*:mss,nop,nop,ts,nop,ws:df:0".to_string(),
            "*:64:0:*:mss*10,*:mss,nop,nop,sok,nop,ws:df:0".to_string(),
        ];
        presets.insert("Linux_3_X".to_string(), vecs);

        // Linux 2.4-2.6
        let vecs = vec![
            "*:64:0:*:mss*4,0:mss:df:0".to_string(),
            "*:64:0:*:mss*4,0:mss,sok,ts:df:0".to_string(),
            "*:64:0:*:mss*4,0:mss,nop,nop,ts:df:0".to_string(),
            "*:64:0:*:mss*4,0:mss,nop,nop,sok:df:0".to_string(),
        ];
        presets.insert("Linux_2_4_2_6".to_string(), vecs);

        // Linux 2.4.x
        let vecs = vec![
            "*:64:0:*:mss*4,0:mss,nop,ws:df:0".to_string(),
            "*:64:0:*:mss*4,0:mss,sok,ts,nop,ws:df:0".to_string(),
            "*:64:0:*:mss*4,0:mss,nop,nop,ts,nop,ws:df:0".to_string(),
            "*:64:0:*:mss*4,0:mss,nop,nop,sok,nop,ws:df:0".to_string(),
        ];
        presets.insert("Linux_2_4_X".to_string(), vecs);

        // Linux 2.6.x
        let vecs = vec![
            "*:64:0:*:mss*4,*:mss,nop,ws:df:0".to_string(),
            "*:64:0:*:mss*4,*:mss,sok,ts,nop,ws:df:0".to_string(),
            "*:64:0:*:mss*4,*:mss,nop,nop,ts,nop,ws:df:0".to_string(),
            "*:64:0:*:mss*4,*:mss,nop,nop,sok,nop,ws:df:0".to_string(),
        ];
        presets.insert("Linux_2_6_X".to_string(), vecs);

        // Windows XP
        let vecs = vec![
            "*:128:0:*:65535,0:mss:df,id+:0".to_string(),
            "*:128:0:*:65535,0:mss,nop,ws:df,id+:0".to_string(),
            "*:128:0:*:65535,0:mss,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:65535,0:mss,nop,nop,ts:df,id+,ts1-:0".to_string(),
            "*:128:0:*:65535,0:mss,nop,ws,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:65535,0:mss,nop,ws,nop,nop,ts:df,id+,ts1-:0".to_string(),
            "*:128:0:*:65535,0:mss,nop,nop,ts,nop,nop,sok:df,id+,ts1-:0".to_string(),
            "*:128:0:*:65535,0:mss,nop,ws,nop,nop,ts,nop,nop,sok:df,id+,ts1-:0".to_string(),
            "*:128:0:*:16384,0:mss:df,id+:0".to_string(),
            "*:128:0:*:16384,0:mss,nop,ws:df,id+:0".to_string(),
            "*:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:16384,0:mss,nop,nop,ts:df,id+,ts1-:0".to_string(),
            "*:128:0:*:16384,0:mss,nop,ws,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:16384,0:mss,nop,ws,nop,nop,ts:df,id+,ts1-:0".to_string(),
            "*:128:0:*:16384,0:mss,nop,nop,ts,nop,nop,sok:df,id+,ts1-:0".to_string(),
            "*:128:0:*:16384,0:mss,nop,ws,nop,nop,ts,nop,nop,sok:df,id+,ts1-:0".to_string(),
        ];
        presets.insert("Windows_XP".to_string(), vecs);

        // Windows 7 or 8
        let vecs = vec![
            "*:128:0:*:8192,0:mss:df,id+:0".to_string(),
            "*:128:0:*:8192,0:mss,sok,ts:df,id+:0".to_string(),
            "*:128:0:*:8192,8:mss,nop,ws:df,id+:0".to_string(),
            "*:128:0:*:8192,0:mss,nop,nop,ts:df,id+:0".to_string(),
            "*:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:8192,8:mss,nop,ws,sok,ts:df,id+:0".to_string(),
            "*:128:0:*:8192,8:mss,nop,ws,nop,nop,ts:df,id+:0".to_string(),
            "*:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0".to_string(),
        ];
        presets.insert("Windows_7_8".to_string(), vecs);

        // FreeBSD 9.x
        let vecs = vec![
            "*:64:0:*:65535,6:mss,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:65535,6:mss,nop,ws,sok,ts:df,id+:0".to_string(),
            "*:64:0:*:65535,6:mss,nop,ws,nop,nop,ts:df,id+:0".to_string(),
        ];
        presets.insert("FreeBSD_9_X".to_string(), vecs);

        // FreeBSD 8.x
        let vecs = vec![
            "*:64:0:*:65535,3:mss,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:65535,3:mss,nop,ws,sok,ts:df,id+:0".to_string(),
            "*:64:0:*:65535,3:mss,nop,ws,nop,nop,ts:df,id+:0".to_string(),
        ];
        presets.insert("FreeBSD_8_X".to_string(), vecs);

        // FreeBSD 8.x-9.x
        let vecs = vec![
            "*:64:0:*:65535,0:mss,sok,ts:df,id+:0".to_string(),
            "*:64:0:*:65535,0:mss,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:65535,0:mss,nop,nop,ts:df,id+:0".to_string(),
            "*:64:0:*:65535,0:mss,nop,nop,sok:df,id+:0".to_string(),
        ];
        presets.insert("FreeBSD_8_9_X".to_string(), vecs);

        // MacOS X
        let vecs = vec![
            "*:64:0:*:65535,10:mss,sok,ts:df,id+:0".to_string(),
            "*:64:0:*:65535,10:mss,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:65535,10:mss,nop,nop,ts:df,id+:0".to_string(),
            "*:64:0:*:65535,10:mss,nop,nop,sok:df,id+:0".to_string(),
        ];
        presets.insert("MacOS_X".to_string(), vecs);

        // MacOS X (Lion)
        let vecs = vec![
            "*:64:0:*:65535,12:mss,sok,ts:df,id+:0".to_string(),
            "*:64:0:*:65535,12:mss,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:65535,12:mss,nop,nop,ts:df,id+:0".to_string(),
            "*:64:0:*:65535,12:mss,nop,nop,sok:df,id+:0".to_string(),
        ];
        presets.insert("MacOS_X_Lion".to_string(), vecs);

        // AIX 7.x
        let vecs = vec![
            "*:60:0:*:65535,0:mss:df,id+:0".to_string(),
            "*:60:0:*:65535,0:mss,nop,ws:df,id+:0".to_string(),
            "*:60:0:*:65535,0:mss,nop,nop,ts:df,id+:0".to_string(),
            "*:60:0:*:65535,0:mss,nop,nop,sok:df,id+:0".to_string(),
        ];
        presets.insert("AIX_7_X".to_string(), vecs);

        // AIX 5.x or 6.x
        let vecs = vec![
            "*:60:0:*:65535,0:mss:df,id+:0".to_string(),
            "*:60:0:*:65535,0:mss,nop,ws:df,id+:0".to_string(),
            "*:60:0:*:65535,0:mss,nop,nop,ts:df,id+:0".to_string(),
            "*:60:0:*:65535,0:mss,nop,nop,sok:df,id+:0".to_string(),
        ];
        presets.insert("AIX_5_6_X".to_string(), vecs);

        // Solaris 10
        let vecs = vec![
            "*:64:0:*:mss*4,0:mss,nop,ws:df:0".to_string(),
            "*:64:0:*:mss*4,0:mss,nop,nop,ts:df:0".to_string(),
            "*:64:0:*:mss*4,0:mss,nop,nop,sok:df:0".to_string(),
            "*:64:0:*:mss*4,0:mss,nop,nop,sok,ts:df:0".to_string(),
        ];
        presets.insert("Solaris_10".to_string(), vecs);

        // HPUX 11.x
        let vecs = vec![
            "*:64:0:*:mss*2,0:mss,nop,ws:0".to_string(),
            "*:64:0:*:mss*2,0:mss,nop,nop,ts:0".to_string(),
            "*:64:0:*:mss*2,0:mss,nop,nop,sok:0".to_string(),
            "*:64:0:*:mss*2,0:mss,nop,nop,sok,ts:0".to_string(),
        ];
        presets.insert("HPUX_11_X".to_string(), vecs);

        // Windows 2000
        let vecs = vec![
            "*:128:0:*:8192,0:mss,nop,ws:df,id+:0".to_string(),
            "*:128:0:*:8192,0:mss,nop,nop,ts:df,id+:0".to_string(),
            "*:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:8192,0:mss,nop,nop,sok,ts:df,id+:0".to_string(),
        ];
        presets.insert("Windows_2000".to_string(), vecs);

        // Windows NT
        let vecs = vec![
            "*:128:0:*:8192,0:mss:df,id+:0".to_string(),
            "*:128:0:*:8192,0:mss,nop,ws:df,id+:0".to_string(),
            "*:128:0:*:8192,0:mss,nop,nop,ts:df,id+:0".to_string(),
            "*:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0".to_string(),
        ];
        presets.insert("Windows_NT".to_string(), vecs);

        Mutex::new(presets)
    };

    pub static ref SYN_OS_PRESET_STR: Mutex<HashMap<String, Vec<String>>> = {
        let mut presets = HashMap::new();

        // Linux 3.11 and newer
        let vecs = vec![
            "*:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Linux_3_11_and_newer".to_string(), vecs);

        // Linux 3.1-3.10
        let vecs = vec![
            "*:64:0:*:mss*10,4:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*10,5:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*10,6:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*10,7:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Linux_3_1_to_3_10".to_string(), vecs);

        // Linux 2.6.x
        let vecs = vec![
            "*:64:0:*:mss*4,6:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*4,7:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*4,8:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Linux_2_6_x".to_string(), vecs);

        // Linux 2.4.x
        let vecs = vec![
            "*:64:0:*:mss*4,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*4,1:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*4,2:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Linux_2_4_x".to_string(), vecs);

        // Linux 2.2.x
        let vecs = vec![
            "*:64:0:*:mss*11,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*20,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*22,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Linux_2_2_x".to_string(), vecs);

        // Linux 2.0
        let vecs = vec![
            "*:64:0:*:mss*12,0:mss::0".to_string(),
            "*:64:0:*:16384,0:mss::0".to_string(),
        ];
        presets.insert("Linux_2_0".to_string(), vecs);

        // Linux 3.x (loopback)
        let vecs = vec![
            "*:64:0:16396:mss*2,4:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:16376:mss*2,4:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Linux_3_x_loopback".to_string(), vecs);

        // Linux 2.6.x (loopback)
        let vecs = vec![
            "*:64:0:16396:mss*2,2:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:16376:mss*2,2:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Linux_2_6_x_loopback".to_string(), vecs);

        // Linux 2.4.x (loopback)
        let vecs = vec![
            "*:64:0:16396:mss*2,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Linux_2_4_x_loopback".to_string(), vecs);

        // Linux 2.2.x (loopback)
        let vecs = vec![
            "*:64:0:3884:mss*8,0:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Linux_2_2_x_loopback".to_string(), vecs);

        // Linux 2.6.x (Google crawler)
        let vecs = vec![
            "4:64:0:1430:mss*4,6:mss,sok,ts,nop,ws::0".to_string(),
        ];
        presets.insert("Linux_2_6_x_Google_crawler".to_string(), vecs);

        // Linux (Android)
        let vecs = vec![
            "*:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:*:mss*44,3:mss,sok,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Linux_Android".to_string(), vecs);

        // Windows XP
        let vecs = vec![
            "*:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:65535,0:mss,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:65535,0:mss,nop,ws,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:65535,1:mss,nop,ws,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:65535,2:mss,nop,ws,nop,nop,sok:df,id+:0".to_string(),
        ];
        presets.insert("Windows_XP".to_string(), vecs);

        // Windows 7 or 8
        let vecs = vec![
            "*:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0".to_string(),
            "*:128:0:*:8192,2:mss,nop,ws,sok,ts:df,id+:0".to_string(),
        ];
        presets.insert("Windows_7_or_8".to_string(), vecs);

        // Windows 7 (Websense crawler)
        let vecs = vec![
            "*:64:0:1380:mss*4,6:mss,nop,nop,ts,nop,ws:df,id+:0".to_string(),
            "*:64:0:1380:mss*4,7:mss,nop,nop,ts,nop,ws:df,id+:0".to_string(),
        ];
        presets.insert("Windows_7_Websense_crawler".to_string(), vecs);

        // FreeBSD 9.x or newer
        let vecs = vec![
                    "*:64:0:*:65535,6:mss,nop,ws,sok,ts:df,id+:0".to_string(),    ];
        presets.insert("FreeBSD_9_x_or_newer".to_string(), vecs);

        // FreeBSD 8.x
        let vecs = vec![        "*:64:0:*:65535,3:mss,nop,ws,sok,ts:df,id+:0".to_string(),    ];
        presets.insert("FreeBSD_8_x".to_string(), vecs);

        // OpenBSD 3.x
        let vecs = vec![        "*:64:0:*:16384,0:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+:0".to_string(),    ];
        presets.insert("OpenBSD_3_x".to_string(), vecs);

        // OpenBSD 4.x-5.x
        let vecs = vec![        "*:64:0:*:16384,3:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+:0".to_string(),    ];
        presets.insert("OpenBSD_4_x_to_5_x".to_string(), vecs);

        // Solaris 8
        let vecs = vec![        "*:64:0:*:32850,1:nop,ws,nop,nop,ts,nop,nop,sok,mss:df,id+:0".to_string(),    ];
        presets.insert("Solaris_8".to_string(), vecs);

        // Solaris 10
        let vecs = vec![        "*:64:0:*:mss*34,0:mss,nop,ws,nop,nop,sok:df,id+:0".to_string(),    ];
        presets.insert("Solaris_10".to_string(), vecs);

        // OpenVMS 8.x
        let vecs = vec![        "4:128:0:1460:mtu*2,0:mss,nop,ws::0".to_string(),    ];
        presets.insert("OpenVMS_8_x".to_string(), vecs);

        // OpenVMS 7.x
        let vecs = vec![        "4:64:0:1460:61440,0:mss,nop,ws::0".to_string(),    ];
        presets.insert("OpenVMS_7_x".to_string(), vecs);

        // NeXTSTEP
        let vecs = vec![        "4:64:0:1024:mss*4,0:mss::0".to_string(),    ];
        presets.insert("NeXTSTEP".to_string(), vecs);

        // Tru64 4.x
        let vecs = vec![        "4:64:0:1460:32768,0:mss,nop,ws:df,id+:0".to_string(),    ];
        presets.insert("Tru64_4_x".to_string(), vecs);

        Mutex::new(presets)
    };

    pub static ref SYN_ACK_OS_PRESET: Mutex<HashMap<String, Vec<Preset>>> = {
        let mut presets = HashMap::new();
        if let Ok(presets_str) = SYN_ACK_OS_PRESET_STR.lock() {
            for (os_name, v) in presets_str.iter() {
                let mut vecs = vec![];
                for v2 in v {
                    vecs.push(Preset::new(os_name, v2));
                }
                presets.insert(os_name.to_string(), vecs);
            }
        }
        Mutex::new(presets)
    };


    pub static ref SYN_OS_PRESET: Mutex<HashMap<String, Vec<Preset>>> = {
        let mut presets = HashMap::new();
        if let Ok(presets_str) = SYN_OS_PRESET_STR.lock() {
            for (os_name, v) in presets_str.iter() {
                let mut vecs = vec![];
                for v2 in v {
                    vecs.push(Preset::new(os_name, v2));
                }
                presets.insert(os_name.to_string(), vecs);
            }
        }
        Mutex::new(presets)
    };

}

pub fn catch_syn_fp_preset(os_name: &str) -> Option<Preset> {
    if let Ok(presets) = SYN_OS_PRESET.lock() {
        if let Some(v) = presets.get(os_name) {
            let mut rng = rand::thread_rng();
            Some(v.choose(&mut rng).unwrap().clone())
        } else {
            None
        }
    } else {
        None
    }
}

pub fn catch_syn_ack_fp_preset(os_name: &str) -> Option<Preset> {
    if let Ok(presets) = SYN_ACK_OS_PRESET.lock() {
        if let Some(v) = presets.get(os_name) {
            let mut rng = rand::thread_rng();
            Some(v.choose(&mut rng).unwrap().clone())
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use super::Preset;
    use crate::preset::PresetWindowSize;
    use crate::preset::PresetWindowSizeOp;

    #[test]
    fn dissect_window_size_test() {
        let result = Preset::dissect_window_size("MSS");
        assert_eq!(vec![PresetWindowSize::MSS], result);

        let result = Preset::dissect_window_size("MSS*1024");
        assert_eq!(
            vec![
                PresetWindowSize::MSS,
                PresetWindowSize::Number(1024),
                PresetWindowSize::Op(PresetWindowSizeOp::Multiple)
            ],
            result
        );

        let result = Preset::dissect_window_size("8192");
        assert_eq!(vec![PresetWindowSize::Number(8192)], result);

        let result = Preset::dissect_window_size("mss%256");
        assert_eq!(
            vec![
                PresetWindowSize::MSS,
                PresetWindowSize::Number(256),
                PresetWindowSize::Op(PresetWindowSizeOp::Modular)
            ],
            result
        );

        let result = Preset::dissect_window_size("*");
        assert_eq!(vec![PresetWindowSize::Number(0)], result);
    }

    #[test]
    fn dissect_all() {
        let given = "4:64:0:*:mss*10,6:mss,sok,ts,nop,ws:df,id+:0";
        let linux_preset = Preset::new("Linux", given);
        let expected = "Preset { os_name: \"Linux\", ip_version: 4, ttl: 64, \
        ip_option_len: 0, mss: 0, window_size: [MSS, Number(10), Op(Multiple)], \
        window_scale: 6, tcp_option: [MaximumSegmentSize(0), SACKPermitted, \
        Timestamp(0, 0), NoOperation, WindowScale(0)], quirks: [DontFragment, \
        NonZeroIdWithDF], payload_class: 0 }";
        println!("{:#?}", linux_preset);
        assert_eq!(format!("{:?}", linux_preset), expected);
    }

    #[test]
    fn dissect_windows() {
        let mut vecs = vec![];
        vecs.push("*:128:0:*:16384,0:mss,nop,nop,sok:df");
        vecs.push("*:128:0:*:65535,0:mss,nop,nop,sok:df");
        vecs.push("*:128:0:*:65535,0:mss,nop,ws,nop,nop,sok:df");
        vecs.push("*:128:0:*:65535,1:mss,nop,ws,nop,nop,sok:df");
        vecs.push("*:128:0:*:65535,2:mss,nop,ws,nop,nop,sok:df");
        vecs.push("*:128:0:*:8192,0:mss,nop,nop,sok:df");
        vecs.push("*:128:0:*:8192,2:mss,nop,ws,nop,nop,sok:df");
        vecs.push("*:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df");
        vecs.push("*:128:0:*:8192,2:mss,nop,ws,sok,ts:df");
        vecs.push("*:64:0:1380:mss*4,6:mss,nop,nop,ts,nop,ws:df");
        vecs.push("*:64:0:1380:mss*4,7:mss,nop,nop,ts,nop,ws:df");
        vecs.push("*:128:0:*:16384,*:mss,nop,nop,sok:df");
        vecs.push("*:128:0:*:65535,*:mss,nop,nop,sok:df");
        vecs.push("*:128:0:*:16384,*:mss,nop,ws,nop,nop,sok:df");
        vecs.push("*:128:0:*:65535,*:mss,nop,ws,nop,nop,sok:df");
        vecs.push("*:128:0:*:8192,*:mss,nop,nop,sok:df");
        vecs.push("*:128:0:*:8192,*:mss,nop,ws,nop,nop,sok:df");
        vecs.push("*:128:0:*:*,*:mss,nop,nop,sok:df");
        vecs.push("*:128:0:*:*,*:mss,nop,ws,nop,nop,sok:df");

        for (idx, v) in vecs.iter().enumerate() {
            println!("start at {} for Windows Signature, sig={}", idx, v);
            let result = Preset::new("Some Windows", v);
            println!("{:?}", result);
        }
    }
}
