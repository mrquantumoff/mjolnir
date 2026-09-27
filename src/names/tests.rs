use super::*;

fn name(bytes: &[u8]) -> WireName {
    WireName::new(bytes.to_vec()).unwrap()
}

fn wide(local: &LocalName) -> &[u16] {
    match local {
        LocalName::Windows(w) => w,
        other => panic!("expected a Windows name, got {other:?}"),
    }
}

fn round_trip(bytes: &[u8], platform: Platform) -> Vec<u8> {
    decode_local(&encode_local(&name(bytes), platform))
}

const TRICKY: &[&[u8]] = &[
    b"plain.txt",
    b"\xff\xfe invalid",
    b"half \xe2\x82",
    b"a:b",
    b"back\\slash",
    b"trailing.",
    b"trailing ",
    b"dots...",
    b"CON",
    b"con",
    b"aux.txt",
    b"Com1.tar.gz",
    b"lpt9",
    b"NUL .txt",
    "COM\u{B9}".as_bytes(),
    b"CONIN$",
    b"\x01\x1fctl",
    b"q?\"<>|*",
    "emoji \u{1F600}".as_bytes(),
    "caf\u{E9}".as_bytes(),
    "literal \u{F03A} escape".as_bytes(),
    "\u{F0FF}".as_bytes(),
    b"surrogate \xed\xa0\x80 lone",
    b"pair \xed\xa0\x80\xed\xb0\x80 cesu",
    b"trail \xed\xb0\x80",
    b"overlong \xc0\xaf",
];

#[test]
fn every_platform_round_trips_tricky_names() {
    for &bytes in TRICKY {
        for platform in [Platform::Unix, Platform::MacOs, Platform::Windows] {
            assert_eq!(
                round_trip(bytes, platform),
                bytes,
                "{platform:?} {:?}",
                bytes.escape_ascii().to_string()
            );
        }
    }
}

#[test]
fn unix_to_windows_to_unix() {
    for &bytes in TRICKY {
        let unix = LocalName::Unix(bytes.to_vec());
        let on_windows = encode_local(&name(&decode_local(&unix)), Platform::Windows);
        let back = encode_local(&name(&decode_local(&on_windows)), Platform::Unix);
        assert_eq!(back, unix);
    }
}

#[test]
fn unix_to_macos_to_unix() {
    for &bytes in TRICKY {
        let unix = LocalName::Unix(bytes.to_vec());
        let on_mac = encode_local(&name(&decode_local(&unix)), Platform::MacOs);
        let LocalName::MacOs(mac_bytes) = &on_mac else {
            unreachable!()
        };
        assert!(std::str::from_utf8(mac_bytes).is_ok());
        let back = encode_local(&name(&decode_local(&on_mac)), Platform::Unix);
        assert_eq!(back, unix);
    }
}

#[test]
fn windows_unpaired_surrogate_to_unix_to_windows() {
    for original in [
        vec![0x61, 0xD800, 0x62],
        vec![0xDC00],
        vec![0xD800, 0xD800],
        vec![0xDBFF, 0x41, 0xDFFF],
    ] {
        let windows = LocalName::Windows(original);
        let on_unix = encode_local(&name(&decode_local(&windows)), Platform::Unix);
        let back = encode_local(&name(&decode_local(&on_unix)), Platform::Windows);
        assert_eq!(back, windows);
    }
}

#[test]
fn windows_escapes_follow_the_spec() {
    let cases: &[(&[u8], &str)] = &[
        (b"a:b", "a\u{F03A}b"),
        (b"x.", "x\u{F02E}"),
        (b"x ", "x\u{F020}"),
        (b"x.y", "x.y"),
        (b"CON", "\u{F043}ON"),
        (b"aux.txt", "\u{F061}ux.txt"),
        (b"CONSOLE", "CONSOLE"),
        (b"COM0", "COM0"),
        (b"COM10", "COM10"),
        (b"\x01", "\u{F001}"),
        (b"\xff", "\u{F0FF}"),
        ("\u{F03A}".as_bytes(), "\u{F0EF}\u{F080}\u{F0BA}"),
    ];
    for &(bytes, want) in cases {
        let got = encode_local(&name(bytes), Platform::Windows);
        assert_eq!(
            String::from_utf16(wide(&got)).unwrap(),
            want,
            "{}",
            bytes.escape_ascii()
        );
    }
}

#[test]
fn literal_escapes_do_not_collide_with_escaped_bytes() {
    let pairs: &[(&[u8], &[u8])] = &[
        (b"a:", "a\u{F03A}".as_bytes()),
        (b"\xff", "\u{F0FF}".as_bytes()),
    ];
    for &(a, b) in pairs {
        for platform in [Platform::MacOs, Platform::Windows] {
            assert_ne!(
                encode_local(&name(a), platform),
                encode_local(&name(b), platform)
            );
        }
    }
}

#[test]
fn parse_rejects_bad_paths() {
    let err = |parts: &[&[u8]]| WirePath::parse(parts.iter().copied()).unwrap_err();
    let at = |parts: &[&[u8]], index: usize, reason: NameReason| {
        let e = err(parts);
        assert_eq!(e.reason, reason, "{e}");
        assert_eq!(e.component.as_ref().map(|(i, _)| *i), Some(index), "{e}");
    };
    assert_eq!(err(&[]).reason, NameReason::EmptyPath);
    at(&[b"a", b""], 1, NameReason::Empty);
    at(&[b"."], 0, NameReason::Dot);
    at(&[b"a", b".."], 1, NameReason::DotDot);
    at(&[b"a\0b"], 0, NameReason::Nul);
    at(&[b"a/b"], 0, NameReason::Slash);
    at(
        &[b"f.mjolnir-part"],
        0,
        NameReason::ReservedSuffix(".mjolnir-part"),
    );
    at(
        &[b"dir.MJOLNIR-STATE", b"x"],
        0,
        NameReason::ReservedSuffix(".mjolnir-state"),
    );
    at(
        &[b"x.mjolnir-state.tmp"],
        0,
        NameReason::ReservedSuffix(".mjolnir-state.tmp"),
    );
    at(
        &[b"x.mjolnir-sums"],
        0,
        NameReason::ReservedSuffix(".mjolnir-sums"),
    );
    let deep = vec![b"d".as_slice(); MAX_COMPONENTS + 1];
    assert_eq!(
        err(&deep).reason,
        NameReason::TooManyComponents(MAX_COMPONENTS + 1)
    );
    let long = vec![b"x".repeat(2048), b"y".repeat(2048)];
    assert_eq!(
        WirePath::parse(long).unwrap_err().reason,
        NameReason::TooLong(4097)
    );

    assert!(WirePath::parse(vec![b"d".as_slice(); MAX_COMPONENTS]).is_ok());
    assert!(WirePath::parse([b"x".repeat(2047), b"y".repeat(2048)]).is_ok());
    assert!(WirePath::parse(["...", "mjolnir-part", "a.mjolnir-partx"]).is_ok());
}

#[test]
fn deserializing_validates() {
    let good = WirePath::parse([b"dir".as_slice(), b"\xff:x"]).unwrap();
    let bytes = postcard::to_stdvec(&good).unwrap();
    assert_eq!(bytes, b"\x02\x03dir\x03\xff:x");
    assert_eq!(postcard::from_bytes::<WirePath>(&bytes).unwrap(), good);

    for bad in [&b"\x01\x02.."[..], b"\x00", b"\x01\x00", b"\x01\x03a/b"] {
        assert!(postcard::from_bytes::<WirePath>(bad).is_err());
    }
}

#[test]
fn fold_key_is_case_insensitive_and_platform_independent() {
    let key = |parts: &[&[u8]]| WirePath::parse(parts.iter().copied()).unwrap().fold_key();
    assert_eq!(key(&[b"Dir", b"README"]), key(&[b"dir", b"readme"]));
    assert_eq!(key(&[b"CON"]), key(&[b"con"]));
    assert_ne!(key(&[b"\xff"]), key(&["\u{F0FF}".as_bytes()]));
    assert_ne!(key(&[b"\xff"]), key(&[b"\xfe"]));
}

#[test]
fn display_is_lossy() {
    let p = WirePath::parse([b"d".as_slice(), b"\xffx"]).unwrap();
    assert_eq!(p.display(), "d/\u{FFFD}x");
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const FRAGMENTS: &[&[u8]] = &[
    b".",
    b" ",
    b":",
    b"\\",
    b"a",
    b"CON",
    b"aux",
    b"com7",
    b"LpT",
    "\u{B3}".as_bytes(),
    b"\xed\xa0\x80",
    b"\xed\xb0\x80",
    b"\xed\xbf\xbf",
    "\u{F02E}".as_bytes(),
    "\u{F001}".as_bytes(),
    "\u{F000}".as_bytes(),
    "\u{1F600}".as_bytes(),
    "\u{E9}".as_bytes(),
    b"\xe2\x82",
    b"\xf0\x9f",
];

fn random_name(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..1 + rng.below(8) {
        if rng.below(3) == 0 {
            out.push(1 + rng.below(255) as u8);
        } else {
            out.extend_from_slice(FRAGMENTS[rng.below(FRAGMENTS.len())]);
        }
    }
    out.retain(|&b| b != b'/');
    out
}

fn assert_safe_on_windows(bytes: &[u8], w: &[u16]) {
    let shown = bytes.escape_ascii().to_string();
    for &u in w {
        assert!(u >= 0x20, "control char in {shown}");
        let forbidden = "\\/:*?\"<>|".encode_utf16().any(|r| r == u);
        assert!(!forbidden, "reserved char in {shown}");
    }
    let last = *w.last().unwrap();
    assert!(
        last != u16::from(b'.') && last != u16::from(b' '),
        "{shown}"
    );
    let text = String::from_utf16_lossy(w);
    assert!(!is_device_stem(windows_stem(&text)), "device name {shown}");
}

#[test]
fn random_names_round_trip_and_are_safe_on_windows() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut tested = 0;
    for _ in 0..50_000 {
        let bytes = random_name(&mut rng);
        let Ok(wire) = WireName::new(bytes.clone()) else {
            continue;
        };
        tested += 1;
        for platform in [Platform::Unix, Platform::MacOs, Platform::Windows] {
            let local = encode_local(&wire, platform);
            assert_eq!(decode_local(&local), bytes, "{platform:?}");
            match &local {
                LocalName::MacOs(b) => assert!(std::str::from_utf8(b).is_ok()),
                LocalName::Windows(w) => assert_safe_on_windows(&bytes, w),
                LocalName::Unix(_) => {}
            }
        }
    }
    assert!(tested > 40_000);
}

#[test]
fn from_os_path_rejects_non_relative_paths() {
    let e = WirePath::from_os_path(Path::new("a/../b")).unwrap_err();
    assert_eq!(e.reason, NameReason::NotRelative);
    assert_eq!(e.component.map(|(i, _)| i), Some(1));
    assert!(WirePath::from_os_path(Path::new("")).is_err());
}

fn create_and_list(names: &[&[u8]]) {
    let dir = tempfile::tempdir().unwrap();
    for &bytes in names {
        let local = WirePath::parse([bytes]).unwrap().to_local_path(dir.path());
        std::fs::write(&local, bytes).unwrap();
        assert!(local.exists(), "{}", bytes.escape_ascii());
        assert_eq!(std::fs::read(&local).unwrap(), bytes);
    }
    let sub: &[u8] = b"sub:dir.";
    let nested = WirePath::parse([sub, names[0]]).unwrap();
    let local = nested.to_local_path(dir.path());
    std::fs::create_dir(local.parent().unwrap()).unwrap();
    std::fs::write(&local, b"nested").unwrap();
    let rel = local.strip_prefix(local_base(dir.path())).unwrap();
    assert_eq!(WirePath::from_os_path(rel).unwrap(), nested);

    let mut found: Vec<Vec<u8>> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| {
            let file_name = e.unwrap().file_name();
            let path = WirePath::from_os_path(Path::new(&file_name)).unwrap();
            path.components()[0].as_bytes().to_vec()
        })
        .collect();
    found.sort();
    let mut want: Vec<Vec<u8>> = names.iter().chain([&sub]).map(|n| n.to_vec()).collect();
    want.sort();
    assert_eq!(found, want);
}

#[cfg(windows)]
#[test]
fn windows_creates_hostile_names() {
    let base = tempfile::tempdir().unwrap();
    let local = WirePath::parse(["x"]).unwrap().to_local_path(base.path());
    assert!(local.as_os_str().to_string_lossy().starts_with(r"\\?\"));
    create_and_list(&[
        b"a:b",
        b"x.",
        b"CON",
        b"aux.txt",
        b"trailing ",
        b"\xff\xfe non-utf8",
        b"q?\"<>|*\\",
        b"\x01ctl",
        b"lone \xed\xa0\x80",
    ]);
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn unix_creates_non_utf8_names() {
    create_and_list(&[
        b"\xff\xfe non-utf8",
        b"a:b\\c",
        b"x.",
        b"CON",
        b"lone \xed\xa0\x80",
        "literal \u{F03A}".as_bytes(),
    ]);
}
