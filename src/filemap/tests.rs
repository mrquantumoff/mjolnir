use std::fs;

use super::*;

fn wp(parts: &[&str]) -> WirePath {
    WirePath::parse(parts.iter().copied()).unwrap()
}

/// Stands in for the receiver renaming each file into place: the bytes
/// arrive, the metadata comes only from `apply`.
fn deliver(captured: &Captured, out: &Path) {
    for f in &captured.files {
        let dest = f.path.to_local_path(out);
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(&dest, fs::read(&f.source).unwrap()).unwrap();
    }
}

fn paths(captured: &Captured) -> Vec<(String, EntryKind)> {
    captured
        .map
        .entries
        .iter()
        .map(|e| (e.path.display(), e.kind))
        .collect()
}

/// `src/tree/{a/b/c/deep.txt, a/top.txt, empty/}` plus a file root.
fn sample_tree() -> (tempfile::TempDir, Vec<PathBuf>) {
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    fs::create_dir_all(tree.join("a/b/c")).unwrap();
    fs::create_dir_all(tree.join("empty")).unwrap();
    fs::write(tree.join("a/b/c/deep.txt"), b"deep").unwrap();
    fs::write(tree.join("a/top.txt"), b"top").unwrap();
    fs::write(tmp.path().join("single.bin"), b"single").unwrap();
    let roots = vec![tree, tmp.path().join("single.bin")];
    (tmp, roots)
}

#[test]
fn capture_names_roots_like_the_sender() {
    let (_tmp, roots) = sample_tree();
    let captured = capture(&roots, Preserve::default()).unwrap();
    let file = |id| EntryKind::File { file_id: id };
    assert_eq!(
        paths(&captured),
        [
            ("tree".into(), EntryKind::Dir),
            ("tree/a".into(), EntryKind::Dir),
            ("tree/a/b".into(), EntryKind::Dir),
            ("tree/a/b/c".into(), EntryKind::Dir),
            ("tree/a/b/c/deep.txt".into(), file(0)),
            ("tree/a/top.txt".into(), file(1)),
            ("tree/empty".into(), EntryKind::Dir),
            ("single.bin".into(), file(2)),
        ]
    );
    let files: Vec<_> = captured
        .files
        .iter()
        .map(|f| (f.path.display(), f.size))
        .collect();
    assert_eq!(
        files,
        [
            ("tree/a/b/c/deep.txt".into(), 4),
            ("tree/a/top.txt".into(), 3),
            ("single.bin".into(), 6),
        ]
    );
    assert!(captured.files.iter().all(|f| f.mtime > 0));
    let offer: Vec<_> = captured.files.iter().map(|f| f.path.clone()).collect();
    captured.map.check(&offer).unwrap();
    assert!(captured.skipped.is_empty());
}

#[test]
fn capture_then_apply_recreates_the_tree_and_is_idempotent() {
    let (tmp, roots) = sample_tree();
    let captured = capture(&roots, Preserve::default()).unwrap();
    let out = tmp.path().join("out");
    fs::create_dir(&out).unwrap();
    deliver(&captured, &out);
    assert!(!out.join("tree/empty").exists());

    for _ in 0..2 {
        assert_eq!(
            apply(&captured.map, &out, ApplyPolicy::default()),
            Vec::<String>::new()
        );
        assert!(out.join("tree/empty").is_dir());
        assert_eq!(fs::read(out.join("tree/a/b/c/deep.txt")).unwrap(), b"deep");
        assert_eq!(fs::read(out.join("single.bin")).unwrap(), b"single");
    }
}

#[test]
fn preserve_none_still_recreates_directories() {
    let (tmp, roots) = sample_tree();
    let captured = capture(&roots, Preserve::NONE).unwrap();
    assert!(
        captured.map.entries.iter().all(|e| e.mode.is_none()
            && e.mtime.is_none()
            && e.atime.is_none()
            && e.owner.is_none())
    );
    let out = tmp.path().join("out");
    deliver(&captured, &out);
    assert!(apply(&captured.map, &out, ApplyPolicy::default()).is_empty());
    assert!(out.join("tree/empty").is_dir());
    assert!(out.join("tree/a/b/c").is_dir());
}

#[test]
fn preserve_parses() {
    let p = |s: &str| s.parse::<Preserve>();
    assert_eq!(p("none").unwrap(), Preserve::NONE);
    assert_eq!(p("perms").unwrap(), Preserve::default());
    assert_eq!(
        p("perms, times,owner").unwrap(),
        Preserve {
            perms: true,
            times: true,
            owner: true
        }
    );
    assert_eq!(
        p("times").unwrap(),
        Preserve {
            times: true,
            ..Preserve::NONE
        }
    );
    for bad in ["", "perms,", "all", "none,perms"] {
        assert!(p(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn times_round_trip() {
    let (tmp, roots) = sample_tree();
    let tree = &roots[0];
    let mtime = FileTime::from_unix_time(1_600_000_000, 123_456_700);
    let atime = FileTime::from_unix_time(1_500_000_000, 500_000_000);
    let dir_mtime = FileTime::from_unix_time(1_400_000_000, 0);
    filetime::set_file_times(tree.join("a/top.txt"), atime, mtime).unwrap();
    filetime::set_file_times(tree.join("a/b"), atime, dir_mtime).unwrap();
    let preserve = Preserve {
        times: true,
        ..Preserve::default()
    };
    let captured = capture(&roots, preserve).unwrap();
    let out = tmp.path().join("out");
    fs::create_dir(&out).unwrap();
    deliver(&captured, &out);
    assert!(apply(&captured.map, &out, ApplyPolicy::default()).is_empty());

    let top = fs::metadata(out.join("tree/a/top.txt")).unwrap();
    assert_eq!(FileTime::from_last_modification_time(&top), mtime);
    assert_eq!(FileTime::from_last_access_time(&top), atime);
    let dir = fs::metadata(out.join("tree/a/b")).unwrap();
    assert_eq!(FileTime::from_last_modification_time(&dir), dir_mtime);
    for entry in &captured.map.entries {
        let local = entry.path.to_local_path(&out);
        let got = FileTime::from_last_modification_time(&fs::metadata(local).unwrap());
        assert_eq!(
            Some(got),
            entry.mtime.map(file_time),
            "{}",
            entry.path.display()
        );
    }
}

#[test]
fn file_time_handles_times_before_the_epoch() {
    assert_eq!(file_time(-100), FileTime::from_unix_time(-1, 999_999_900));
    let before = UNIX_EPOCH - std::time::Duration::from_nanos(100);
    assert_eq!(unix_nanos(before), Some(-100));
}

#[test]
fn symlinks_are_skipped() {
    let (_tmp, roots) = sample_tree();
    let link = roots[0].join("link");
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(roots[0].join("a"), &link);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_dir(roots[0].join("a"), &link);
    if let Err(e) = made {
        eprintln!("skipping: cannot create a symlink here: {e}");
        return;
    }
    let captured = capture(&roots, Preserve::default()).unwrap();
    assert_eq!(captured.skipped, [link]);
    assert!(paths(&captured).iter().all(|(p, _)| !p.contains("link")));
}

#[test]
fn owner_needs_permission_and_warns_once() {
    let (tmp, roots) = sample_tree();
    let captured = capture(
        &roots,
        Preserve {
            owner: true,
            ..Preserve::default()
        },
    )
    .unwrap();
    let out = tmp.path().join("out");
    fs::create_dir(&out).unwrap();
    deliver(&captured, &out);
    let warnings = apply(&captured.map, &out, ApplyPolicy::default());
    if cfg!(unix) {
        assert!(captured.map.entries.iter().all(|e| e.owner.is_some()));
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("--allow-owner"));
    } else {
        assert!(captured.map.entries.iter().all(|e| e.owner.is_none()));
        assert!(warnings.is_empty());
    }
}

#[test]
fn check_rejects_a_mismatched_file_id() {
    let map = FileMap {
        entries: vec![Entry {
            path: wp(&["a"]),
            kind: EntryKind::File { file_id: 1 },
            mode: None,
            mtime: None,
            atime: None,
            owner: None,
        }],
    };
    assert!(map.check(&[wp(&["a"])]).is_err());
    assert!(map.check(&[wp(&["b"]), wp(&["b"])]).is_err());
    map.check(&[wp(&["b"]), wp(&["a"])]).unwrap();
}

#[test]
fn map_round_trips_through_postcard() {
    let (_tmp, roots) = sample_tree();
    let preserve = Preserve {
        perms: true,
        times: true,
        owner: true,
    };
    let map = capture(&roots, preserve).unwrap().map;
    let bytes = postcard::to_stdvec(&map).unwrap();
    assert_eq!(postcard::from_bytes::<FileMap>(&bytes).unwrap(), map);
}

#[test]
fn a_missing_target_is_a_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let map = FileMap {
        entries: vec![Entry {
            path: wp(&["gone"]),
            kind: EntryKind::File { file_id: 0 },
            mode: Some(0o644),
            mtime: None,
            atime: None,
            owner: None,
        }],
    };
    let warnings = apply(&map, tmp.path(), ApplyPolicy::default());
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].starts_with("gone: "), "{warnings:?}");
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn modes_round_trip_and_special_bits_need_permission() {
        let (tmp, roots) = sample_tree();
        let tree = &roots[0];
        chmod(&tree.join("a/top.txt"), 0o4755);
        chmod(&tree.join("a/b/c/deep.txt"), 0o600);
        chmod(&tree.join("a/b"), 0o750);
        chmod(&tree.join("empty"), 0o700);
        let captured = capture(&roots, Preserve::default()).unwrap();

        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        deliver(&captured, &out);
        assert!(apply(&captured.map, &out, ApplyPolicy::default()).is_empty());
        assert_eq!(mode(&out.join("tree/a/top.txt")), 0o755);
        assert_eq!(mode(&out.join("tree/a/b/c/deep.txt")), 0o600);
        assert_eq!(mode(&out.join("tree/a/b")), 0o750);
        assert_eq!(mode(&out.join("tree/empty")), 0o700);

        let policy = ApplyPolicy {
            allow_special_bits: true,
            ..ApplyPolicy::default()
        };
        assert!(apply(&captured.map, &out, policy).is_empty());
        assert_eq!(mode(&out.join("tree/a/top.txt")), 0o4755);
    }

    #[test]
    fn an_unsearchable_directory_is_applied_after_its_contents() {
        let (tmp, roots) = sample_tree();
        let tree = &roots[0];
        chmod(&tree.join("a/b/c/deep.txt"), 0o640);
        let mtime = FileTime::from_unix_time(1_300_000_000, 0);
        filetime::set_file_mtime(tree.join("a/b/c/deep.txt"), mtime).unwrap();
        filetime::set_file_mtime(tree.join("a/b/c"), mtime).unwrap();
        let preserve = Preserve {
            times: true,
            ..Preserve::default()
        };
        let mut captured = capture(&roots, preserve).unwrap();
        for entry in &mut captured.map.entries {
            if matches!(entry.path.display().as_str(), "tree/a/b" | "tree/a/b/c") {
                entry.mode = Some(0o444);
            }
        }

        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        deliver(&captured, &out);
        let warnings = apply(&captured.map, &out, ApplyPolicy::default());
        assert_eq!(mode(&out.join("tree/a/b")), 0o444);
        chmod(&out.join("tree/a/b"), 0o755);
        assert_eq!(mode(&out.join("tree/a/b/c")), 0o444);
        chmod(&out.join("tree/a/b/c"), 0o755);
        assert!(warnings.is_empty(), "{warnings:?}");

        let deep = out.join("tree/a/b/c/deep.txt");
        assert_eq!(mode(&deep), 0o640);
        let deep_meta = fs::metadata(&deep).unwrap();
        assert_eq!(FileTime::from_last_modification_time(&deep_meta), mtime);
        let c_meta = fs::metadata(out.join("tree/a/b/c")).unwrap();
        assert_eq!(FileTime::from_last_modification_time(&c_meta), mtime);
    }
}

#[cfg(windows)]
mod windows {
    use super::*;

    fn set_readonly(path: &Path, readonly: bool) {
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_readonly(readonly);
        fs::set_permissions(path, perms).unwrap();
    }

    fn readonly(path: &Path) -> bool {
        fs::metadata(path).unwrap().permissions().readonly()
    }

    #[test]
    fn a_read_only_file_stays_read_only_and_reapplies() {
        let (tmp, roots) = sample_tree();
        let top = roots[0].join("a/top.txt");
        set_readonly(&top, true);
        let preserve = Preserve {
            times: true,
            ..Preserve::default()
        };
        let captured = capture(&roots, preserve).unwrap();
        set_readonly(&top, false);
        let modes: Vec<_> = captured
            .map
            .entries
            .iter()
            .map(|e| (e.path.display(), e.mode))
            .collect();
        assert!(
            modes.contains(&("tree/a/top.txt".into(), Some(0o444))),
            "{modes:?}"
        );
        assert!(modes.contains(&("tree/a/b/c/deep.txt".into(), Some(0o644))));
        assert!(modes.contains(&("tree".into(), Some(0o755))));

        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        deliver(&captured, &out);
        for _ in 0..2 {
            assert_eq!(
                apply(&captured.map, &out, ApplyPolicy::default()),
                Vec::<String>::new()
            );
            assert!(readonly(&out.join("tree/a/top.txt")));
            assert!(!readonly(&out.join("tree/a/b/c/deep.txt")));
        }
        set_readonly(&out.join("tree/a/top.txt"), false);
    }

    #[test]
    fn a_read_only_directory_is_applied_after_its_contents() {
        let (tmp, roots) = sample_tree();
        let dir = roots[0].join("a/b");
        let mtime = FileTime::from_unix_time(1_300_000_000, 0);
        filetime::set_file_mtime(&dir, mtime).unwrap();
        set_readonly(&dir, true);
        let preserve = Preserve {
            times: true,
            ..Preserve::default()
        };
        let captured = capture(&roots, preserve);
        set_readonly(&dir, false);
        let captured = captured.unwrap();

        let out = tmp.path().join("out");
        fs::create_dir(&out).unwrap();
        deliver(&captured, &out);
        assert!(apply(&captured.map, &out, ApplyPolicy::default()).is_empty());
        let local = out.join("tree/a/b");
        assert!(readonly(&local));
        let meta = fs::metadata(&local).unwrap();
        assert_eq!(FileTime::from_last_modification_time(&meta), mtime);
        set_readonly(&local, false);
    }
}

fn link_file(target: &Path, link: &Path) -> io::Result<()> {
    #[cfg(unix)]
    return std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    return std::os::windows::fs::symlink_file(target, link);
}

fn link_dir(target: &Path, link: &Path) -> io::Result<()> {
    #[cfg(unix)]
    return std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    return std::os::windows::fs::symlink_dir(target, link);
}

/// Mode (Unix) or read-only flag (Windows), and mtime.
fn fingerprint(path: &Path) -> (String, SystemTime) {
    let meta = fs::metadata(path).unwrap();
    #[cfg(unix)]
    let perms = {
        use std::os::unix::fs::PermissionsExt;
        format!("{:o}", meta.permissions().mode())
    };
    #[cfg(windows)]
    let perms = format!("readonly={}", meta.permissions().readonly());
    (perms, meta.modified().unwrap())
}

fn hostile_entry(path: WirePath, kind: EntryKind) -> Entry {
    Entry {
        path,
        kind,
        mode: Some(0o400),
        mtime: Some(0),
        atime: Some(0),
        owner: None,
    }
}

/// A link swapped in for a file after it was written must not redirect the
/// file's metadata to where the link points.
#[test]
fn apply_does_not_follow_a_link_in_place_of_a_file() {
    let out = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    fs::write(&victim, b"not yours").unwrap();
    let before = fingerprint(&victim);
    if let Err(e) = link_file(&victim, &out.path().join("f")) {
        eprintln!("skipping: cannot create a symlink here: {e}");
        return;
    }
    let map = FileMap {
        entries: vec![hostile_entry(wp(&["f"]), EntryKind::File { file_id: 0 })],
    };
    let warnings = apply(&map, out.path(), ApplyPolicy::default());
    assert_eq!(fingerprint(&victim), before, "the outside file was touched");
    assert!(
        warnings.len() == 1 && warnings[0].contains("symbolic link"),
        "{warnings:?}"
    );
}

/// The same for a link swapped in for a parent directory.
#[test]
fn apply_does_not_follow_a_link_in_place_of_a_parent() {
    let out = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("g");
    fs::write(&victim, b"not yours").unwrap();
    let before = fingerprint(&victim);
    if let Err(e) = link_dir(outside.path(), &out.path().join("d")) {
        eprintln!("skipping: cannot create a symlink here: {e}");
        return;
    }
    let map = FileMap {
        entries: vec![hostile_entry(
            wp(&["d", "g"]),
            EntryKind::File { file_id: 0 },
        )],
    };
    let warnings = apply(&map, out.path(), ApplyPolicy::default());
    assert_eq!(fingerprint(&victim), before, "the outside file was touched");
    assert!(
        warnings.len() == 1 && warnings[0].contains("symbolic link"),
        "{warnings:?}"
    );
}
