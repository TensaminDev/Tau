use mtp::crypto::Keyring;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

/// Includes the five-byte MTP raw keyring header. Current keyrings fit well below this limit.
pub const MAX_PRIVATE_KEYRING_BYTES: u64 = 1024 * 1024;

#[cfg(unix)]
fn verify_descriptor(file: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "keyring must be a regular owner-only file owned by the service user",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_descriptor(_: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "keyring permissions cannot be verified on this platform",
    ))
}

/// Parent directories must be trusted. NOFOLLOW protects the final component;
/// NONBLOCK prevents a substituted FIFO from blocking before descriptor validation.
pub fn open_private_keyring(path: &Path) -> io::Result<Option<File>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    verify_descriptor(&file)?;
    Ok(Some(file))
}

/// Parse the same descriptor that was verified, preserving MTP's MTMK/version-1 format.
pub fn read_private_keyring(file: File) -> io::Result<Keyring> {
    verify_descriptor(&file)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_PRIVATE_KEYRING_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PRIVATE_KEYRING_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private keyring exceeds size limit",
        ));
    }
    if !bytes.starts_with(b"MTMK\x01") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported or invalid MTP raw keyring header",
        ));
    }
    Keyring::from_bytes(&bytes[5..])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn load_private_keyring(path: &Path) -> io::Result<Option<Keyring>> {
    open_private_keyring(path)?
        .map(read_private_keyring)
        .transpose()
}

/// Compatibility metadata check. Loading callers must use load_private_keyring.
pub fn verify_private_keyring(path: &Path) -> io::Result<()> {
    open_private_keyring(path).map(|_| ())
}

/// Publish without replacing an identity created concurrently.
pub fn create_private_keyring(keyring: &Keyring, path: &Path) -> io::Result<()> {
    write_private_keyring(keyring, path, false)
}

/// Deliberate identity replacement in a trusted directory, followed by directory synchronization.
pub fn replace_private_keyring(keyring: &Keyring, path: &Path) -> io::Result<()> {
    write_private_keyring(keyring, path, true)
}

fn write_private_keyring(keyring: &Keyring, path: &Path, replace: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".keyring-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(&temporary)?;
    let result = (|| {
        let payload = zeroize::Zeroizing::new(
            keyring
                .try_to_bytes()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        );
        if payload.len() as u64 + 5 > MAX_PRIVATE_KEYRING_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private keyring exceeds size limit",
            ));
        }
        file.write_all(b"MTMK\x01")?;
        file.write_all(&payload)?;
        file.sync_all()?;
        verify_descriptor(&file)?;
        if replace {
            std::fs::rename(&temporary, path)?;
        } else {
            std::fs::hard_link(&temporary, path)?;
        }
        std::fs::remove_file(&temporary).or_else(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        })?;
        File::open(parent)?.sync_all()
    })();
    let _ = std::fs::remove_file(&temporary);
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("tau-keyring-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn descriptor_survives_path_replacement() {
        let directory = Directory::new();
        let path = directory.0.join("identity.mk");
        let original = Keyring::generate();
        create_private_keyring(&original, &path).unwrap();
        let verified = open_private_keyring(&path).unwrap().unwrap();
        replace_private_keyring(&Keyring::generate(), &path).unwrap();
        assert_eq!(
            read_private_keyring(verified)
                .unwrap()
                .try_to_bytes()
                .unwrap(),
            original.try_to_bytes().unwrap()
        );
        assert_ne!(
            load_private_keyring(&path)
                .unwrap()
                .unwrap()
                .try_to_bytes()
                .unwrap(),
            original.try_to_bytes().unwrap()
        );
    }

    #[test]
    fn unsafe_permissions_symlinks_and_nonregular_files_are_rejected() {
        let directory = Directory::new();
        let path = directory.0.join("identity.mk");
        create_private_keyring(&Keyring::generate(), &path).unwrap();
        for mode in [0o640, 0o604] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(load_private_keyring(&path).is_err());
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.0.join("link");
        symlink(&path, &link).unwrap();
        assert!(load_private_keyring(&link).is_err());
        assert!(load_private_keyring(&directory.0).is_err());
    }

    #[test]
    fn invalid_and_oversized_files_fail_closed() {
        let directory = Directory::new();
        let path = directory.0.join("identity.mk");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(b"MTMK\x01invalid").unwrap();
        assert!(load_private_keyring(&path).is_err());
        file.set_len(MAX_PRIVATE_KEYRING_BYTES + 1).unwrap();
        assert!(
            load_private_keyring(&path)
                .unwrap_err()
                .to_string()
                .contains("size limit")
        );
    }

    #[test]
    fn concurrent_creation_does_not_replace_the_winner() {
        let directory = Directory::new();
        let path = directory.0.join("identity.mk");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let keyring = Keyring::generate();
                    barrier.wait();
                    (create_private_keyring(&keyring, &path), keyring)
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            results.iter().filter(|(result, _)| result.is_ok()).count(),
            1
        );
        let winner = results.iter().find(|(result, _)| result.is_ok()).unwrap();
        let loser = results.iter().find(|(result, _)| result.is_err()).unwrap();
        assert_eq!(
            loser.0.as_ref().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            load_private_keyring(&path)
                .unwrap()
                .unwrap()
                .try_to_bytes()
                .unwrap(),
            winner.1.try_to_bytes().unwrap()
        );
    }
}
