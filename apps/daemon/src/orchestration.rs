use async_trait::async_trait;
use tokio::process::Child;

// --- Tunnel Abstraction (Enterprise Grade) ---

/// Abstraction for a VPN tunnel process (e.g., WireGuard, ShadowMesh Core).
#[async_trait]
pub trait VpnTunnel: Send + Sync {
    /// Returns the process ID if applicable.
    fn pid(&self) -> Option<u32>;

    /// Checks if the tunnel process is still running.
    fn try_wait(&mut self) -> anyhow::Result<Option<std::process::ExitStatus>>;

    /// Gracefully terminates the tunnel and cleans up resources.
    async fn shutdown(&mut self) -> anyhow::Result<()>;
}

/// Implementation of VpnTunnel using a real OS process.
pub struct ProcessTunnel {
    pub child: Child,
    pub name: String,
}

#[async_trait]
impl VpnTunnel for ProcessTunnel {
    fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    fn try_wait(&mut self) -> anyhow::Result<Option<std::process::ExitStatus>> {
        Ok(self.child.try_wait()?)
    }

    async fn shutdown(&mut self) -> anyhow::Result<()> {
        let _ = self.child.kill().await;
        let _ = self.child.wait().await; // Async wait to avoid zombies
        Ok(())
    }
}

// --- System Command Abstraction ---

#[async_trait]
pub trait SystemCommandRunner: Send + Sync {
    /// Executes a one-off command and waits for its completion.
    /// Returns the combined stdout and stderr if successful.
    async fn run_command(&self, cmd: &str, args: &[&str]) -> anyhow::Result<String>;

    /// Spawns a long-running tunnel process.
    async fn spawn_tunnel(
        &self,
        cmd: &str,
        args: &[&str],
        name: String,
    ) -> anyhow::Result<Box<dyn VpnTunnel>>;
}

pub struct RealCommandRunner;

#[async_trait]
impl SystemCommandRunner for RealCommandRunner {
    async fn run_command(&self, cmd: &str, args: &[&str]) -> anyhow::Result<String> {
        let output = tokio::process::Command::new(cmd).args(args).output().await?;
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if output.status.success() {
            Ok(combined)
        } else {
            Err(anyhow::anyhow!(
                "Command '{} {:?}' failed with exit code {:?}: {}",
                cmd,
                args,
                output.status.code(),
                combined.trim()
            ))
        }
    }

    async fn spawn_tunnel(
        &self,
        cmd: &str,
        args: &[&str],
        name: String,
    ) -> anyhow::Result<Box<dyn VpnTunnel>> {
        let child = tokio::process::Command::new(cmd)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;

        Ok(Box::new(ProcessTunnel { child, name }))
    }
}

// --- File System Abstraction ---

#[async_trait]
pub trait FileSystem: Send + Sync {
    async fn read_to_string(&self, path: &str) -> anyhow::Result<String>;
    async fn read(&self, path: &str) -> anyhow::Result<Vec<u8>>;
    async fn write(&self, path: &str, contents: String) -> anyhow::Result<()>;
    async fn create_dir_all(&self, path: &str) -> anyhow::Result<()>;
    async fn remove_file(&self, path: &str) -> anyhow::Result<()>;
    fn metadata_permissions_mode(&self, path: &str) -> anyhow::Result<u32>;
    fn set_permissions_mode(&self, path: &str, mode: u32) -> anyhow::Result<()>;
}

pub struct RealFileSystem;

#[async_trait]
impl FileSystem for RealFileSystem {
    async fn read_to_string(&self, path: &str) -> anyhow::Result<String> {
        Ok(std::fs::read_to_string(path)?)
    }
    async fn read(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        Ok(std::fs::read(path)?)
    }
    async fn write(&self, path: &str, contents: String) -> anyhow::Result<()> {
        Ok(std::fs::write(path, contents)?)
    }
    async fn create_dir_all(&self, path: &str) -> anyhow::Result<()> {
        Ok(std::fs::create_dir_all(path)?)
    }
    async fn remove_file(&self, path: &str) -> anyhow::Result<()> {
        Ok(std::fs::remove_file(path)?)
    }
    fn metadata_permissions_mode(&self, path: &str) -> anyhow::Result<u32> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Ok(std::fs::metadata(path)?.permissions().mode())
        }
        #[cfg(not(unix))]
        {
            Ok(0)
        }
    }
    fn set_permissions_mode(&self, _path: &str, _mode: u32) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(_path)?.permissions();
            perms.set_mode(_mode);
            std::fs::set_permissions(_path, perms)?;
        }
        Ok(())
    }
}

// --- Secure Storage Abstraction ---

pub trait SecureStorage: Send + Sync {
    fn get_password(&self, service: &str, user: &str) -> anyhow::Result<String>;
    fn set_password(&self, service: &str, user: &str, password: &str) -> anyhow::Result<()>;
    fn delete_password(&self, service: &str, user: &str) -> anyhow::Result<()>;
}

pub struct RealSecureStorage;

impl SecureStorage for RealSecureStorage {
    fn get_password(&self, service: &str, user: &str) -> anyhow::Result<String> {
        keyring::Entry::new(service, user)?.get_password().map_err(|e| anyhow::anyhow!(e))
    }
    fn set_password(&self, service: &str, user: &str, password: &str) -> anyhow::Result<()> {
        keyring::Entry::new(service, user)?.set_password(password).map_err(|e| anyhow::anyhow!(e))
    }
    fn delete_password(&self, service: &str, user: &str) -> anyhow::Result<()> {
        keyring::Entry::new(service, user)?.delete_password().map_err(|e| anyhow::anyhow!(e))
    }
}
