use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use crate::client::core::ClientCore;
use crate::commands::{
    ChassisControlCommand, Command, GetChannelAuthCapabilities, GetChassisStatus, GetDeviceId,
    GetSelfTestResults, GetSystemGuid,
};
use crate::crypto::SecretBytes;
use crate::error::{Error, Result};
use crate::session::establish_session;
use crate::transport::Transport;
use crate::transport::blocking::UdpTransport;
use crate::types::{
    ChannelAuthCapabilities, ChassisControl, ChassisStatus, DeviceId, PrivilegeLevel, RawResponse,
    SelfTestResult, SystemGuid,
};

/// A blocking IPMI v2.0 RMCP+ client.
///
/// `Client` manages an RMCP+ session and can issue IPMI commands over UDP port 623.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Mutex<Inner>>,
    managed_session_id: u32,
    remote_session_id: u32,
}

struct Inner {
    transport: Box<dyn Transport + Send>,
    core: ClientCore,
}

/// Builder for [`Client`].
#[derive(Debug)]
pub struct ClientBuilder {
    target: SocketAddr,
    username: Option<Vec<u8>>,
    password: Option<SecretBytes>,
    bmc_key: Option<SecretBytes>,
    privilege_level: PrivilegeLevel,
    timeout: Duration,
    retries: u32,
}

impl ClientBuilder {
    /// Create a new builder.
    pub fn new(target: SocketAddr) -> Self {
        Self {
            target,
            username: None,
            password: None,
            bmc_key: None,
            privilege_level: PrivilegeLevel::Administrator,
            timeout: Duration::from_secs(1),
            retries: 3,
        }
    }

    /// Set the username (bytes).
    ///
    /// IPMI usernames are ASCII in most deployments, but the protocol treats them as raw bytes.
    pub fn username_bytes(mut self, username: impl Into<Vec<u8>>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Set the username (UTF-8 string). This is a convenience wrapper around [`Self::username_bytes`].
    pub fn username(mut self, username: impl AsRef<str>) -> Self {
        self.username = Some(username.as_ref().as_bytes().to_vec());
        self
    }

    /// Set the password (bytes).
    pub fn password_bytes(mut self, password: impl Into<Vec<u8>>) -> Self {
        self.password = Some(SecretBytes::new(password.into()));
        self
    }

    /// Set the password (UTF-8 string). This is a convenience wrapper around [`Self::password_bytes`].
    pub fn password(mut self, password: impl AsRef<str>) -> Self {
        self.password = Some(SecretBytes::new(password.as_ref().as_bytes().to_vec()));
        self
    }

    /// Set the optional BMC key (`Kg`) for "two-key" logins.
    ///
    /// If not set, the password key is used ("one-key" login), which is common in many BMC default configs.
    pub fn bmc_key_bytes(mut self, kg: impl Into<Vec<u8>>) -> Self {
        self.bmc_key = Some(SecretBytes::new(kg.into()));
        self
    }

    /// Set the optional BMC key (`Kg`) for "two-key" logins (UTF-8 string).
    pub fn bmc_key(mut self, kg: impl AsRef<str>) -> Self {
        self.bmc_key = Some(SecretBytes::new(kg.as_ref().as_bytes().to_vec()));
        self
    }

    /// Set requested session privilege level.
    pub fn privilege_level(mut self, level: PrivilegeLevel) -> Self {
        self.privilege_level = level;
        self
    }

    /// Set UDP read timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set number of send attempts per request (including the first attempt).
    pub fn retries(mut self, attempts: u32) -> Self {
        self.retries = attempts;
        self
    }

    /// Establish the session and build the [`Client`].
    pub fn build(self) -> Result<Client> {
        let username = self
            .username
            .ok_or(Error::Protocol("username is required"))?;
        let password = self
            .password
            .ok_or(Error::Protocol("password is required"))?;

        if username.len() > 16 {
            // Many BMCs limit username length to 16; the protocol allows larger, but interoperability suffers.
            return Err(Error::InvalidArgument(
                "username longer than 16 bytes is not widely supported",
            ));
        }

        let transport: Box<dyn Transport + Send> = Box::new(UdpTransport::connect(
            self.target,
            self.timeout,
            self.retries,
        )?);

        let session = establish_session(
            &*transport,
            &username,
            &password,
            self.bmc_key.as_ref(),
            self.privilege_level,
        )?;

        let managed_session_id = session.managed_session_id;
        let remote_session_id = session.remote_session_id;

        Ok(Client {
            inner: Arc::new(Mutex::new(Inner {
                transport,
                core: ClientCore::new(session),
            })),
            managed_session_id,
            remote_session_id,
        })
    }
}

impl Client {
    /// Create a [`ClientBuilder`].
    pub fn builder(target: SocketAddr) -> ClientBuilder {
        ClientBuilder::new(target)
    }

    /// Execute a typed command (single request/response).
    pub fn execute<C: Command>(&self, command: C) -> Result<C::Output> {
        let request_data = command.request_data();
        let response = self.send_raw(C::NETFN, C::CMD, &request_data)?;
        command.parse_response(response)
    }

    /// Send a raw IPMI request and return the raw response.
    ///
    /// This method uses LUN=0 and addresses commonly used for LAN sessions
    /// (`rsAddr=0x20`, `rqAddr=0x81`).
    pub fn send_raw(&self, netfn: u8, cmd: u8, data: &[u8]) -> Result<RawResponse> {
        let start = Instant::now();
        let result = {
            let mut inner = self.lock_inner()?;
            send_raw_locked(&mut inner, netfn, cmd, data)
        };
        let elapsed = start.elapsed();
        match &result {
            Ok(resp) => {
                crate::observe::record_ok("blocking", netfn, cmd, elapsed, resp.completion_code)
            }
            Err(err) => crate::observe::record_err("blocking", netfn, cmd, elapsed, err),
        }
        result
    }

    /// Convenience wrapper for `Get Device ID` (App NetFn, cmd 0x01).
    pub fn get_device_id(&self) -> Result<DeviceId> {
        self.execute(GetDeviceId)
    }

    /// Convenience wrapper for `Get Self Test Results` (App NetFn, cmd 0x04).
    pub fn get_self_test_results(&self) -> Result<SelfTestResult> {
        self.execute(GetSelfTestResults)
    }

    /// Convenience wrapper for `Get System GUID` (App NetFn, cmd 0x37).
    pub fn get_system_guid(&self) -> Result<SystemGuid> {
        self.execute(GetSystemGuid)
    }

    /// Convenience wrapper for `Get Chassis Status` (Chassis NetFn, cmd 0x01).
    pub fn get_chassis_status(&self) -> Result<ChassisStatus> {
        self.execute(GetChassisStatus)
    }

    /// Run `Chassis Control` (Chassis NetFn, cmd 0x02).
    pub fn chassis_control(&self, control: ChassisControl) -> Result<()> {
        self.execute(ChassisControlCommand { control })
    }

    /// Convenience wrapper for `Get Channel Authentication Capabilities`
    /// (App NetFn, cmd 0x38).
    pub fn get_channel_auth_capabilities(
        &self,
        channel: u8,
        privilege: PrivilegeLevel,
    ) -> Result<ChannelAuthCapabilities> {
        let cmd = GetChannelAuthCapabilities::new(channel, privilege);
        match self.execute(cmd) {
            Ok(caps) => Ok(caps),
            Err(Error::CompletionCode { .. }) => self.execute(cmd.without_v2_data()),
            Err(e) => Err(e),
        }
    }

    /// Return the managed system (BMC) session ID (SIDC).
    pub fn managed_session_id(&self) -> u32 {
        self.managed_session_id
    }

    /// Return the remote console session ID (SIDM).
    pub fn remote_session_id(&self) -> u32 {
        self.remote_session_id
    }

    /// Close the active RMCP+ session (App NetFn, cmd 0x3C).
    ///
    /// This is a best-effort operation. If the BMC does not respond (timeout) the client still
    /// transitions to a locally closed state and will reject further requests.
    pub fn close_session(&self) -> Result<()> {
        const NETFN_APP: u8 = 0x06;
        const CMD_CLOSE_SESSION: u8 = 0x3C;

        let mut inner = self.lock_inner()?;
        if inner.core.is_closed() {
            return Ok(());
        }

        let session_id = inner.core.managed_session_id_bytes_le();
        let start = Instant::now();
        let result = send_raw_locked(&mut inner, NETFN_APP, CMD_CLOSE_SESSION, &session_id);
        let elapsed = start.elapsed();
        match &result {
            Ok(resp) => crate::observe::record_ok(
                "blocking",
                NETFN_APP,
                CMD_CLOSE_SESSION,
                elapsed,
                resp.completion_code,
            ),
            Err(err) => {
                crate::observe::record_err("blocking", NETFN_APP, CMD_CLOSE_SESSION, elapsed, err)
            }
        }

        match result {
            Ok(resp) => {
                // Completion code 0x87 = invalid session ID. Treat it as "already closed".
                if resp.completion_code != 0x00 && resp.completion_code != 0x87 {
                    inner.core.mark_closed();
                    return Err(Error::CompletionCode {
                        completion_code: resp.completion_code,
                    });
                }
                inner.core.mark_closed();
                Ok(())
            }
            Err(Error::Timeout) => {
                inner.core.mark_closed();
                Ok(())
            }
            Err(e) => {
                inner.core.mark_closed();
                Err(e)
            }
        }
    }

    /// A service-style grouping for App netfn commands.
    pub fn app(&self) -> AppService {
        AppService {
            client: self.clone(),
        }
    }

    /// A service-style grouping for Chassis netfn commands.
    pub fn chassis(&self) -> ChassisService {
        ChassisService {
            client: self.clone(),
        }
    }

    fn lock_inner(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| Error::Protocol("client lock poisoned"))
    }
}

fn send_raw_locked(inner: &mut Inner, netfn: u8, cmd: u8, data: &[u8]) -> Result<RawResponse> {
    let (rq_seq, packet) = inner.core.build_rmcpplus_ipmi_request(netfn, cmd, data)?;
    let response_bytes = inner.transport.send_recv(&packet)?;
    inner
        .core
        .decode_rmcpplus_ipmi_response(netfn, cmd, rq_seq, &response_bytes)
}

/// App NetFn service.
#[derive(Clone)]
pub struct AppService {
    client: Client,
}

impl AppService {
    /// `Get Device ID` (App NetFn, cmd 0x01).
    pub fn get_device_id(&self) -> Result<DeviceId> {
        self.client.get_device_id()
    }

    /// `Get Self Test Results` (App NetFn, cmd 0x04).
    pub fn get_self_test_results(&self) -> Result<SelfTestResult> {
        self.client.get_self_test_results()
    }

    /// `Get System GUID` (App NetFn, cmd 0x37).
    pub fn get_system_guid(&self) -> Result<SystemGuid> {
        self.client.get_system_guid()
    }

    /// `Get Channel Authentication Capabilities` (App NetFn, cmd 0x38).
    pub fn get_channel_auth_capabilities(
        &self,
        channel: u8,
        privilege: PrivilegeLevel,
    ) -> Result<ChannelAuthCapabilities> {
        self.client
            .get_channel_auth_capabilities(channel, privilege)
    }
}

/// Chassis NetFn service.
#[derive(Clone)]
pub struct ChassisService {
    client: Client,
}

impl ChassisService {
    /// `Get Chassis Status` (Chassis NetFn, cmd 0x01).
    pub fn get_chassis_status(&self) -> Result<ChassisStatus> {
        self.client.get_chassis_status()
    }

    /// `Chassis Control` (Chassis NetFn, cmd 0x02).
    pub fn chassis_control(&self, control: ChassisControl) -> Result<()> {
        self.client.chassis_control(control)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::session::Session;

    #[derive(Debug, Clone, Copy)]
    struct TimeoutTransport;

    impl Transport for TimeoutTransport {
        fn send_recv(&self, _request: &[u8]) -> Result<Vec<u8>> {
            Err(Error::Timeout)
        }
    }

    fn dummy_session() -> Session {
        Session::new_test(0x11223344, 0x55667788, false, false)
    }

    #[test]
    fn close_session_timeout_marks_client_closed() {
        let session = dummy_session();
        let managed_session_id = session.managed_session_id;
        let remote_session_id = session.remote_session_id;
        let client = Client {
            inner: Arc::new(Mutex::new(Inner {
                transport: Box::new(TimeoutTransport),
                core: ClientCore::new(session),
            })),
            managed_session_id,
            remote_session_id,
        };

        client.close_session().expect("close_session");

        let err = client
            .get_device_id()
            .expect_err("expected session-closed error");
        assert!(matches!(err, Error::Protocol("session is closed")));
    }
}
