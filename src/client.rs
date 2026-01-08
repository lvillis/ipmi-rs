use std::net::SocketAddr;
use std::time::Duration;

use rand::RngCore;

use crate::crypto::SecretBytes;
use crate::error::{Error, Result};
use crate::protocol::{
    RakpMessage2, SecurityContext, algorithm, build_open_session_request_payload,
    build_rakp_message_1_payload, build_rakp_message_3_payload, compute_sik_sha1,
    decode_ipmi_lan_response, decode_rmcpplus_packet, derive_security_context_sha1,
    encode_ipmi_lan_request, encode_rmcpplus_packet, encrypt_payload_aes_cbc,
    parse_open_session_response_payload, parse_rakp_message_2_payload,
    parse_rakp_message_4_payload, payload_type, rakp2_key_exchange_auth_code_sha1,
    rakp3_key_exchange_auth_code_sha1, rakp4_integrity_check_value_sha1_96,
};
use crate::transport::UdpTransport;
use crate::types::{
    ChannelAuthCapabilities, ChassisControl, ChassisStatus, DeviceId, FrontPanelControls,
    LastPowerEvent, PowerRestorePolicy, PrivilegeLevel, RawResponse, SelfTestDeviceError,
    SelfTestResult, SystemGuid,
};

fn debug_enabled() -> bool {
    std::env::var("IPMI_DEBUG")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

fn dump_hex(label: &str, bytes: &[u8]) {
    if !debug_enabled() {
        return;
    }
    let mut out = String::with_capacity(label.len() + bytes.len() * 3 + 4);
    out.push_str(label);
    out.push_str(" (");
    out.push_str(&bytes.len().to_string());
    out.push_str("):");
    for b in bytes {
        out.push(' ');
        out.push_str(&format!("{b:02x}"));
    }
    eprintln!("{out}");
}

/// A blocking IPMI v2.0 RMCP+ client.
///
/// `Client` manages an RMCP+ session and can issue IPMI commands over UDP port 623.
pub struct Client {
    transport: UdpTransport,
    session: Session,
    rq_seq: u8,
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

        let transport = UdpTransport::connect(self.target, self.timeout, self.retries)?;

        let session = establish_session(
            &transport,
            &username,
            &password,
            self.bmc_key.as_ref(),
            self.privilege_level,
        )?;

        Ok(Client {
            transport,
            session,
            rq_seq: 0,
        })
    }
}

impl Client {
    /// Create a [`ClientBuilder`].
    pub fn builder(target: SocketAddr) -> ClientBuilder {
        ClientBuilder::new(target)
    }

    /// Send a raw IPMI request and return the raw response.
    ///
    /// This method uses LUN=0 and addresses commonly used for LAN sessions
    /// (`rsAddr=0x20`, `rqAddr=0x81`).
    pub fn send_raw(&mut self, netfn: u8, cmd: u8, data: &[u8]) -> Result<RawResponse> {
        let rq_seq = self.allocate_rq_seq();
        let ipmi_msg = encode_ipmi_lan_request(netfn, cmd, rq_seq, data)?;
        let payload = if self.session.confidentiality_enabled {
            let mut iv = [0u8; 16];
            rand::rng().fill_bytes(&mut iv);
            encrypt_payload_aes_cbc(&ipmi_msg, &self.session.security.aes_key, &iv)?
        } else {
            ipmi_msg
        };

        let session_seq = self.session.allocate_out_seq();
        let packet = encode_rmcpplus_packet(
            payload_type::IPMI,
            self.session.managed_session_id,
            session_seq,
            &payload,
            self.session.integrity_enabled,
            self.session.confidentiality_enabled,
            Some(&self.session.security),
        )?;

        let response_bytes = self.transport.send_recv(&packet)?;
        let decoded = decode_rmcpplus_packet(&response_bytes, Some(&self.session.security))?;
        dump_hex("ipmi response payload", &decoded.payload);

        if decoded.payload_type != payload_type::IPMI {
            return Err(Error::Protocol("unexpected RMCP+ payload type"));
        }

        // Some implementations may echo either SIDC or SIDM in the header. Accept either.
        if decoded.session_id != self.session.managed_session_id
            && decoded.session_id != self.session.remote_session_id
        {
            return Err(Error::Protocol("unexpected RMCP+ session id"));
        }

        decode_ipmi_lan_response(netfn, cmd, rq_seq, &decoded.payload)
    }

    /// Convenience wrapper for `Get Device ID` (App NetFn, cmd 0x01).
    pub fn get_device_id(&mut self) -> Result<DeviceId> {
        const NETFN_APP: u8 = 0x06;
        const CMD_GET_DEVICE_ID: u8 = 0x01;

        let resp = self.send_raw(NETFN_APP, CMD_GET_DEVICE_ID, &[])?;
        if resp.completion_code != 0x00 {
            return Err(Error::CompletionCode {
                completion_code: resp.completion_code,
            });
        }

        parse_device_id(&resp.data)
    }

    /// Convenience wrapper for `Get Self Test Results` (App NetFn, cmd 0x04).
    pub fn get_self_test_results(&mut self) -> Result<SelfTestResult> {
        const NETFN_APP: u8 = 0x06;
        const CMD_GET_SELF_TEST: u8 = 0x04;

        let resp = self.send_raw(NETFN_APP, CMD_GET_SELF_TEST, &[])?;
        if resp.completion_code != 0x00 {
            return Err(Error::CompletionCode {
                completion_code: resp.completion_code,
            });
        }

        parse_self_test_result(&resp.data)
    }

    /// Convenience wrapper for `Get System GUID` (App NetFn, cmd 0x37).
    pub fn get_system_guid(&mut self) -> Result<SystemGuid> {
        const NETFN_APP: u8 = 0x06;
        const CMD_GET_SYSTEM_GUID: u8 = 0x37;

        let resp = self.send_raw(NETFN_APP, CMD_GET_SYSTEM_GUID, &[])?;
        if resp.completion_code != 0x00 {
            return Err(Error::CompletionCode {
                completion_code: resp.completion_code,
            });
        }

        parse_system_guid(&resp.data)
    }

    /// Convenience wrapper for `Get Chassis Status` (Chassis NetFn, cmd 0x01).
    pub fn get_chassis_status(&mut self) -> Result<ChassisStatus> {
        const NETFN_CHASSIS: u8 = 0x00;
        const CMD_GET_CHASSIS_STATUS: u8 = 0x01;

        let resp = self.send_raw(NETFN_CHASSIS, CMD_GET_CHASSIS_STATUS, &[])?;
        if resp.completion_code != 0x00 {
            return Err(Error::CompletionCode {
                completion_code: resp.completion_code,
            });
        }

        parse_chassis_status(&resp.data)
    }

    /// Run `Chassis Control` (Chassis NetFn, cmd 0x02).
    pub fn chassis_control(&mut self, control: ChassisControl) -> Result<()> {
        const NETFN_CHASSIS: u8 = 0x00;
        const CMD_CHASSIS_CONTROL: u8 = 0x02;

        let data = [control.as_u8()];
        let resp = self.send_raw(NETFN_CHASSIS, CMD_CHASSIS_CONTROL, &data)?;
        if resp.completion_code != 0x00 {
            return Err(Error::CompletionCode {
                completion_code: resp.completion_code,
            });
        }

        Ok(())
    }

    /// Convenience wrapper for `Get Channel Authentication Capabilities`
    /// (App NetFn, cmd 0x38).
    pub fn get_channel_auth_capabilities(
        &mut self,
        channel: u8,
        privilege: PrivilegeLevel,
    ) -> Result<ChannelAuthCapabilities> {
        const NETFN_APP: u8 = 0x06;
        const CMD_GET_CHANNEL_AUTH_CAP: u8 = 0x38;

        let mut data = [0u8; 2];
        data[0] = channel | 0x80;
        data[1] = privilege.as_u8() & 0x0F;

        let resp = self.send_raw(NETFN_APP, CMD_GET_CHANNEL_AUTH_CAP, &data)?;
        let resp = if resp.completion_code == 0x00 {
            resp
        } else {
            data[0] &= 0x7F;
            let resp = self.send_raw(NETFN_APP, CMD_GET_CHANNEL_AUTH_CAP, &data)?;
            if resp.completion_code != 0x00 {
                return Err(Error::CompletionCode {
                    completion_code: resp.completion_code,
                });
            }
            resp
        };

        parse_channel_auth_capabilities(&resp.data)
    }

    /// Return the managed system (BMC) session ID (SIDC).
    pub fn managed_session_id(&self) -> u32 {
        self.session.managed_session_id
    }

    /// Return the remote console session ID (SIDM).
    pub fn remote_session_id(&self) -> u32 {
        self.session.remote_session_id
    }

    fn allocate_rq_seq(&mut self) -> u8 {
        // rq_seq is 6-bit. We keep a u8 and wrap at 64.
        let current = self.rq_seq;
        self.rq_seq = (self.rq_seq + 1) & 0x3F;
        current
    }
}

#[derive(Debug)]
struct Session {
    managed_session_id: u32,
    remote_session_id: u32,
    #[allow(dead_code)]
    bmc_guid: [u8; 16],
    security: SecurityContext,
    integrity_enabled: bool,
    confidentiality_enabled: bool,
    next_out_seq: u32,
}

impl Session {
    fn allocate_out_seq(&mut self) -> u32 {
        let current = self.next_out_seq;
        self.next_out_seq = self.next_out_seq.wrapping_add(1);
        current
    }
}

fn establish_session(
    transport: &UdpTransport,
    username: &[u8],
    password: &SecretBytes,
    bmc_key: Option<&SecretBytes>,
    privilege_level: PrivilegeLevel,
) -> Result<Session> {
    // --- Open Session ---
    let mut rng = rand::rng();

    let remote_session_id = rng.next_u32();
    let open_tag = (rng.next_u32() & 0xFF) as u8;

    // Mandatory-to-implement suite:
    // - Auth: RAKP-HMAC-SHA1
    // - Integrity: HMAC-SHA1-96
    // - Confidentiality: AES-CBC-128
    let auth_algo: u8 = algorithm::AUTH_RAKP_HMAC_SHA1;
    let integrity_algo: u8 = algorithm::INTEGRITY_HMAC_SHA1_96;
    let conf_algo: u8 = algorithm::CONFIDENTIALITY_AES_CBC_128;

    const PRIV_ADMIN: [PrivilegeLevel; 3] = [
        PrivilegeLevel::Administrator,
        PrivilegeLevel::Operator,
        PrivilegeLevel::User,
    ];
    const PRIV_OPERATOR: [PrivilegeLevel; 2] = [PrivilegeLevel::Operator, PrivilegeLevel::User];
    const PRIV_USER: [PrivilegeLevel; 1] = [PrivilegeLevel::User];
    const PRIV_CALLBACK: [PrivilegeLevel; 1] = [PrivilegeLevel::Callback];
    const PRIV_OEM: [PrivilegeLevel; 1] = [PrivilegeLevel::Oem];

    let privilege_candidates: &[PrivilegeLevel] = match privilege_level {
        PrivilegeLevel::Administrator => &PRIV_ADMIN,
        PrivilegeLevel::Operator => &PRIV_OPERATOR,
        PrivilegeLevel::User => &PRIV_USER,
        PrivilegeLevel::Callback => &PRIV_CALLBACK,
        PrivilegeLevel::Oem => &PRIV_OEM,
    };

    let suites = [
        (auth_algo, integrity_algo, conf_algo),
        (auth_algo, integrity_algo, 0x00),
        (auth_algo, 0x00, 0x00),
    ];

    let mut open_resp = None;
    let mut selected = None;
    let mut selected_privilege = None;
    'open_session: for &requested_priv in privilege_candidates {
        for (auth, integrity, conf) in suites {
            let open_payload = build_open_session_request_payload(
                open_tag,
                requested_priv,
                remote_session_id,
                auth,
                integrity,
                conf,
            );

            let open_packet = encode_rmcpplus_packet(
                payload_type::OPEN_SESSION_REQUEST,
                0,
                0,
                &open_payload,
                false,
                false,
                None,
            )?;
            dump_hex("rmcp+ open request", &open_packet);

            let open_response_bytes = transport.send_recv(&open_packet)?;
            dump_hex("rmcp+ open response", &open_response_bytes);
            let open_decoded = decode_rmcpplus_packet(&open_response_bytes, None)?;
            if open_decoded.payload_type != payload_type::OPEN_SESSION_RESPONSE {
                return Err(Error::Protocol(
                    "unexpected Open Session response payload type",
                ));
            }

            let response = parse_open_session_response_payload(&open_decoded.payload)?;

            if response.message_tag != open_tag {
                return Err(Error::Protocol(
                    "Open Session response message tag mismatch",
                ));
            }

            if response.status_code == 0x00 {
                if requested_priv != privilege_level && debug_enabled() {
                    eprintln!(
                        "Open Session accepted with downgraded privilege {:?}",
                        requested_priv
                    );
                }
                open_resp = Some(response);
                selected = Some((auth, integrity, conf));
                selected_privilege = Some(requested_priv);
                break 'open_session;
            }

            if response.status_code != 0x12 {
                return Err(Error::protocol_owned(format!(
                    "Open Session rejected by managed system (status {:#04x})",
                    response.status_code
                )));
            }
        }
    }

    let open_resp = open_resp.ok_or_else(|| {
        Error::protocol_owned("Open Session rejected by managed system (status 0x12)".to_string())
    })?;
    let (auth_algo, integrity_algo, conf_algo) =
        selected.ok_or(Error::Protocol("missing cipher suite selection"))?;
    let negotiated_privilege =
        selected_privilege.ok_or(Error::Protocol("missing negotiated privilege selection"))?;

    if open_resp.remote_console_session_id != remote_session_id {
        return Err(Error::Protocol("Open Session remote session id mismatch"));
    }

    if open_resp.selected_auth_algorithm != auth_algo
        || open_resp.selected_integrity_algorithm != integrity_algo
        || open_resp.selected_confidentiality_algorithm != conf_algo
    {
        return Err(Error::Unsupported(
            "managed system selected unsupported cipher suite",
        ));
    }

    let managed_session_id = open_resp.managed_system_session_id;

    // --- RAKP Message 1 ---
    let rakp1_tag = (rng.next_u32() & 0xFF) as u8;
    let mut rm = [0u8; 16];
    rng.fill_bytes(&mut rm);

    let rakp1_payload = build_rakp_message_1_payload(
        rakp1_tag,
        managed_session_id,
        &rm,
        negotiated_privilege,
        username,
    )?;

    let rakp1_packet = encode_rmcpplus_packet(
        payload_type::RAKP_1,
        0,
        0,
        &rakp1_payload,
        false,
        false,
        None,
    )?;

    let rakp2_bytes = transport.send_recv(&rakp1_packet)?;
    dump_hex("rmcp+ rakp2 response", &rakp2_bytes);
    let rakp2_decoded = decode_rmcpplus_packet(&rakp2_bytes, None)?;
    if rakp2_decoded.payload_type != payload_type::RAKP_2 {
        return Err(Error::Protocol("unexpected RAKP message 2 payload type"));
    }

    let rakp2: RakpMessage2 = parse_rakp_message_2_payload(&rakp2_decoded.payload)?;

    if rakp2.message_tag != rakp1_tag {
        return Err(Error::Protocol("RAKP message 2 tag mismatch"));
    }
    if rakp2.status_code != 0x00 {
        return Err(Error::AuthenticationFailed("RAKP message 2 status != 0"));
    }
    if rakp2.remote_console_session_id != remote_session_id {
        return Err(Error::Protocol("RAKP message 2 remote session id mismatch"));
    }

    // --- Verify RAKP Message 2 auth code (HMAC(K[UID], ...), truncated) ---
    let user_key = password.to_key_sha1();
    let kg_key = match bmc_key {
        Some(kg) => kg.to_key_sha1(),
        None => user_key,
    };

    let expected_rakp2_auth = rakp2_key_exchange_auth_code_sha1(
        &user_key,
        remote_session_id,
        managed_session_id,
        &rm,
        &rakp2.bmc_random,
        &rakp2.bmc_guid,
        negotiated_privilege,
        username,
    )?;
    if !crate::crypto::ct_eq(&expected_rakp2_auth, &rakp2.key_exchange_auth_code) {
        return Err(Error::AuthenticationFailed(
            "RAKP message 2 authentication code mismatch",
        ));
    }

    // --- Compute SIK (HMAC(Kg, RM | RC | Role | ULen | UName), no truncation) ---
    let sik = compute_sik_sha1(
        &kg_key,
        &rm,
        &rakp2.bmc_random,
        negotiated_privilege,
        username,
    )?;
    let security = derive_security_context_sha1(&sik)?;

    // --- RAKP Message 3 ---
    let rakp3_tag = (rng.next_u32() & 0xFF) as u8;

    let rakp3_auth = rakp3_key_exchange_auth_code_sha1(
        &user_key,
        &rakp2.bmc_random,
        remote_session_id,
        negotiated_privilege,
        username,
    )?;
    let rakp3_payload = build_rakp_message_3_payload(rakp3_tag, managed_session_id, &rakp3_auth);
    let rakp3_packet = encode_rmcpplus_packet(
        payload_type::RAKP_3,
        0,
        0,
        &rakp3_payload,
        false,
        false,
        None,
    )?;

    let rakp4_bytes = transport.send_recv(&rakp3_packet)?;
    dump_hex("rmcp+ rakp4 response", &rakp4_bytes);
    let rakp4_decoded = decode_rmcpplus_packet(&rakp4_bytes, None)?;
    if rakp4_decoded.payload_type != payload_type::RAKP_4 {
        return Err(Error::Protocol("unexpected RAKP message 4 payload type"));
    }

    let rakp4 = parse_rakp_message_4_payload(&rakp4_decoded.payload)?;

    if rakp4.message_tag != rakp3_tag {
        return Err(Error::Protocol("RAKP message 4 tag mismatch"));
    }
    if rakp4.status_code != 0x00 {
        return Err(Error::AuthenticationFailed("RAKP message 4 status != 0"));
    }
    if rakp4.remote_console_session_id != remote_session_id {
        return Err(Error::Protocol("RAKP message 4 remote session id mismatch"));
    }

    // --- Verify RAKP Message 4 ICV: HMAC(SIK, RM | SIDC | GUIDC), truncated ---
    let expected_icv =
        rakp4_integrity_check_value_sha1_96(&sik, &rm, managed_session_id, &rakp2.bmc_guid)?;
    if !crate::crypto::ct_eq(&expected_icv, &rakp4.integrity_check_value) {
        return Err(Error::AuthenticationFailed(
            "RAKP message 4 integrity check value mismatch",
        ));
    }

    Ok(Session {
        managed_session_id,
        remote_session_id,
        bmc_guid: rakp2.bmc_guid,
        security,
        integrity_enabled: open_resp.selected_integrity_algorithm != 0x00,
        confidentiality_enabled: open_resp.selected_confidentiality_algorithm != 0x00,
        next_out_seq: 1,
    })
}

fn parse_device_id(data: &[u8]) -> Result<DeviceId> {
    // IPMI "Get Device ID" response (after completion code) is commonly 15 bytes.
    if data.len() < 15 {
        return Err(Error::Protocol("Get Device ID response too short"));
    }

    let device_id = data[0];
    let device_revision = data[1] & 0x0F;
    let fw_rev1 = data[2];
    let fw_rev2 = data[3];
    let ipmi_version = data[4];

    let manufacturer_id =
        u32::from(data[6]) | (u32::from(data[7]) << 8) | (u32::from(data[8]) << 16);
    let product_id = u16::from(data[9]) | (u16::from(data[10]) << 8);

    let aux_fw = [data[11], data[12], data[13], data[14]];

    Ok(DeviceId {
        device_id,
        device_revision,
        firmware_major: fw_rev1,
        firmware_minor: fw_rev2,
        ipmi_version,
        manufacturer_id,
        product_id,
        aux_firmware_revision: aux_fw,
    })
}

fn parse_self_test_result(data: &[u8]) -> Result<SelfTestResult> {
    if data.len() < 2 {
        return Err(Error::Protocol("Get Self Test Results response too short"));
    }

    let code = data[0];
    let detail = data[1];

    let result = match code {
        0x55 => SelfTestResult::Passed,
        0x56 => SelfTestResult::NotImplemented,
        0x57 => SelfTestResult::DeviceError(SelfTestDeviceError::from_bits(detail)),
        0x58 => SelfTestResult::FatalError(detail),
        _ => SelfTestResult::DeviceSpecific { code, detail },
    };

    Ok(result)
}

fn parse_system_guid(data: &[u8]) -> Result<SystemGuid> {
    if data.len() < 16 {
        return Err(Error::Protocol("Get System GUID response too short"));
    }

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[..16]);
    Ok(SystemGuid { bytes })
}

fn parse_chassis_status(data: &[u8]) -> Result<ChassisStatus> {
    if data.len() < 3 {
        return Err(Error::Protocol("Get Chassis Status response too short"));
    }

    let b1 = data[0];
    let b2 = data[1];
    let b3 = data[2];

    let power_restore_policy = match (b1 >> 5) & 0x03 {
        0x00 => PowerRestorePolicy::AlwaysOff,
        0x01 => PowerRestorePolicy::Previous,
        0x02 => PowerRestorePolicy::AlwaysOn,
        other => PowerRestorePolicy::Unknown(other),
    };

    let last_power_event = LastPowerEvent {
        ac_failed: b2 & 0x01 != 0,
        power_overload: b2 & 0x02 != 0,
        power_interlock: b2 & 0x04 != 0,
        power_fault: b2 & 0x08 != 0,
        power_on_command: b2 & 0x10 != 0,
    };

    let front_panel_controls = if data.len() > 3 {
        let b4 = data[3];
        if b4 == 0 {
            None
        } else {
            Some(FrontPanelControls {
                sleep_button_disable_allowed: b4 & 0x80 != 0,
                diag_button_disable_allowed: b4 & 0x40 != 0,
                reset_button_disable_allowed: b4 & 0x20 != 0,
                power_button_disable_allowed: b4 & 0x10 != 0,
                sleep_button_disabled: b4 & 0x08 != 0,
                diag_button_disabled: b4 & 0x04 != 0,
                reset_button_disabled: b4 & 0x02 != 0,
                power_button_disabled: b4 & 0x01 != 0,
            })
        }
    } else {
        None
    };

    Ok(ChassisStatus {
        system_power_on: b1 & 0x01 != 0,
        power_overload: b1 & 0x02 != 0,
        power_interlock: b1 & 0x04 != 0,
        main_power_fault: b1 & 0x08 != 0,
        power_control_fault: b1 & 0x10 != 0,
        power_restore_policy,
        last_power_event,
        chassis_intrusion: b3 & 0x01 != 0,
        front_panel_lockout: b3 & 0x02 != 0,
        drive_fault: b3 & 0x04 != 0,
        cooling_fan_fault: b3 & 0x08 != 0,
        front_panel_controls,
    })
}

fn parse_channel_auth_capabilities(data: &[u8]) -> Result<ChannelAuthCapabilities> {
    if data.len() < 8 {
        return Err(Error::Protocol(
            "Get Channel Authentication Capabilities response too short",
        ));
    }

    let channel_number = data[0] & 0x0F;
    let enabled_auth_types = data[1] & 0x3F;
    let v20_data_available = data[1] & 0x80 != 0;

    let per_message_auth_disabled = data[2] & 0x10 != 0;
    let user_level_auth_disabled = data[2] & 0x08 != 0;
    let non_null_usernames = data[2] & 0x04 != 0;
    let null_usernames = data[2] & 0x02 != 0;
    let anonymous_login_enabled = data[2] & 0x01 != 0;
    let kg_nonzero = data[2] & 0x20 != 0;

    let supports_ipmi_v1_5 = data[3] & 0x01 != 0;
    let supports_ipmi_v2_0 = data[3] & 0x02 != 0;

    let has_oem = enabled_auth_types & 0x20 != 0;
    let (oem_id, oem_aux_data) = if has_oem {
        let id = u32::from(data[4]) | (u32::from(data[5]) << 8) | (u32::from(data[6]) << 16);
        (Some(id), Some(data[7]))
    } else {
        (None, None)
    };

    Ok(ChannelAuthCapabilities {
        channel_number,
        v20_data_available,
        enabled_auth_types,
        per_message_auth_disabled,
        user_level_auth_disabled,
        non_null_usernames,
        null_usernames,
        anonymous_login_enabled,
        kg_nonzero,
        supports_ipmi_v1_5,
        supports_ipmi_v2_0,
        oem_id,
        oem_aux_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_self_test_result_variants() {
        let result = parse_self_test_result(&[0x55, 0x00]).expect("parse");
        assert!(matches!(result, SelfTestResult::Passed));

        let result = parse_self_test_result(&[0x56, 0x00]).expect("parse");
        assert!(matches!(result, SelfTestResult::NotImplemented));

        let result = parse_self_test_result(&[0x57, 0xAD]).expect("parse");
        let SelfTestResult::DeviceError(err) = result else {
            panic!("expected device error");
        };
        assert!(err.firmware_corrupted);
        assert!(!err.boot_block_corrupted);
        assert!(err.fru_internal_corrupted);
        assert!(err.sdr_repository_empty);
        assert!(!err.ipmb_not_responding);
        assert!(err.bmc_fru_access_error);
        assert!(!err.sdr_repository_access_error);
        assert!(err.sel_access_error);

        let result = parse_self_test_result(&[0x58, 0x12]).expect("parse");
        assert!(matches!(result, SelfTestResult::FatalError(0x12)));

        let result = parse_self_test_result(&[0x60, 0x34]).expect("parse");
        assert!(matches!(
            result,
            SelfTestResult::DeviceSpecific {
                code: 0x60,
                detail: 0x34
            }
        ));
    }

    #[test]
    fn parse_system_guid_copies_bytes() {
        let mut data = [0u8; 16];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i as u8;
        }
        let guid = parse_system_guid(&data).expect("parse");
        assert_eq!(guid.bytes, data);
    }

    #[test]
    fn parse_chassis_status_fields() {
        let data = [0x5F, 0x19, 0x0F, 0xFF];
        let status = parse_chassis_status(&data).expect("parse");

        assert!(status.system_power_on);
        assert!(status.power_overload);
        assert!(status.power_interlock);
        assert!(status.main_power_fault);
        assert!(status.power_control_fault);
        assert!(matches!(
            status.power_restore_policy,
            PowerRestorePolicy::AlwaysOn
        ));

        assert!(status.last_power_event.ac_failed);
        assert!(!status.last_power_event.power_overload);
        assert!(!status.last_power_event.power_interlock);
        assert!(status.last_power_event.power_fault);
        assert!(status.last_power_event.power_on_command);

        assert!(status.chassis_intrusion);
        assert!(status.front_panel_lockout);
        assert!(status.drive_fault);
        assert!(status.cooling_fan_fault);

        let controls = status.front_panel_controls.expect("controls");
        assert!(controls.sleep_button_disable_allowed);
        assert!(controls.diag_button_disable_allowed);
        assert!(controls.reset_button_disable_allowed);
        assert!(controls.power_button_disable_allowed);
        assert!(controls.sleep_button_disabled);
        assert!(controls.diag_button_disabled);
        assert!(controls.reset_button_disabled);
        assert!(controls.power_button_disabled);
    }

    #[test]
    fn parse_channel_auth_capabilities_with_oem() {
        let data = [0x82, 0xA1, 0x3D, 0x03, 0x33, 0x22, 0x11, 0x77];
        let caps = parse_channel_auth_capabilities(&data).expect("parse");

        assert_eq!(caps.channel_number, 0x02);
        assert!(caps.v20_data_available);
        assert_eq!(caps.enabled_auth_types, 0x21);
        assert!(caps.per_message_auth_disabled);
        assert!(caps.user_level_auth_disabled);
        assert!(caps.non_null_usernames);
        assert!(!caps.null_usernames);
        assert!(caps.anonymous_login_enabled);
        assert!(caps.kg_nonzero);
        assert!(caps.supports_ipmi_v1_5);
        assert!(caps.supports_ipmi_v2_0);
        assert_eq!(caps.oem_id, Some(0x112233));
        assert_eq!(caps.oem_aux_data, Some(0x77));
    }

    #[test]
    fn parse_channel_auth_capabilities_without_oem() {
        let data = [0x01, 0x80, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD];
        let caps = parse_channel_auth_capabilities(&data).expect("parse");

        assert_eq!(caps.channel_number, 0x01);
        assert!(caps.v20_data_available);
        assert_eq!(caps.enabled_auth_types, 0x00);
        assert!(!caps.per_message_auth_disabled);
        assert!(!caps.user_level_auth_disabled);
        assert!(!caps.non_null_usernames);
        assert!(!caps.null_usernames);
        assert!(!caps.anonymous_login_enabled);
        assert!(!caps.kg_nonzero);
        assert!(caps.supports_ipmi_v1_5);
        assert!(!caps.supports_ipmi_v2_0);
        assert_eq!(caps.oem_id, None);
        assert_eq!(caps.oem_aux_data, None);
    }
}
