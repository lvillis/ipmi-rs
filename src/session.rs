use rand::RngCore;
use zeroize::Zeroizing;

use crate::crypto::SecretBytes;
use crate::error::{Error, Result};
use crate::protocol::{
    RakpMessage2, SecurityContext, algorithm, build_open_session_request_payload,
    build_rakp_message_1_payload, build_rakp_message_3_payload, compute_sik_sha1,
    decode_rmcpplus_packet, derive_security_context_sha1, encode_rmcpplus_packet,
    parse_open_session_response_payload, parse_rakp_message_2_payload,
    parse_rakp_message_4_payload, payload_type, rakp2_key_exchange_auth_code_sha1,
    rakp3_key_exchange_auth_code_sha1, rakp4_integrity_check_value_sha1_96,
};
#[cfg(feature = "blocking")]
use crate::transport::Transport;
use crate::types::PrivilegeLevel;

#[derive(Debug)]
pub(crate) struct Session {
    pub(crate) managed_session_id: u32,
    pub(crate) remote_session_id: u32,
    #[allow(dead_code)]
    pub(crate) bmc_guid: [u8; 16],
    pub(crate) security: SecurityContext,
    pub(crate) integrity_enabled: bool,
    pub(crate) confidentiality_enabled: bool,
    next_out_seq: u32,
}

impl Session {
    pub(crate) fn allocate_out_seq(&mut self) -> u32 {
        let current = self.next_out_seq;
        self.next_out_seq = self.next_out_seq.wrapping_add(1);
        current
    }

    #[cfg(test)]
    pub(crate) fn new_test(
        managed_session_id: u32,
        remote_session_id: u32,
        integrity_enabled: bool,
        confidentiality_enabled: bool,
    ) -> Self {
        Self {
            managed_session_id,
            remote_session_id,
            bmc_guid: [0u8; 16],
            security: SecurityContext {
                k1: [0u8; 20],
                aes_key: [0u8; 16],
            },
            integrity_enabled,
            confidentiality_enabled,
            next_out_seq: 1,
        }
    }
}

#[cfg(feature = "blocking")]
pub(crate) fn establish_session<T: Transport + ?Sized>(
    transport: &T,
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
            crate::debug::dump_hex("rmcp+ open request", &open_packet);

            let open_response_bytes = transport.send_recv(&open_packet)?;
            crate::debug::dump_hex("rmcp+ open response", &open_response_bytes);
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
                if requested_priv != privilege_level && crate::debug::enabled() {
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
    crate::debug::dump_hex("rmcp+ rakp2 response", &rakp2_bytes);
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
    let user_key = Zeroizing::new(password.to_key_sha1());
    let kg_key = Zeroizing::new(match bmc_key {
        Some(kg) => kg.to_key_sha1(),
        None => *user_key,
    });

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
    let sik = Zeroizing::new(compute_sik_sha1(
        &kg_key,
        &rm,
        &rakp2.bmc_random,
        negotiated_privilege,
        username,
    )?);
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
    crate::debug::dump_hex("rmcp+ rakp4 response", &rakp4_bytes);
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

#[cfg(feature = "async")]
pub(crate) async fn establish_session_async<T: crate::transport::AsyncTransport + ?Sized>(
    transport: &T,
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
            crate::debug::dump_hex("rmcp+ open request", &open_packet);

            let open_response_bytes = transport.send_recv(&open_packet).await?;
            crate::debug::dump_hex("rmcp+ open response", &open_response_bytes);
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
                if requested_priv != privilege_level && crate::debug::enabled() {
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

    let rakp2_bytes = transport.send_recv(&rakp1_packet).await?;
    crate::debug::dump_hex("rmcp+ rakp2 response", &rakp2_bytes);
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
    let user_key = Zeroizing::new(password.to_key_sha1());
    let kg_key = Zeroizing::new(match bmc_key {
        Some(kg) => kg.to_key_sha1(),
        None => *user_key,
    });

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
    let sik = Zeroizing::new(compute_sik_sha1(
        &kg_key,
        &rm,
        &rakp2.bmc_random,
        negotiated_privilege,
        username,
    )?);
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

    let rakp4_bytes = transport.send_recv(&rakp3_packet).await?;
    crate::debug::dump_hex("rmcp+ rakp4 response", &rakp4_bytes);
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
