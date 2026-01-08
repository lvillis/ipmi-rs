use crate::crypto::{
    aes128_cbc_decrypt, aes128_cbc_encrypt, ct_eq, derive_aes_key_from_k2, derive_k1_k2_sha1,
    hmac_sha1, hmac_sha1_truncated_12, normalize_key_sha1,
};
use crate::error::{Error, Result};
use crate::types::PrivilegeLevel;

/// RMCP header values.
const RMCP_VERSION: u8 = 0x06;
const RMCP_RESERVED: u8 = 0x00;
const RMCP_SEQ_NO_ACK: u8 = 0xFF;
const RMCP_CLASS_IPMI: u8 = 0x07;

/// RMCP+ session auth type/format.
const RMCPPLUS_AUTH_TYPE: u8 = 0x06;

/// RMCP+ session trailer next header value.
const RMCPPLUS_NEXT_HEADER: u8 = 0x07;

/// Payload type numbers (see IPMI v2.0 Table 13-16).
///
/// We only implement the baseline types required for IPMI messaging and session setup.
pub(crate) mod payload_type {
    /// Standard IPMI payload (lan message) wrapped in RMCP+.
    pub const IPMI: u8 = 0x00;
    /// RMCP+ Open Session Request.
    pub const OPEN_SESSION_REQUEST: u8 = 0x10;
    /// RMCP+ Open Session Response.
    pub const OPEN_SESSION_RESPONSE: u8 = 0x11;
    /// RAKP Message 1.
    pub const RAKP_1: u8 = 0x12;
    /// RAKP Message 2.
    pub const RAKP_2: u8 = 0x13;
    /// RAKP Message 3.
    pub const RAKP_3: u8 = 0x14;
    /// RAKP Message 4.
    pub const RAKP_4: u8 = 0x15;
}

/// Algorithm numbers (baseline, mandatory-to-implement set).
///
/// This crate currently implements:
/// - Authentication: RAKP-HMAC-SHA1
/// - Integrity: HMAC-SHA1-96
/// - Confidentiality: AES-CBC-128
pub(crate) mod algorithm {
    /// Authentication algorithm: RAKP-HMAC-SHA1.
    pub const AUTH_RAKP_HMAC_SHA1: u8 = 0x01;
    /// Integrity algorithm: HMAC-SHA1-96.
    pub const INTEGRITY_HMAC_SHA1_96: u8 = 0x01;
    /// Confidentiality algorithm: AES-CBC-128.
    pub const CONFIDENTIALITY_AES_CBC_128: u8 = 0x01;
}

/// Security context for an established RMCP+ session.
#[derive(Debug, Clone)]
pub(crate) struct SecurityContext {
    /// Integrity keying material (K1).
    pub k1: [u8; 20],
    /// Confidentiality key (AES-128 key derived from K2).
    pub aes_key: [u8; 16],
}

impl SecurityContext {
    pub(crate) fn auth_code_len(&self) -> usize {
        // HMAC-SHA1-96
        12
    }
}

/// Parsed RMCP+ packet (payload is decrypted/verified when security context is provided).
#[derive(Debug, Clone)]
pub(crate) struct DecodedPacket {
    pub payload_type: u8,
    #[allow(dead_code)]
    pub is_authenticated: bool,
    #[allow(dead_code)]
    pub is_encrypted: bool,
    pub session_id: u32,
    #[allow(dead_code)]
    pub session_seq: u32,
    pub payload: Vec<u8>,
}

pub(crate) fn encode_rmcpplus_packet(
    payload_type_num: u8,
    session_id: u32,
    session_seq: u32,
    payload: &[u8],
    authenticated: bool,
    encrypted: bool,
    security: Option<&SecurityContext>,
) -> Result<Vec<u8>> {
    if (authenticated || encrypted) && security.is_none() {
        return Err(Error::Protocol(
            "security context required for authenticated/encrypted packets",
        ));
    }

    let payload_type_byte = make_payload_type_byte(payload_type_num, authenticated, encrypted);

    let payload_len: u16 = payload
        .len()
        .try_into()
        .map_err(|_| Error::Protocol("payload too large"))?;

    let mut packet = Vec::with_capacity(4 + 12 + payload.len() + 64);

    // RMCP header.
    packet.push(RMCP_VERSION);
    packet.push(RMCP_RESERVED);
    packet.push(RMCP_SEQ_NO_ACK);
    packet.push(RMCP_CLASS_IPMI);

    // RMCP+ session header.
    packet.push(RMCPPLUS_AUTH_TYPE);
    packet.push(payload_type_byte);
    packet.extend_from_slice(&session_id.to_le_bytes());
    packet.extend_from_slice(&session_seq.to_le_bytes());
    packet.extend_from_slice(&payload_len.to_le_bytes());

    // IPMI payload.
    packet.extend_from_slice(payload);

    if authenticated {
        let security = security.ok_or(Error::Protocol("missing security context"))?;

        // Integrity padding is used to align the authenticated range to 4 bytes.
        let base_len = 12usize + payload.len() + 2;
        let pad_len = ((4 - (base_len % 4)) % 4) as u8;

        packet.extend(std::iter::repeat_n(0xFF, pad_len as usize));
        packet.push(pad_len);
        packet.push(RMCPPLUS_NEXT_HEADER);

        let auth_code = hmac_sha1_truncated_12(&security.k1, &packet[4..])?;
        packet.extend_from_slice(&auth_code);
    }

    Ok(packet)
}

pub(crate) fn decode_rmcpplus_packet(
    bytes: &[u8],
    security: Option<&SecurityContext>,
) -> Result<DecodedPacket> {
    let (header, payload, trailer) = parse_rmcpplus_header_and_sections(bytes)?;

    let (is_authenticated, is_encrypted, payload_type_num) =
        split_payload_type(header.payload_type);

    if is_authenticated || is_encrypted {
        let security = security.ok_or(Error::Protocol(
            "security context required for authenticated/encrypted packets",
        ))?;
        verify_auth_code(bytes, &header, &trailer, security)?;
    }

    let payload_data = if is_encrypted {
        let security = security.ok_or(Error::Protocol(
            "security context required for encrypted payload",
        ))?;
        decrypt_payload_aes_cbc(payload, &security.aes_key)?
    } else {
        payload.to_vec()
    };

    Ok(DecodedPacket {
        payload_type: payload_type_num,
        is_authenticated,
        is_encrypted,
        session_id: header.session_id,
        session_seq: header.session_seq,
        payload: payload_data,
    })
}

#[derive(Debug, Clone)]
struct ParsedHeader {
    payload_type: u8,
    session_id: u32,
    session_seq: u32,
    payload_len: u16,
    header_len: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ParsedTrailer {
    payload_end: usize,
    auth_code_len: usize,
    auth_code_start: usize,
    pad_len: u8,
    next_header: u8,
}

fn parse_rmcpplus_header_and_sections(
    bytes: &[u8],
) -> Result<(ParsedHeader, &[u8], Option<ParsedTrailer>)> {
    if bytes.len() < 4 + 12 {
        return Err(Error::Protocol("packet too short"));
    }

    // RMCP header.
    if bytes[0] != RMCP_VERSION {
        return Err(Error::Protocol("unexpected RMCP version"));
    }
    if bytes[3] != RMCP_CLASS_IPMI {
        return Err(Error::Protocol("unexpected RMCP class"));
    }

    // RMCP+ auth type.
    if bytes[4] != RMCPPLUS_AUTH_TYPE {
        return Err(Error::Protocol("unsupported RMCP auth type"));
    }

    let payload_type = bytes[5];
    let payload_type_num = payload_type & 0x3F;
    if payload_type_num == 0x02 {
        // OEM explicit payload includes OEM fields we don't currently implement.
        return Err(Error::Unsupported("OEM explicit payload is not supported"));
    }

    let session_id = u32::from_le_bytes(
        bytes[6..10]
            .try_into()
            .map_err(|_| Error::Protocol("invalid session id"))?,
    );
    let session_seq = u32::from_le_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| Error::Protocol("invalid session seq"))?,
    );
    let payload_len = u16::from_le_bytes(
        bytes[14..16]
            .try_into()
            .map_err(|_| Error::Protocol("invalid payload len"))?,
    );

    let header_len = 4 + 12;
    let payload_start = header_len;
    let payload_end = payload_start + (payload_len as usize);

    if bytes.len() < payload_end {
        return Err(Error::Protocol("truncated payload"));
    }

    let payload = &bytes[payload_start..payload_end];

    let (is_authenticated, _is_encrypted, _payload_type_num) = split_payload_type(payload_type);

    let trailer = if is_authenticated {
        // We cannot fully parse trailer without the integrity algorithm. We'll parse the common
        // fields and leave auth_code_len to be filled during verification.
        Some(ParsedTrailer {
            payload_end,
            auth_code_len: 0,
            auth_code_start: 0,
            pad_len: 0,
            next_header: 0,
        })
    } else {
        None
    };

    Ok((
        ParsedHeader {
            payload_type,
            session_id,
            session_seq,
            payload_len,
            header_len,
        },
        payload,
        trailer,
    ))
}

fn verify_auth_code(
    bytes: &[u8],
    header: &ParsedHeader,
    trailer: &Option<ParsedTrailer>,
    security: &SecurityContext,
) -> Result<()> {
    if trailer.is_none() {
        return Err(Error::Protocol("missing trailer for authenticated packet"));
    }

    let auth_code_len = security.auth_code_len();
    if bytes.len() < header.header_len + (header.payload_len as usize) + 2 + auth_code_len {
        return Err(Error::Protocol("authenticated packet too short"));
    }

    let auth_code_start = bytes.len() - auth_code_len;
    let auth_code = &bytes[auth_code_start..];

    // The authenticated range is from AuthType (byte 4) through Next Header (inclusive).
    let data_end = auth_code_start;
    let data = &bytes[4..data_end];

    let expected = hmac_sha1_truncated_12(&security.k1, data)?;
    if !ct_eq(auth_code, &expected) {
        return Err(Error::AuthenticationFailed("invalid packet auth code"));
    }

    // Parse pad length and next header.
    if data_end < 2 {
        return Err(Error::Protocol("malformed session trailer"));
    }
    let pad_len = bytes[data_end - 2];
    let next_header = bytes[data_end - 1];
    if next_header != RMCPPLUS_NEXT_HEADER {
        return Err(Error::Protocol("unexpected next header"));
    }

    let payload_end = header.header_len + (header.payload_len as usize);
    let expected_trailer_start = payload_end;
    let expected_trailer_end = data_end;

    // Trailer layout: [integrity pad bytes][pad_len][next_header]
    if expected_trailer_end < expected_trailer_start + 2 {
        return Err(Error::Protocol("malformed trailer length"));
    }

    let pad_bytes_end = expected_trailer_end - 2;
    let pad_bytes = &bytes[expected_trailer_start..pad_bytes_end];
    if pad_bytes.len() != pad_len as usize {
        return Err(Error::Protocol("pad length mismatch"));
    }
    if pad_bytes.iter().any(|&b| b != 0xFF) {
        // Spec says pad bytes are FFh.
        return Err(Error::Protocol("invalid integrity pad bytes"));
    }

    Ok(())
}

fn decrypt_payload_aes_cbc(payload: &[u8], aes_key: &[u8; 16]) -> Result<Vec<u8>> {
    if payload.len() < 16 {
        return Err(Error::Protocol("encrypted payload too short"));
    }

    let iv: [u8; 16] = payload[..16]
        .try_into()
        .map_err(|_| Error::Protocol("invalid IV"))?;
    let ciphertext = &payload[16..];
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(Error::Protocol("invalid AES-CBC ciphertext length"));
    }

    let mut plaintext = aes128_cbc_decrypt(aes_key, &iv, ciphertext)?;
    if plaintext.is_empty() {
        return Err(Error::Protocol("empty decrypted payload"));
    }

    let pad_len = *plaintext
        .last()
        .ok_or(Error::Protocol("missing confidentiality pad length"))? as usize;

    if pad_len > plaintext.len().saturating_sub(1) {
        return Err(Error::Protocol("invalid confidentiality pad length"));
    }

    let trailer_start = plaintext.len() - 1 - pad_len;
    let pad_bytes = &plaintext[trailer_start..plaintext.len() - 1];
    for (i, &b) in pad_bytes.iter().enumerate() {
        if b != (i as u8 + 1) {
            return Err(Error::Protocol("invalid confidentiality pad bytes"));
        }
    }

    plaintext.truncate(trailer_start);
    Ok(plaintext)
}

fn make_payload_type_byte(payload_type_num: u8, authenticated: bool, encrypted: bool) -> u8 {
    let mut b = payload_type_num & 0x3F;
    if authenticated {
        b |= 0x40;
    }
    if encrypted {
        b |= 0x80;
    }
    b
}

fn split_payload_type(payload_type_byte: u8) -> (bool, bool, u8) {
    let is_encrypted = (payload_type_byte & 0x80) != 0;
    let is_authenticated = (payload_type_byte & 0x40) != 0;
    let payload_type_num = payload_type_byte & 0x3F;
    (is_authenticated, is_encrypted, payload_type_num)
}

/// Build the Open Session Request payload (Table 13-9).
pub(crate) fn build_open_session_request_payload(
    message_tag: u8,
    requested_privilege: PrivilegeLevel,
    remote_console_session_id: u32,
    auth_algorithm: u8,
    integrity_algorithm: u8,
    confidentiality_algorithm: u8,
) -> Vec<u8> {
    let mut p = Vec::with_capacity(32);

    // 1: Message Tag
    p.push(message_tag);
    // 2: requested maximum privilege level (0 means "maximum allowed")
    let requested_priv = if matches!(requested_privilege, PrivilegeLevel::Administrator) {
        0x00
    } else {
        requested_privilege.as_u8() & 0x0F
    };
    p.push(requested_priv);
    // 3: reserved
    p.push(0x00);
    // 4: reserved
    p.push(0x00);
    // 5:8 remote console session id (LSB first)
    p.extend_from_slice(&remote_console_session_id.to_le_bytes());

    // 9:16 authentication payload
    p.extend_from_slice(&build_algorithm_proposal(0x00, auth_algorithm));
    // 17:24 integrity payload
    p.extend_from_slice(&build_algorithm_proposal(0x01, integrity_algorithm));
    // 25:32 confidentiality payload
    p.extend_from_slice(&build_algorithm_proposal(0x02, confidentiality_algorithm));

    debug_assert_eq!(p.len(), 32);
    p
}

fn build_algorithm_proposal(payload_type: u8, algorithm: u8) -> [u8; 8] {
    [
        payload_type,
        0x00,
        0x00,
        0x08,
        algorithm & 0x3F,
        0x00,
        0x00,
        0x00,
    ]
}

#[derive(Debug, Clone)]
pub(crate) struct OpenSessionResponse {
    pub message_tag: u8,
    pub status_code: u8,
    #[allow(dead_code)]
    pub max_privilege_level: u8,
    pub remote_console_session_id: u32,
    pub managed_system_session_id: u32,
    pub selected_auth_algorithm: u8,
    pub selected_integrity_algorithm: u8,
    pub selected_confidentiality_algorithm: u8,
}

pub(crate) fn parse_open_session_response_payload(payload: &[u8]) -> Result<OpenSessionResponse> {
    if payload.len() < 8 {
        return Err(Error::Protocol("open session response payload too short"));
    }

    let message_tag = payload[0];
    let status_code = payload[1];
    let max_privilege_level = payload[2];

    let remote_console_session_id = u32::from_le_bytes(
        payload[4..8]
            .try_into()
            .map_err(|_| Error::Protocol("invalid remote session id"))?,
    );

    if status_code != 0x00 {
        return Ok(OpenSessionResponse {
            message_tag,
            status_code,
            max_privilege_level,
            remote_console_session_id,
            managed_system_session_id: 0,
            selected_auth_algorithm: 0,
            selected_integrity_algorithm: 0,
            selected_confidentiality_algorithm: 0,
        });
    }

    if payload.len() < 36 {
        return Err(Error::Protocol("open session response payload too short"));
    }

    let managed_system_session_id = u32::from_le_bytes(
        payload[8..12]
            .try_into()
            .map_err(|_| Error::Protocol("invalid managed session id"))?,
    );

    // Selected algorithms are encoded in byte 5 of each 8-byte block.
    let selected_auth_algorithm = payload[12 + 4] & 0x3F;
    let selected_integrity_algorithm = payload[20 + 4] & 0x3F;
    let selected_confidentiality_algorithm = payload[28 + 4] & 0x3F;

    Ok(OpenSessionResponse {
        message_tag,
        status_code,
        max_privilege_level,
        remote_console_session_id,
        managed_system_session_id,
        selected_auth_algorithm,
        selected_integrity_algorithm,
        selected_confidentiality_algorithm,
    })
}

/// Build RAKP Message 1 payload (Table 13-11).
pub(crate) fn build_rakp_message_1_payload(
    message_tag: u8,
    managed_system_session_id: u32,
    console_random: &[u8; 16],
    requested_privilege: PrivilegeLevel,
    username: &[u8],
) -> Result<Vec<u8>> {
    if username.len() > 16 {
        return Err(Error::Protocol("username too long (max 16 bytes)"));
    }

    let mut p = Vec::with_capacity(28 + username.len());

    p.push(message_tag);
    p.extend_from_slice(&[0x00, 0x00, 0x00]);
    p.extend_from_slice(&managed_system_session_id.to_le_bytes());
    p.extend_from_slice(console_random);

    // Requested maximum privilege level (Role) with bit4=0 (do username/priv lookup).
    let role = requested_privilege.as_u8() & 0x0F;
    p.push(role);
    p.extend_from_slice(&[0x00, 0x00]);

    p.push(username.len() as u8);
    p.extend_from_slice(username);

    Ok(p)
}

#[derive(Debug, Clone)]
pub(crate) struct RakpMessage2 {
    pub message_tag: u8,
    pub status_code: u8,
    pub remote_console_session_id: u32,
    pub bmc_random: [u8; 16],
    pub bmc_guid: [u8; 16],
    pub key_exchange_auth_code: [u8; 20],
}

pub(crate) fn parse_rakp_message_2_payload(payload: &[u8]) -> Result<RakpMessage2> {
    if payload.len() < 40 + 20 {
        return Err(Error::Protocol("RAKP message 2 payload too short"));
    }

    let message_tag = payload[0];
    let status_code = payload[1];

    let remote_console_session_id = u32::from_le_bytes(
        payload[4..8]
            .try_into()
            .map_err(|_| Error::Protocol("invalid remote session id"))?,
    );

    let bmc_random: [u8; 16] = payload[8..24]
        .try_into()
        .map_err(|_| Error::Protocol("invalid bmc random"))?;

    let bmc_guid: [u8; 16] = payload[24..40]
        .try_into()
        .map_err(|_| Error::Protocol("invalid bmc guid"))?;

    let key_exchange_auth_code: [u8; 20] = payload[40..60]
        .try_into()
        .map_err(|_| Error::Protocol("invalid key exchange auth code"))?;

    Ok(RakpMessage2 {
        message_tag,
        status_code,
        remote_console_session_id,
        bmc_random,
        bmc_guid,
        key_exchange_auth_code,
    })
}

/// Build RAKP Message 3 payload (Table 13-13).
pub(crate) fn build_rakp_message_3_payload(
    message_tag: u8,
    managed_system_session_id: u32,
    key_exchange_auth_code: &[u8; 20],
) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + 20);
    p.push(message_tag);
    p.push(0x00); // status code (always 00h for request)
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&managed_system_session_id.to_le_bytes());
    p.extend_from_slice(key_exchange_auth_code);
    p
}

#[derive(Debug, Clone)]
pub(crate) struct RakpMessage4 {
    pub message_tag: u8,
    pub status_code: u8,
    pub remote_console_session_id: u32,
    pub integrity_check_value: [u8; 12],
}

pub(crate) fn parse_rakp_message_4_payload(payload: &[u8]) -> Result<RakpMessage4> {
    if payload.len() < 8 {
        return Err(Error::Protocol("RAKP message 4 payload too short"));
    }

    let message_tag = payload[0];
    let status_code = payload[1];

    let remote_console_session_id = u32::from_le_bytes(
        payload[4..8]
            .try_into()
            .map_err(|_| Error::Protocol("invalid remote session id"))?,
    );

    if status_code != 0x00 {
        return Ok(RakpMessage4 {
            message_tag,
            status_code,
            remote_console_session_id,
            integrity_check_value: [0u8; 12],
        });
    }

    if payload.len() < 8 + 12 {
        return Err(Error::Protocol("RAKP message 4 payload too short"));
    }

    let integrity_check_value: [u8; 12] = payload[8..20]
        .try_into()
        .map_err(|_| Error::Protocol("invalid ICV"))?;

    Ok(RakpMessage4 {
        message_tag,
        status_code,
        remote_console_session_id,
        integrity_check_value,
    })
}

/// Compute the RAKP Message 2 key exchange authentication code (HMAC-SHA1).
#[allow(clippy::too_many_arguments)]
pub(crate) fn rakp2_key_exchange_auth_code_sha1(
    user_key: &[u8; 20],
    remote_console_session_id: u32,
    managed_system_session_id: u32,
    console_random: &[u8; 16],
    bmc_random: &[u8; 16],
    bmc_guid: &[u8; 16],
    requested_privilege: PrivilegeLevel,
    username: &[u8],
) -> Result<[u8; 20]> {
    let mut data = Vec::with_capacity(4 + 4 + 16 + 16 + 16 + 1 + 1 + username.len());
    data.extend_from_slice(&remote_console_session_id.to_le_bytes());
    data.extend_from_slice(&managed_system_session_id.to_le_bytes());
    data.extend_from_slice(console_random);
    data.extend_from_slice(bmc_random);
    data.extend_from_slice(bmc_guid);
    data.push(requested_privilege.as_u8() & 0x0F);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_sha1(user_key, &data)
}

/// Compute the Session Integrity Key (SIK) (HMAC-SHA1, no truncation).
pub(crate) fn compute_sik_sha1(
    kg: &[u8; 20],
    console_random: &[u8; 16],
    bmc_random: &[u8; 16],
    requested_privilege: PrivilegeLevel,
    username: &[u8],
) -> Result<[u8; 20]> {
    let mut data = Vec::with_capacity(16 + 16 + 1 + 1 + username.len());
    data.extend_from_slice(console_random);
    data.extend_from_slice(bmc_random);
    data.push(requested_privilege.as_u8() & 0x0F);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_sha1(kg, &data)
}

/// Compute the RAKP Message 3 key exchange authentication code (HMAC-SHA1).
pub(crate) fn rakp3_key_exchange_auth_code_sha1(
    user_key: &[u8; 20],
    bmc_random: &[u8; 16],
    remote_console_session_id: u32,
    requested_privilege: PrivilegeLevel,
    username: &[u8],
) -> Result<[u8; 20]> {
    let mut data = Vec::with_capacity(16 + 4 + 1 + 1 + username.len());
    data.extend_from_slice(bmc_random);
    data.extend_from_slice(&remote_console_session_id.to_le_bytes());
    data.push(requested_privilege.as_u8() & 0x0F);
    data.push(username.len() as u8);
    data.extend_from_slice(username);

    hmac_sha1(user_key, &data)
}

/// Compute the RAKP Message 4 integrity check value (HMAC-SHA1-96) using SIK.
pub(crate) fn rakp4_integrity_check_value_sha1_96(
    sik: &[u8; 20],
    console_random: &[u8; 16],
    managed_system_session_id: u32,
    bmc_guid: &[u8; 16],
) -> Result<[u8; 12]> {
    let mut data = Vec::with_capacity(16 + 4 + 16);
    data.extend_from_slice(console_random);
    data.extend_from_slice(&managed_system_session_id.to_le_bytes());
    data.extend_from_slice(bmc_guid);

    hmac_sha1_truncated_12(sik, &data)
}

/// Derive the security context (K1 + AES key) from SIK.
pub(crate) fn derive_security_context_sha1(sik: &[u8; 20]) -> Result<SecurityContext> {
    let (k1, k2) = derive_k1_k2_sha1(sik)?;
    let aes_key = derive_aes_key_from_k2(&k2);
    Ok(SecurityContext { k1, aes_key })
}

/// Encrypt an IPMI payload using AES-CBC-128 and IPMI confidentiality padding.
///
/// Returns `iv || ciphertext`.
#[allow(dead_code)]
pub(crate) fn encrypt_payload_aes_cbc(
    plaintext_payload: &[u8],
    aes_key: &[u8; 16],
    iv: &[u8; 16],
) -> Result<Vec<u8>> {
    // Confidentiality trailer: [pad bytes][pad_len]
    let base = plaintext_payload.len() + 1;
    let pad_len = (16 - (base % 16)) % 16;

    let mut to_encrypt = Vec::with_capacity(base + pad_len);
    to_encrypt.extend_from_slice(plaintext_payload);
    for i in 0..pad_len {
        to_encrypt.push((i + 1) as u8);
    }
    to_encrypt.push(pad_len as u8);

    let ciphertext = aes128_cbc_encrypt(aes_key, iv, &to_encrypt)?;

    let mut out = Vec::with_capacity(16 + ciphertext.len());
    out.extend_from_slice(iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Compute the standard 2's complement checksum used by IPMI LAN messages.
fn ipmi_checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    (!sum).wrapping_add(1)
}

/// Encode an IPMI LAN message.
pub(crate) fn encode_ipmi_lan_request(
    netfn: u8,
    cmd: u8,
    rq_seq: u8,
    data: &[u8],
) -> Result<Vec<u8>> {
    if rq_seq > 0x3F {
        return Err(Error::Protocol("rq_seq must be 6-bit"));
    }

    // Constants per LAN interface.
    let responder_addr: u8 = 0x20;
    let requester_addr: u8 = 0x81;
    let lun: u8 = 0;

    let netfn_lun = (netfn << 2) | (lun & 0x03);
    let csum1 = ipmi_checksum(&[responder_addr, netfn_lun]);

    let rq_seq_lun = (rq_seq << 2) | (lun & 0x03);

    let mut msg = Vec::with_capacity(7 + data.len() + 1);
    msg.push(responder_addr);
    msg.push(netfn_lun);
    msg.push(csum1);

    msg.push(requester_addr);
    msg.push(rq_seq_lun);
    msg.push(cmd);
    msg.extend_from_slice(data);

    let csum2 = ipmi_checksum(&msg[3..]);
    msg.push(csum2);

    Ok(msg)
}

/// Decode and validate an IPMI LAN response message.
pub(crate) fn decode_ipmi_lan_response(
    expected_netfn: u8,
    expected_cmd: u8,
    expected_rq_seq: u8,
    msg: &[u8],
) -> Result<crate::types::RawResponse> {
    if msg.len() < 7 + 1 {
        return Err(Error::Protocol("IPMI response too short"));
    }

    let rs_addr = msg[0];
    let netfn_lun = msg[1];
    let csum1 = msg[2];

    // Validate checksum1 (sum of bytes including checksum must be zero).
    if rs_addr.wrapping_add(netfn_lun).wrapping_add(csum1) != 0 {
        return Err(Error::Protocol("invalid IPMI checksum1"));
    }

    let rq_addr = msg[3];
    let rq_seq_lun = msg[4];
    let cmd = msg[5];

    // Validate checksum2.
    let provided_csum2 = *msg.last().ok_or(Error::Protocol("missing checksum2"))?;
    let sum2 = msg[3..msg.len() - 1]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b))
        .wrapping_add(provided_csum2);
    if sum2 != 0 {
        return Err(Error::Protocol("invalid IPMI checksum2"));
    }

    let expected_netfn_lun = (expected_netfn + 1) << 2;
    if rs_addr != 0x81 || netfn_lun != expected_netfn_lun {
        return Err(Error::Protocol("unexpected responder or netfn"));
    }

    if rq_addr != 0x20 {
        return Err(Error::Protocol("unexpected requester address"));
    }

    let expected_rq_seq_lun = expected_rq_seq << 2;
    if rq_seq_lun != expected_rq_seq_lun {
        return Err(Error::Protocol("unexpected request sequence"));
    }

    if cmd != expected_cmd {
        return Err(Error::Protocol("unexpected command"));
    }

    let completion_code = msg[6];
    let data = if msg.len() > 8 {
        msg[7..msg.len() - 1].to_vec()
    } else {
        Vec::new()
    };

    Ok(crate::types::RawResponse {
        completion_code,
        data,
    })
}

/// Convenience helpers for key normalization in the protocol layer.
#[allow(dead_code)]
pub(crate) fn user_key_sha1_from_secret(secret: &[u8]) -> [u8; 20] {
    normalize_key_sha1(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipmi_request_encoding_get_device_id_no_data() {
        let msg = encode_ipmi_lan_request(0x06, 0x01, 0, &[]).expect("encode");
        assert_eq!(msg, vec![0x20, 0x18, 0xC8, 0x81, 0x00, 0x01, 0x7E]);
    }

    #[test]
    fn ipmi_response_decoding_basic() {
        let response = vec![
            0x81, 0x1C, 0x63, // rs_addr, netfn/lun, checksum1
            0x20, 0x00, 0x01, // rq_addr, rq_seq/lun, cmd
            0x00, // completion code
            0x20, 0x01, 0x02, // data (3 bytes)
            0xBC, // checksum2
        ];

        let decoded = decode_ipmi_lan_response(0x06, 0x01, 0, &response).expect("decode");
        assert_eq!(decoded.completion_code, 0x00);
        assert_eq!(decoded.data, vec![0x20, 0x01, 0x02]);
    }

    #[test]
    fn ipmi_response_decoding_detects_bad_checksum() {
        let mut response = vec![
            0x81, 0x1C, 0x63, // rs_addr, netfn/lun, checksum1
            0x20, 0x00, 0x01, // rq_addr, rq_seq/lun, cmd
            0x00, // completion code
            0x20, 0x01, 0x02, // data
            0xBC, // checksum2
        ];

        // Corrupt a byte.
        response[7] ^= 0xFF;

        let err = decode_ipmi_lan_response(0x06, 0x01, 0, &response).unwrap_err();
        let _ = format!("{err}");
    }
}
