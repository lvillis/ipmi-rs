use rand::RngCore;

use crate::error::{Error, Result};
use crate::protocol::{
    decode_ipmi_lan_response, decode_rmcpplus_packet, encode_ipmi_lan_request,
    encode_rmcpplus_packet, encrypt_payload_aes_cbc, payload_type,
};
use crate::session::Session;
use crate::types::RawResponse;

#[derive(Debug)]
pub(crate) struct ClientCore {
    session: Session,
    rq_seq: u8,
    closed: bool,
}

impl ClientCore {
    pub(crate) fn new(session: Session) -> Self {
        Self {
            session,
            rq_seq: 0,
            closed: false,
        }
    }

    pub(crate) fn managed_session_id_bytes_le(&self) -> [u8; 4] {
        self.session.managed_session_id.to_le_bytes()
    }

    pub(crate) fn mark_closed(&mut self) {
        self.closed = true;
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    pub(crate) fn build_rmcpplus_ipmi_request(
        &mut self,
        netfn: u8,
        cmd: u8,
        data: &[u8],
    ) -> Result<(u8, Vec<u8>)> {
        if self.closed {
            return Err(Error::Protocol("session is closed"));
        }

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

        Ok((rq_seq, packet))
    }

    pub(crate) fn decode_rmcpplus_ipmi_response(
        &self,
        expected_netfn: u8,
        expected_cmd: u8,
        expected_rq_seq: u8,
        response_bytes: &[u8],
    ) -> Result<RawResponse> {
        if self.closed {
            return Err(Error::Protocol("session is closed"));
        }

        let decoded = decode_rmcpplus_packet(response_bytes, Some(&self.session.security))?;
        crate::debug::dump_hex("ipmi response payload", &decoded.payload);

        if decoded.payload_type != payload_type::IPMI {
            return Err(Error::Protocol("unexpected RMCP+ payload type"));
        }

        // Some implementations may echo either SIDC or SIDM in the header. Accept either.
        if decoded.session_id != self.session.managed_session_id
            && decoded.session_id != self.session.remote_session_id
        {
            return Err(Error::Protocol("unexpected RMCP+ session id"));
        }

        decode_ipmi_lan_response(
            expected_netfn,
            expected_cmd,
            expected_rq_seq,
            &decoded.payload,
        )
    }

    fn allocate_rq_seq(&mut self) -> u8 {
        // rq_seq is 6-bit. We keep a u8 and wrap at 64.
        let current = self.rq_seq;
        self.rq_seq = (self.rq_seq + 1) & 0x3F;
        current
    }
}
