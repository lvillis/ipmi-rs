use crate::error::{Error, Result};
use crate::types::{
    ChannelAuthCapabilities, ChassisControl, ChassisStatus, DeviceId, FrontPanelControls,
    LastPowerEvent, PowerRestorePolicy, PrivilegeLevel, RawResponse, SelfTestDeviceError,
    SelfTestResult, SystemGuid,
};

/// A typed IPMI command (single request/response).
pub trait Command {
    /// Parsed output type.
    type Output;

    /// Network Function (NetFn) for the request.
    const NETFN: u8;

    /// Command number.
    const CMD: u8;

    /// Encode request payload bytes (excluding NetFn/Cmd framing).
    fn request_data(&self) -> Vec<u8>;

    /// Parse a raw response into the typed output.
    fn parse_response(&self, response: RawResponse) -> Result<Self::Output>;
}

fn ok_data(response: &RawResponse) -> Result<&[u8]> {
    if response.completion_code != 0x00 {
        return Err(Error::CompletionCode {
            completion_code: response.completion_code,
        });
    }
    Ok(&response.data)
}

/// `Get Device ID` (App NetFn, cmd 0x01).
#[derive(Debug, Clone, Copy)]
pub struct GetDeviceId;

impl Command for GetDeviceId {
    type Output = DeviceId;
    const NETFN: u8 = 0x06;
    const CMD: u8 = 0x01;

    fn request_data(&self) -> Vec<u8> {
        Vec::new()
    }

    fn parse_response(&self, response: RawResponse) -> Result<Self::Output> {
        parse_device_id(ok_data(&response)?)
    }
}

/// `Get Self Test Results` (App NetFn, cmd 0x04).
#[derive(Debug, Clone, Copy)]
pub struct GetSelfTestResults;

impl Command for GetSelfTestResults {
    type Output = SelfTestResult;
    const NETFN: u8 = 0x06;
    const CMD: u8 = 0x04;

    fn request_data(&self) -> Vec<u8> {
        Vec::new()
    }

    fn parse_response(&self, response: RawResponse) -> Result<Self::Output> {
        parse_self_test_result(ok_data(&response)?)
    }
}

/// `Get System GUID` (App NetFn, cmd 0x37).
#[derive(Debug, Clone, Copy)]
pub struct GetSystemGuid;

impl Command for GetSystemGuid {
    type Output = SystemGuid;
    const NETFN: u8 = 0x06;
    const CMD: u8 = 0x37;

    fn request_data(&self) -> Vec<u8> {
        Vec::new()
    }

    fn parse_response(&self, response: RawResponse) -> Result<Self::Output> {
        parse_system_guid(ok_data(&response)?)
    }
}

/// `Get Chassis Status` (Chassis NetFn, cmd 0x01).
#[derive(Debug, Clone, Copy)]
pub struct GetChassisStatus;

impl Command for GetChassisStatus {
    type Output = ChassisStatus;
    const NETFN: u8 = 0x00;
    const CMD: u8 = 0x01;

    fn request_data(&self) -> Vec<u8> {
        Vec::new()
    }

    fn parse_response(&self, response: RawResponse) -> Result<Self::Output> {
        parse_chassis_status(ok_data(&response)?)
    }
}

/// `Chassis Control` (Chassis NetFn, cmd 0x02).
#[derive(Debug, Clone, Copy)]
pub struct ChassisControlCommand {
    /// Control operation.
    pub control: ChassisControl,
}

impl Command for ChassisControlCommand {
    type Output = ();
    const NETFN: u8 = 0x00;
    const CMD: u8 = 0x02;

    fn request_data(&self) -> Vec<u8> {
        vec![self.control.as_u8()]
    }

    fn parse_response(&self, response: RawResponse) -> Result<Self::Output> {
        let _ = ok_data(&response)?;
        Ok(())
    }
}

/// `Get Channel Authentication Capabilities` (App NetFn, cmd 0x38).
#[derive(Debug, Clone, Copy)]
pub struct GetChannelAuthCapabilities {
    /// Channel number (low nibble).
    pub channel: u8,
    /// Privilege to query.
    pub privilege: PrivilegeLevel,
    /// Request that IPMI v2.0 data be included when available.
    pub request_v2_data: bool,
}

impl GetChannelAuthCapabilities {
    /// Create a query that requests IPMI v2.0 data (when supported).
    pub fn new(channel: u8, privilege: PrivilegeLevel) -> Self {
        Self {
            channel,
            privilege,
            request_v2_data: true,
        }
    }

    /// Return a variant that does not request IPMI v2.0 data.
    pub fn without_v2_data(self) -> Self {
        Self {
            request_v2_data: false,
            ..self
        }
    }
}

impl Command for GetChannelAuthCapabilities {
    type Output = ChannelAuthCapabilities;
    const NETFN: u8 = 0x06;
    const CMD: u8 = 0x38;

    fn request_data(&self) -> Vec<u8> {
        let channel = if self.request_v2_data {
            self.channel | 0x80
        } else {
            self.channel & 0x7F
        };
        vec![channel, self.privilege.as_u8() & 0x0F]
    }

    fn parse_response(&self, response: RawResponse) -> Result<Self::Output> {
        parse_channel_auth_capabilities(ok_data(&response)?)
    }
}

pub(crate) fn parse_device_id(data: &[u8]) -> Result<DeviceId> {
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

pub(crate) fn parse_self_test_result(data: &[u8]) -> Result<SelfTestResult> {
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

pub(crate) fn parse_system_guid(data: &[u8]) -> Result<SystemGuid> {
    if data.len() < 16 {
        return Err(Error::Protocol("Get System GUID response too short"));
    }

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[..16]);
    Ok(SystemGuid { bytes })
}

pub(crate) fn parse_chassis_status(data: &[u8]) -> Result<ChassisStatus> {
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

pub(crate) fn parse_channel_auth_capabilities(data: &[u8]) -> Result<ChannelAuthCapabilities> {
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
