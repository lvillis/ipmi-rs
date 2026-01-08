use core::fmt;

/// The privilege level requested for the IPMI session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivilegeLevel {
    /// Callback privilege.
    Callback = 0x01,
    /// User privilege.
    User = 0x02,
    /// Operator privilege.
    Operator = 0x03,
    /// Administrator privilege.
    Administrator = 0x04,
    /// OEM-defined privilege.
    Oem = 0x05,
}

impl PrivilegeLevel {
    pub(crate) fn as_u8(self) -> u8 {
        self as u8
    }
}

/// A raw IPMI response.
#[derive(Clone, PartialEq, Eq)]
pub struct RawResponse {
    /// IPMI completion code.
    pub completion_code: u8,
    /// Payload bytes after the completion code.
    pub data: Vec<u8>,
}

impl fmt::Debug for RawResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawResponse")
            .field(
                "completion_code",
                &format_args!("{:#04x}", self.completion_code),
            )
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// Parsed response for the `Get Device ID` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceId {
    /// Device ID (BMC-defined).
    pub device_id: u8,
    /// Device revision (lower 4 bits are the revision).
    pub device_revision: u8,
    /// Firmware major revision.
    pub firmware_major: u8,
    /// Firmware minor revision.
    pub firmware_minor: u8,
    /// IPMI version as BCD (e.g. 0x02 for 2.0).
    pub ipmi_version: u8,
    /// Manufacturer ID (24-bit, least-significant byte first).
    pub manufacturer_id: u32,
    /// Product ID.
    pub product_id: u16,
    /// Auxiliary firmware revision (4 bytes).
    pub aux_firmware_revision: [u8; 4],
}

/// Parsed response for the `Get Self Test Results` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfTestResult {
    /// Self-test passed.
    Passed,
    /// Self-test is not implemented.
    NotImplemented,
    /// Device error details.
    DeviceError(SelfTestDeviceError),
    /// Fatal hardware error with a device-specific error code.
    FatalError(u8),
    /// Device-specific failure (code, detail).
    DeviceSpecific {
        /// Self-test result code.
        code: u8,
        /// Device-specific detail byte.
        detail: u8,
    },
}

/// Detailed device error flags from self-test result code 0x57.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfTestDeviceError {
    /// Firmware corrupted.
    pub firmware_corrupted: bool,
    /// Boot block corrupted.
    pub boot_block_corrupted: bool,
    /// FRU internal use area corrupted.
    pub fru_internal_corrupted: bool,
    /// SDR repository empty.
    pub sdr_repository_empty: bool,
    /// IPMB not responding.
    pub ipmb_not_responding: bool,
    /// Cannot access BMC FRU.
    pub bmc_fru_access_error: bool,
    /// Cannot access SDR repository.
    pub sdr_repository_access_error: bool,
    /// Cannot access SEL device.
    pub sel_access_error: bool,
}

impl SelfTestDeviceError {
    pub(crate) fn from_bits(bits: u8) -> Self {
        Self {
            firmware_corrupted: bits & 0x01 != 0,
            boot_block_corrupted: bits & 0x02 != 0,
            fru_internal_corrupted: bits & 0x04 != 0,
            sdr_repository_empty: bits & 0x08 != 0,
            ipmb_not_responding: bits & 0x10 != 0,
            bmc_fru_access_error: bits & 0x20 != 0,
            sdr_repository_access_error: bits & 0x40 != 0,
            sel_access_error: bits & 0x80 != 0,
        }
    }
}

/// Raw system GUID bytes as returned by `Get System GUID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemGuid {
    /// Raw GUID bytes.
    pub bytes: [u8; 16],
}

/// Power restore policy reported by `Get Chassis Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerRestorePolicy {
    /// Always remain off after AC loss.
    AlwaysOff,
    /// Restore previous power state after AC loss.
    Previous,
    /// Always power on after AC loss.
    AlwaysOn,
    /// Reserved or unknown value.
    Unknown(u8),
}

/// Last power event flags reported by `Get Chassis Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastPowerEvent {
    /// AC failed.
    pub ac_failed: bool,
    /// Power overload.
    pub power_overload: bool,
    /// Power interlock activated.
    pub power_interlock: bool,
    /// Power fault.
    pub power_fault: bool,
    /// Power on command issued.
    pub power_on_command: bool,
}

/// Optional front panel controls (byte 4) from `Get Chassis Status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontPanelControls {
    /// Sleep button disable is allowed.
    pub sleep_button_disable_allowed: bool,
    /// Diagnostic button disable is allowed.
    pub diag_button_disable_allowed: bool,
    /// Reset button disable is allowed.
    pub reset_button_disable_allowed: bool,
    /// Power button disable is allowed.
    pub power_button_disable_allowed: bool,
    /// Sleep button is currently disabled.
    pub sleep_button_disabled: bool,
    /// Diagnostic button is currently disabled.
    pub diag_button_disabled: bool,
    /// Reset button is currently disabled.
    pub reset_button_disabled: bool,
    /// Power button is currently disabled.
    pub power_button_disabled: bool,
}

/// Parsed response for the `Get Chassis Status` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChassisStatus {
    /// System power state.
    pub system_power_on: bool,
    /// Power overload state.
    pub power_overload: bool,
    /// Power interlock state.
    pub power_interlock: bool,
    /// Main power fault state.
    pub main_power_fault: bool,
    /// Power control fault state.
    pub power_control_fault: bool,
    /// Power restore policy.
    pub power_restore_policy: PowerRestorePolicy,
    /// Last power event flags.
    pub last_power_event: LastPowerEvent,
    /// Chassis intrusion state.
    pub chassis_intrusion: bool,
    /// Front panel lockout state.
    pub front_panel_lockout: bool,
    /// Drive fault state.
    pub drive_fault: bool,
    /// Cooling/fan fault state.
    pub cooling_fan_fault: bool,
    /// Optional front panel control flags.
    pub front_panel_controls: Option<FrontPanelControls>,
}

/// Chassis control operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChassisControl {
    /// Power down the system.
    PowerDown,
    /// Power up the system.
    PowerUp,
    /// Power cycle the system.
    PowerCycle,
    /// Hard reset the system.
    HardReset,
    /// Pulse diagnostic interrupt.
    PulseDiagnostic,
    /// ACPI soft shutdown.
    AcpiSoft,
}

impl ChassisControl {
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::PowerDown => 0x00,
            Self::PowerUp => 0x01,
            Self::PowerCycle => 0x02,
            Self::HardReset => 0x03,
            Self::PulseDiagnostic => 0x04,
            Self::AcpiSoft => 0x05,
        }
    }
}

/// Parsed response for `Get Channel Authentication Capabilities`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelAuthCapabilities {
    /// Channel number.
    pub channel_number: u8,
    /// Indicates IPMI v2.0 data is available in the response.
    pub v20_data_available: bool,
    /// IPMI v1.5 enabled authentication types (bitmask).
    pub enabled_auth_types: u8,
    /// Per-message authentication is disabled when true.
    pub per_message_auth_disabled: bool,
    /// User-level authentication is disabled when true.
    pub user_level_auth_disabled: bool,
    /// One or more non-null user names exist.
    pub non_null_usernames: bool,
    /// One or more null user names with non-null passwords exist.
    pub null_usernames: bool,
    /// Anonymous login (null user/null password) is enabled.
    pub anonymous_login_enabled: bool,
    /// Non-zero Kg key is configured (two-key login).
    pub kg_nonzero: bool,
    /// Channel supports IPMI v1.5.
    pub supports_ipmi_v1_5: bool,
    /// Channel supports IPMI v2.0.
    pub supports_ipmi_v2_0: bool,
    /// OEM IANA enterprise number for OEM auth types, if present.
    pub oem_id: Option<u32>,
    /// OEM auxiliary data for OEM auth types, if present.
    pub oem_aux_data: Option<u8>,
}
