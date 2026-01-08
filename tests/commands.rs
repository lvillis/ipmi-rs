use ipmi::commands::{
    ChassisControlCommand, Command, GetChannelAuthCapabilities, GetChassisStatus, GetDeviceId,
    GetSelfTestResults, GetSystemGuid,
};
use ipmi::{ChassisControl, Error, PrivilegeLevel, RawResponse, SelfTestResult};

#[test]
fn get_device_id_parses_response() {
    let response = RawResponse {
        completion_code: 0x00,
        data: vec![
            0x20, 0x01, 0x02, 0x43, 0x02, 0x00, 0xA2, 0x02, 0x00, 0x00, 0x01, 0x00, 0x06, 0x2B,
            0x2B,
        ],
    };

    let parsed = GetDeviceId.parse_response(response).expect("parse");
    assert_eq!(parsed.device_id, 0x20);
    assert_eq!(parsed.device_revision, 0x01);
    assert_eq!(parsed.firmware_major, 0x02);
    assert_eq!(parsed.firmware_minor, 0x43);
    assert_eq!(parsed.ipmi_version, 0x02);
    assert_eq!(parsed.manufacturer_id, 0x0000_02A2);
    assert_eq!(parsed.product_id, 0x0100);
    assert_eq!(parsed.aux_firmware_revision, [0x00, 0x06, 0x2B, 0x2B]);
}

#[test]
fn completion_code_is_reported() {
    let response = RawResponse {
        completion_code: 0xC1,
        data: vec![0xAA, 0xBB],
    };

    let err = GetSelfTestResults
        .parse_response(response)
        .expect_err("expected error");
    assert!(matches!(
        err,
        Error::CompletionCode {
            completion_code: 0xC1
        }
    ));
}

#[test]
fn get_system_guid_parses_response() {
    let mut data = vec![0u8; 16];
    for (i, b) in data.iter_mut().enumerate() {
        *b = i as u8;
    }

    let response = RawResponse {
        completion_code: 0x00,
        data,
    };

    let guid = GetSystemGuid.parse_response(response).expect("parse");
    assert_eq!(
        guid.bytes,
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
}

#[test]
fn get_chassis_status_parses_response() {
    let response = RawResponse {
        completion_code: 0x00,
        data: vec![0x5F, 0x19, 0x0F, 0xFF],
    };

    let status = GetChassisStatus.parse_response(response).expect("parse");
    assert!(status.system_power_on);
    assert!(status.power_overload);
    assert!(status.last_power_event.ac_failed);
    assert!(status.front_panel_controls.is_some());
}

#[test]
fn chassis_control_encodes_request_data() {
    let cmd = ChassisControlCommand {
        control: ChassisControl::PowerUp,
    };
    assert_eq!(cmd.request_data(), vec![0x01]);
}

#[test]
fn get_channel_auth_capabilities_encodes_request_data() {
    let cmd = GetChannelAuthCapabilities::new(0x02, PrivilegeLevel::Administrator);
    assert_eq!(cmd.request_data(), vec![0x82, 0x04]);

    let cmd = cmd.without_v2_data();
    assert_eq!(cmd.request_data(), vec![0x02, 0x04]);
}

#[test]
fn get_self_test_results_parses_passed_variant() {
    let response = RawResponse {
        completion_code: 0x00,
        data: vec![0x55, 0x00],
    };
    let parsed = GetSelfTestResults.parse_response(response).expect("parse");
    assert!(matches!(parsed, SelfTestResult::Passed));
}
