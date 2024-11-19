use super::*;
use alloc::string::String;

#[test]
fn password_correct() {
    let signature_request = SignatureRequest {
        message: b"password".to_vec(),
        auxilary_data: None,
    };

    assert!(ProvideAPassword::evaluate(signature_request, None, None).is_ok());
}

#[test]
fn no_message() {
    let signature_request = SignatureRequest {
        message: Vec::new(),
        auxilary_data: None,
    };

    assert!(ProvideAPassword::evaluate(signature_request, None, None).is_err());
}

#[test]
fn test_invalid_password() {
    let signature_request = SignatureRequest {
        message: b"invalid_password".to_vec(),
        auxilary_data: None,
    };

    if String::from_utf8(signature_request.message.clone()).unwrap() != saved_password {
        assert!(ProvideAPassword::evaluate(signature_request, None, None).is_err());
    }
}
