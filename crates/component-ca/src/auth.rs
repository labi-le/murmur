use murmur_component_tls::utls::ClientAuthType;

pub const NO_CLIENT_CERT: ClientAuthType = ClientAuthType::NO_CLIENT_CERT;
pub const REQUEST_CLIENT_CERT: ClientAuthType = ClientAuthType::REQUEST_CLIENT_CERT;
pub const REQUIRE_ANY_CLIENT_CERT: ClientAuthType = ClientAuthType::REQUIRE_ANY_CLIENT_CERT;
pub const VERIFY_CLIENT_CERT_IF_GIVEN: ClientAuthType = ClientAuthType::VERIFY_CLIENT_CERT_IF_GIVEN;
pub const REQUIRE_AND_VERIFY_CLIENT_CERT: ClientAuthType = ClientAuthType::REQUIRE_AND_VERIFY_CLIENT_CERT;

#[must_use]
pub fn client_auth_type_from_string(s: &str) -> ClientAuthType {
    match s {
        "request" => REQUEST_CLIENT_CERT,
        "require-any" => REQUIRE_ANY_CLIENT_CERT,
        "verify-if-given" => VERIFY_CLIENT_CERT_IF_GIVEN,
        "require-and-verify" => REQUIRE_AND_VERIFY_CLIENT_CERT,
        _ => NO_CLIENT_CERT,
    }
}

#[must_use]
pub const fn client_auth_type_to_string(t: ClientAuthType) -> &'static str {
    match t {
        REQUEST_CLIENT_CERT => "request",
        REQUIRE_ANY_CLIENT_CERT => "require-any",
        VERIFY_CLIENT_CERT_IF_GIVEN => "verify-if-given",
        REQUIRE_AND_VERIFY_CLIENT_CERT => "require-and-verify",
        _ => "",
    }
}
