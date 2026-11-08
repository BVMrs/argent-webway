//! Error names from spec §2.2.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E {
    IdentifierInvalid,
    StatementInvalid,
    StatementUntrusted,
    StatementExpired,
    StatementRevoked,
    CapabilityMissing,
    CapabilityInvalid,
    CapabilityDenied,
    CapabilityRevoked,
    RevocationStatusUnavailable,
    InviteInvalid,
    InviteExpired,
    InviteConsumed,
    MandateRequired,
}

impl E {
    pub fn name(self) -> String {
        format!("{self:?}")
    }
}

pub type R<T> = Result<T, E>;
