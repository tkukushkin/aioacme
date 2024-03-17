from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class OrderStatus(Enum):
    """
    Order objects are created in the "pending" state.  Once all of the
    authorizations listed in the order object are in the "valid" state,
    the order transitions to the "ready" state.  The order moves to the
    "processing" state after the client submits a request to the order's
    "finalize" URL and the CA begins the issuance process for the
    certificate.  Once the certificate is issued, the order enters the
    "valid" state.  If an error occurs at any of these stages, the order
    moves to the "invalid" state.  The order also moves to the "invalid"
    state if it expires or one of its authorizations enters a final state
    other than "valid" ("expired", "revoked", or "deactivated").
    """

    pending = 'pending'
    ready = 'ready'
    processing = 'processing'
    valid = 'valid'
    invalid = 'invalid'


class AuthorizationStatus(Enum):
    """
    Authorization objects are created in the "pending" state.  If one of
    the challenges listed in the authorization transitions to the "valid"
    state, then the authorization also changes to the "valid" state.  If
    the client attempts to fulfill a challenge and fails, or if there is
    an error while the authorization is still pending, then the
    authorization transitions to the "invalid" state.  Once the
    authorization is in the "valid" state, it can expire ("expired"), be
    deactivated by the client ("deactivated"), or revoked by the server ("revoked").
    """

    pending = 'pending'
    valid = 'valid'
    invalid = 'invalid'
    deactivated = 'deactivated'
    expired = 'expired'
    revoked = 'revoked'


class IdentifierType(Enum):
    dns = 'dns'
    ip = 'ip'


@dataclass(frozen=True, slots=True)
class Identifier:
    value: str
    """Value"""
    type: IdentifierType = IdentifierType.dns
    """Type"""


@dataclass(frozen=True, slots=True, kw_only=True)
class Error:
    type: str
    """A URI reference to a document with more information about the error."""
    detail: str
    """A short description of the error."""
    identifier: Identifier | None = None
    subproblems: list['Error'] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Order:
    uri: str
    """URI"""
    identifiers: Sequence[Identifier]
    """An array of identifier objects that the order pertains to."""
    authorizations: list[str]
    """
    For pending orders, the authorizations that the client needs to complete
    before the requested certificate can be issued (see Section 7.5),
    including unexpired authorizations that the client has completed in the
    past for identifiers specified in the order. The authorizations required
    are dictated by server policy; there may not be a 1:1 relationship between
    the order identifiers and the authorizations required.  For final orders
    (in the "valid" or "invalid" state), the authorizations that were
    completed. Each entry is a URL from which an authorization can be fetched
    with a POST-as-GET request.
    """
    status: OrderStatus
    """The status of this order."""
    expires: datetime | None = None
    """
    The timestamp after which the server will consider this order invalid.
    This field is REQUIRED for objects with "pending" or "valid"
    in the status field.
    """
    finalize: str
    """
    A URL that a CSR must be POSTed to once all of the order's authorizations
    are satisfied to finalize the order. The result of a successful
    finalization will be the population of the certificate URL for the order.
    """
    not_before: datetime | None = None
    """The requested value of the notBefore field in the certificate."""
    not_after: datetime | None = None
    """The requested value of the notAfter field in the certificate."""
    error: Error | None = None
    """The error that occurred while processing the order, if any."""
    certificate: str | None = None
    """
    A URL for the certificate that has been issued in response to this order.
    """


class ChallengeType(Enum):
    dns01 = 'dns-01'
    http01 = 'http-01'
    tlsalpn01 = 'tls-alpn-01'


class ChallengeStatus(Enum):
    """
    Challenge objects are created in the "pending" state.  They
    transition to the "processing" state when the client responds to the
    challenge (see Section 7.5.1) and the server begins attempting to
    validate that the client has completed the challenge.  Note that
    within the "processing" state, the server may attempt to validate the
    challenge multiple times (see Section 8.2).  Likewise, client
    requests for retries do not cause a state change.  If validation is
    successful, the challenge moves to the "valid" state; if there is an
    error, the challenge moves to the "invalid" state.
    """

    pending = 'pending'
    processing = 'processing'
    valid = 'valid'
    invalid = 'invalid'


@dataclass(frozen=True, slots=True, kw_only=True)
class Challenge:
    type: ChallengeType
    """The type of challenge encoded in the object."""
    url: str
    """The URL to which a response can be posted."""
    status: ChallengeStatus
    """The status of this challenge."""
    validated: datetime | None = None
    """
    The time at which the server validated
    this challenge, encoded in the format specified in [RFC3339].
    This field is REQUIRED if the "status" field is "valid".
    """
    error: Error | None = None
    """
    Error that occurred while the server was validating the challenge, if any.
    Multiple errors can be indicated by using subproblems Section 6.7.1.
    A challenge object with an error MUST have status equal to "invalid".
    """
    token: str
    """
    A random value that uniquely identifies the challenge. This value MUST
    have at least 128 bits of entropy. It MUST NOT contain any characters
    outside the base64url alphabet and MUST NOT include base64 padding
    characters ("=").
    """


@dataclass(frozen=True, slots=True, kw_only=True)
class Authorization:
    uri: str
    """URI"""
    identifier: Identifier
    """The identifier that the account is authorized to represent."""
    status: AuthorizationStatus
    """The status of this authorization."""
    expires: datetime | None = None
    """
    The timestamp after which the server
    will consider this authorization invalid, encoded in the format
    specified in [RFC3339].  This field is REQUIRED for objects with
    "valid" in the "status" field.
    """
    challenges: Sequence[Challenge]
    """
    For pending authorizations,
    the challenges that the client can fulfill in order to prove
    possession of the identifier.  For valid authorizations, the
    challenge that was validated.  For invalid authorizations, the
    challenge that was attempted and failed.  Each array entry is an
    object with parameters required to validate the challenge.  A
    client should attempt to fulfill one of these challenges, and a
    server should consider any one of the challenges sufficient to
    make the authorization valid.
    """
    wildcard: bool = False
    """
    This field MUST be present and true
    for authorizations created as a result of a newOrder request
    containing a DNS identifier with a value that was a wildcard
    domain name.  For other authorizations, it MUST be absent.
    """


class RevocationReason(Enum):
    """Reason to revoke certificate"""

    unspecified = 0
    key_compromise = 1
    ca_compromise = 2
    affiliation_changed = 3
    superseded = 4
    cessation_of_operation = 5
    certificate_hold = 6
    remove_from_crl = 8
    privilege_withdrawn = 9
    aa_compromise = 10
