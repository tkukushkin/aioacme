from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Annotated

import dateutil.parser
from serpyco_rs.metadata import deserialize_with


@dataclass
class ExternalAccountBinding:
    """External Account Binding credentials."""

    kid: str
    """Key ID."""
    mac_key: bytes | str
    """MAC key (:py:class:`str` if it's base64 encoded)."""


class AccountStatus(Enum):
    """Account status."""

    valid = 'valid'
    """Account is active."""
    deactivated = 'deactivated'
    """Client requested deactivation of the account."""
    revoked = 'revoked'
    """Server revoked the account."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Account:
    """Account object."""

    uri: str
    status: AccountStatus
    contact: Sequence[str] | None = None
    terms_of_service_agreed: bool | None = None
    orders: str | None = None
    """
    A URL from which a list of orders submitted by this account can be fetched
    """
    initial_ip: str | None = None
    created_at: Annotated[datetime, deserialize_with(dateutil.parser.isoparse)] | None = None


class OrderStatus(Enum):
    """Order status."""

    pending = 'pending'
    """The order is waiting for the client to satisfy authorizations challenges."""
    ready = 'ready'
    """All authorizations have been satisfied, the order is ready to finalize."""
    processing = 'processing'
    """The server is issuing the certificate."""
    valid = 'valid'
    """The certificate has been issued."""
    invalid = 'invalid'
    """The order has expired or one of its authorizations has failed."""


class AuthorizationStatus(Enum):
    """Authorization status."""

    pending = 'pending'
    """The authorization is waiting to be validated."""
    valid = 'valid'
    """The authorization has been successfully validated."""
    invalid = 'invalid'
    """The authorization has not been successfully validated."""
    deactivated = 'deactivated'
    """The client has deactivated the authorization."""
    expired = 'expired'
    """The authorization has expired."""
    revoked = 'revoked'
    """The server has revoked the authorization."""


class IdentifierType(Enum):
    """Identifier type."""

    dns = 'dns'
    ip = 'ip'


@dataclass(frozen=True, slots=True)
class Identifier:
    """Identifier object."""

    value: str
    type: IdentifierType = IdentifierType.dns


@dataclass(frozen=True, slots=True, kw_only=True)
class Error:
    """Error object."""

    type: str
    """A URI reference to a document with more information about the error."""
    detail: str
    """A short description of the error."""
    identifier: Identifier | None = None
    subproblems: Sequence['Error'] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Order:
    """Order object."""

    uri: str
    """URI"""
    identifiers: Sequence[Identifier]
    """An array of identifier objects that the order pertains to."""
    authorizations: Sequence[str]
    """
    For pending orders, the authorizations that the client needs to complete
    before the requested certificate can be issued,
    including unexpired authorizations that the client has completed in the
    past for identifiers specified in the order. The authorizations required
    are dictated by server policy; there may not be a 1:1 relationship between
    the order identifiers and the authorizations required.  For final orders
    (in the "valid" or "invalid" state), the authorizations that were
    completed. Each entry is a URL from which an authorization can be fetched.
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
    """Challenge type."""

    dns01 = 'dns-01'
    dnsaccount01 = 'dns-account-01'
    http01 = 'http-01'
    tlsalpn01 = 'tls-alpn-01'


class ChallengeStatus(Enum):
    """Challenge status."""

    pending = 'pending'
    """The challenge is waiting to be validated."""
    processing = 'processing'
    """The challenge is in the process of being validated."""
    valid = 'valid'
    """The challenge has been successfully validated."""
    invalid = 'invalid'
    """The challenge has not been successfully validated."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Challenge:
    """Challenge object."""

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
    """Authorization object."""

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
    """Reason to revoke certificate."""

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
