from dataclasses import dataclass, field
from typing import Union, Optional, List
from enum import Enum

BYTE_ORDER = "big"


class TPMI_YES_NO(Enum):
    """
    Yes or No Flag
    """

    YES = 0x00
    NO = 0x01


class TPM_ST(Enum):
    """
    TPM Structure tags
    """

    NULL = 0x8000
    NO_SESSIONS = 0x8001
    SESSIONS = 0x8002


class TPM_CC(Enum):
    """
    TPM Command Codes
    """

    GETCAPABILITY = 0x0000017A
    GETRANDOM = 0x0000017B
    STARTAUTHSESSION = 0x00000176
    CREATEPRIMARY = 0x00000131
    CREATE = 0x00000153
    HASH = 0x0000017D
    GETTESTRESULT = 0x0000017C
    SELFTEST = 0x00000143
    INCREMENTALSELFTEST = 0x00000142
    READCLOCK = 0x00000181


class TPM_RH(Enum):
    """
    TPM Reserved Handles
    """

    OWNER = 0x40000001
    NULL = 0x40000007
    PLATFORM = 0x4000000C


class TPM_RS(Enum):
    """
    TPM Session Handles
    """

    PW = 0x40000009


class TPM_SE(Enum):
    """
    TPM Session Types
    """

    HMAC = 0x00
    POLICY = 0x01
    TRIAL = 0x03


class TPM_ALG(Enum):
    """
    TPM Algorithm ID
    """

    RSA = 0x0001
    SHA1 = 0x0004
    SHA256 = 0x000B
    SHA384 = 0x000C
    AES = 0x0006
    CFB = 0x0043
    NULL = 0x0010


class TPMA_OBJECT(Enum):
    """
    TPM Object Attributes
    """

    FIXEDTPM = 1 << 1
    FIXEDPARENT = 1 << 4
    SENSITIVEDATAORIGIN = 1 << 5
    USERWITHAUTH = 1 << 6
    NODA = 1 << 10
    DECRYPT = 1 << 17
    RESTRICTED = 1 << 16


class TPM_CAP(Enum):
    """
    Capability values used in `TPM2_GetCapability()` to
    select the type of the value to be returned.
    """

    ALGS = 0x00000000
    HANDLES = 0x00000001
    COMMANDS = 0x00000002
    PP_COMMANDS = 0x00000003
    AUDIT_COMMANDS = 0x00000004
    PCRS = 0x00000005
    TPM_PROPERTIES = 0x00000006
    PCR_PROPERTIES = 0x00000007
    ECC_CURVES = 0x00000008
    AUTH_POLICIES = 0x00000009
    ACT = 0x0000000A
    PUB_KEYS = 0x0000000B
    SPDM_SESSION_INFO = 0x0000000C
    VENDOR_PROPERTY = 0x00000100


def _alg_to_int(a: Union[int, TPM_ALG]) -> int:
    return a.value if isinstance(a, TPM_ALG) else int(a)


def _attrs_to_int(attrs: Union[int, TPMA_OBJECT, list[TPMA_OBJECT]]) -> int:
    if isinstance(attrs, int):
        return attrs
    if isinstance(attrs, TPMA_OBJECT):
        return attrs.value
    val = 0
    for a in attrs:
        val |= a.value
    return val


@dataclass
class TPMS_SYM_DEF_OBJECT:
    """
    Corresponds to TPMT_SYM_DEF_OBJECT
    """

    algorithm: Union[int, TPM_ALG] = TPM_ALG.AES
    key_bits: int = 128
    mode: Union[int, TPM_ALG] = TPM_ALG.CFB

    def to_bytes(self) -> bytes:
        alg = _alg_to_int(self.algorithm).to_bytes(2, BYTE_ORDER)
        key_bits = self.key_bits.to_bytes(2, BYTE_ORDER)
        mode = _alg_to_int(self.mode).to_bytes(2, BYTE_ORDER)
        return alg + key_bits + mode


@dataclass
class TPMS_RSA_PARMS:
    """
    Subset of TPMS_RSA_PARMS needed for storage/primary keys.

    symmetric | scheme | keyBits | exponent
    """

    symmetric: TPMS_SYM_DEF_OBJECT = field(
        default_factory=lambda: TPMS_SYM_DEF_OBJECT()
    )
    scheme: Union[int, TPM_ALG] = TPM_ALG.NULL
    key_bits: int = 2048
    exponent: int = 0  # 0 == default 0x00010001

    def to_bytes(self) -> bytes:
        sym = self.symmetric.to_bytes()
        scheme = _alg_to_int(self.scheme).to_bytes(2, BYTE_ORDER)
        key_bits = self.key_bits.to_bytes(2, BYTE_ORDER)
        exponent = self.exponent.to_bytes(4, BYTE_ORDER)
        return sym + scheme + key_bits + exponent


@dataclass
class TPMT_PUBLIC:
    """
    TPMT_PUBLIC structure (without the size prefix).
    For RSA keys, `parameters` is typically TPMS_RSA_PARMS.
    """

    type: Union[int, TPM_ALG] = TPM_ALG.RSA
    name_alg: Union[int, TPM_ALG] = TPM_ALG.SHA256
    object_attributes: Union[int, TPMA_OBJECT, list[TPMA_OBJECT]] = field(
        default_factory=lambda: [
            TPMA_OBJECT.FIXEDTPM,
            TPMA_OBJECT.FIXEDPARENT,
            TPMA_OBJECT.SENSITIVEDATAORIGIN,
            TPMA_OBJECT.USERWITHAUTH,
            TPMA_OBJECT.NODA,
            TPMA_OBJECT.RESTRICTED,
            TPMA_OBJECT.DECRYPT,
        ]
    )
    # TPM2B_DIGEST authPolicy; default empty
    auth_policy: bytes = b""

    # Parameters & unique depend on `type`.
    # For RSA, parameters = TPMS_RSA_PARMS; unique = TPM2B_PUBLIC_KEY_RSA
    rsa_parameters: Optional[TPMS_RSA_PARMS] = field(
        default_factory=lambda: TPMS_RSA_PARMS()
    )
    unique: bytes = b""  # let TPM generate public key if empty

    def to_bytes(self) -> bytes:
        t_type = _alg_to_int(self.type).to_bytes(2, BYTE_ORDER)
        name_alg = _alg_to_int(self.name_alg).to_bytes(2, BYTE_ORDER)
        attrs = _attrs_to_int(self.object_attributes).to_bytes(4, BYTE_ORDER)

        # TPM2B_DIGEST for authPolicy: size(2) + bytes
        auth_size = len(self.auth_policy).to_bytes(2, BYTE_ORDER)
        auth = auth_size + self.auth_policy

        # Parameters + unique depend on type.
        if _alg_to_int(self.type) == TPM_ALG.RSA.value:
            if self.rsa_parameters is None:
                raise ValueError("rsa_parameters must be set for RSA public area")
            parameters = self.rsa_parameters.to_bytes()

            # TPM2B_PUBLIC_KEY_RSA: size(2) + key bytes
            unique_size = len(self.unique).to_bytes(2, BYTE_ORDER)
            unique = unique_size + self.unique
        else:
            # Extend here for other key types (ECC, keyed hash, etc.)
            raise NotImplementedError("Only RSA TPMT_PUBLIC is implemented")

        return t_type + name_alg + attrs + auth + parameters + unique


@dataclass
class TPM2B_PUBLIC:
    """
    TPM2B_PUBLIC = size(2) + TPMT_PUBLIC
    This is what the TPM command expects as inPublic.
    """

    public_area: TPMT_PUBLIC

    def to_bytes(self) -> bytes:
        public_bytes = self.public_area.to_bytes()
        size = len(public_bytes).to_bytes(2, BYTE_ORDER)
        return size + public_bytes


@dataclass
class TPMS_AUTH_COMMAND:
    """
    TPMS_AUTH_COMMAND

    sessionHandle | nonce | sessionAttributes | hmac
    """

    session_handle: int  # TPMI_SH_AUTH_SESSION
    nonce: bytes = b""  # TPM2B_NONCE (data)
    session_attributes: int = 0  # TPMA_SESSION (1 byte bitfield)
    hmac: bytes = b""  # TPM2B_AUTH (data)

    def to_bytes(self) -> bytes:
        # sessionHandle
        sh = self.session_handle.to_bytes(4, BYTE_ORDER)

        # nonce: TPM2B_NONCE = size(2) + bytes
        nonce_size = len(self.nonce).to_bytes(2, BYTE_ORDER)
        nonce = nonce_size + self.nonce

        # sessionAttributes: 1 byte
        attrs = self.session_attributes.to_bytes(1, BYTE_ORDER)

        # hmac: TPM2B_AUTH = size(2) + bytes
        hmac_size = len(self.hmac).to_bytes(2, BYTE_ORDER)
        hmac = hmac_size + self.hmac

        return sh + nonce + attrs + hmac


@dataclass
class TPM_AUTH_AREA:
    """
    Helper for the authorization area in commands with TPM_ST_SESSIONS.

    authSize(4) | authCommand[0] | authCommand[1] | ...
    """

    commands: List[TPMS_AUTH_COMMAND] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        auth_bytes = b"".join(cmd.to_bytes() for cmd in self.commands)
        auth_size = len(auth_bytes).to_bytes(4, BYTE_ORDER)
        return auth_size + auth_bytes


@dataclass
class TPMS_SENSITIVE_CREATE:
    """
    TPMS_SENSITIVE_CREATE

    userAuth (TPM2B_AUTH) | data (TPM2B_SENSITIVE_DATA)
    """

    user_auth: bytes = b""
    data: bytes = b""

    def to_bytes(self) -> bytes:
        # userAuth: TPM2B_AUTH
        ua_size = len(self.user_auth).to_bytes(2, BYTE_ORDER)
        ua = ua_size + self.user_auth

        # data: TPM2B_SENSITIVE_DATA
        d_size = len(self.data).to_bytes(2, BYTE_ORDER)
        d = d_size + self.data

        return ua + d


@dataclass
class TPM2B_SENSITIVE_CREATE:
    """
    TPM2B_SENSITIVE_CREATE = size(2) + TPMS_SENSITIVE_CREATE
    """

    sensitive: TPMS_SENSITIVE_CREATE = field(
        default_factory=lambda: TPMS_SENSITIVE_CREATE()
    )

    def to_bytes(self) -> bytes:
        inner = self.sensitive.to_bytes()
        size = len(inner).to_bytes(2, BYTE_ORDER)
        return size + inner


@dataclass
class TPM2B_DATA:
    """
    TPM2B_DATA

    size(2) | buffer
    """

    buffer: bytes = b""

    def to_bytes(self) -> bytes:
        size = len(self.buffer).to_bytes(2, BYTE_ORDER)
        return size + self.buffer


@dataclass
class TPMS_PCR_SELECTION:
    """
    TPMS_PCR_SELECTION

    hash(2) | sizeofSelect(1) | pcrSelect[sizeofSelect]
    """

    hash: Union[int, TPM_ALG]
    pcr_select: bytes

    def to_bytes(self) -> bytes:
        alg = _alg_to_int(self.hash).to_bytes(2, BYTE_ORDER)
        sizeof_select = len(self.pcr_select).to_bytes(1, BYTE_ORDER)
        return alg + sizeof_select + self.pcr_select


@dataclass
class TPML_PCR_SELECTION:
    """
    TPML_PCR_SELECTION

    count(4) | selections[count]
    """

    selections: List[TPMS_PCR_SELECTION] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        count = len(self.selections).to_bytes(4, BYTE_ORDER)
        body = b"".join(s.to_bytes() for s in self.selections)
        return count + body
