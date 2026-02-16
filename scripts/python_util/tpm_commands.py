import os

from typing import List, Optional, Union
from .tpm_types import *


class TPMCommand(object):
    """
    Represents a concrete `TPM2_<COMMAND>` that can be
    converted into bytes.
    """

    ST_LEN = 2
    CC_LEN = 4
    SIZE_LEN = 4

    def __init__(self, st: TPM_ST, cc: TPM_CC, params: bytes):
        self.tag = st
        self.cc = cc
        self.params = params

    def __bytes__(self) -> bytes:
        size = self.ST_LEN + self.CC_LEN + self.SIZE_LEN + len(self.params)
        return (
            self.tag.value.to_bytes(self.ST_LEN, BYTE_ORDER)
            + size.to_bytes(self.SIZE_LEN, BYTE_ORDER)
            + self.cc.value.to_bytes(self.CC_LEN, BYTE_ORDER)
            + self.params
        )


class TPMIncrementalSelfTest(TPMCommand):
    def __init__(self, algorithms: List[TPM_ALG]):
        count = len(algorithms).to_bytes(4, BYTE_ORDER)
        algIds: bytes = b""
        for a in algorithms:
            algIds += a.value.to_bytes(2, BYTE_ORDER)

        super().__init__(TPM_ST.NO_SESSIONS, TPM_CC.INCREMENTALSELFTEST, count + algIds)

class TPMStirRandom(TPMCommand):
    def __init__(self, data: bytes):
        # TPM2B_SENSITIVE_DATA = UINT16 size + buffer
        params = (
            len(data).to_bytes(2, BYTE_ORDER)
            + data
        )

        super().__init__(
            TPM_ST.NO_SESSIONS,
            TPM_CC.STIRRANDOM,
            params
        )

class TPMVendorTCGTest(TPMCommand):
    def __init__(self, data: bytes):
        params = (
            len(data).to_bytes(2, BYTE_ORDER)  # TPM2B size
            + data                             # buffer
        )

        super().__init__(
            TPM_ST.NO_SESSIONS,
            TPM_CC.VENDORTCGTEST,
            params
        )


class TPMCreate(TPMCommand):
    def __init__(
        self,
        parent_handle: int,
        session_handle: Union[int | TPM_RS],
        hashAlg: TPM_ALG,
        keyBits: int,
    ):
        session_handle = (
            session_handle.value
            if isinstance(session_handle, TPM_RS)
            else session_handle
        )
        auth = TPMS_AUTH_COMMAND(session_handle=session_handle)
        auth = TPM_AUTH_AREA(commands=[auth])
        public_template = TPM2B_PUBLIC(
            public_area=TPMT_PUBLIC(
                name_alg=hashAlg, rsa_parameters=TPMS_RSA_PARMS(key_bits=keyBits)
            )
        )

        params = (
            parent_handle.to_bytes(4, BYTE_ORDER)
            + auth.to_bytes()
            + TPM2B_SENSITIVE_CREATE().to_bytes()
            + public_template.to_bytes()
            + TPM2B_DATA().to_bytes()
            + TPML_PCR_SELECTION().to_bytes()
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.CREATE, params=params)


class TPMCreatePrimary(TPMCommand):
    def __init__(
        self,
        session_handle: Union[int | TPM_RS],
        hashAlg: TPM_ALG,
        keyBits: int,
        primary_handle: Union[int | TPM_RH] = TPM_RH.OWNER,
    ):
        session_handle = (
            session_handle.value
            if isinstance(session_handle, TPM_RS)
            else session_handle
        )
        primary_handle = (
            primary_handle.value
            if isinstance(primary_handle, TPM_RH)
            else primary_handle
        )

        auth = TPMS_AUTH_COMMAND(session_handle=session_handle)
        auth = TPM_AUTH_AREA(commands=[auth])
        public_template = TPM2B_PUBLIC(
            public_area=TPMT_PUBLIC(
                name_alg=hashAlg, rsa_parameters=TPMS_RSA_PARMS(key_bits=keyBits)
            )
        )

        params = (
            primary_handle.to_bytes(4, BYTE_ORDER)
            + auth.to_bytes()
            + TPM2B_SENSITIVE_CREATE().to_bytes()
            + public_template.to_bytes()
            + TPM2B_DATA().to_bytes()
            + TPML_PCR_SELECTION().to_bytes()
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.CREATEPRIMARY, params=params)


class TPMGetRandom(TPMCommand):
    def __init__(
        self,
        req_bytes: int,
        st: Optional[TPM_ST] = TPM_ST.NO_SESSIONS,
        auth: Optional[TPM_AUTH_AREA] = None,
    ):
        if auth is None:
            super().__init__(
                st,
                TPM_CC.GETRANDOM,
                params=req_bytes.to_bytes(2, BYTE_ORDER),
            )
        else:
            params = auth.to_bytes() + req_bytes.to_bytes(2, BYTE_ORDER)
            super().__init__(st, TPM_CC.GETRANDOM, params=params)


class TPMStartAuthSession(TPMCommand):
    def __init__(
        self,
        tpm_key: Union[int | TPM_RH],
        bind: Union[int | TPM_RH],
        nonce: Optional[bytes] = None,
        salt: Optional[bytes] = None,
        session_type: TPM_SE = TPM_SE.HMAC,
        symmetric: TPMS_SYM_DEF_OBJECT = TPMS_SYM_DEF_OBJECT(TPM_ALG.NULL, 0, 0),
        auth_hash: TPM_ALG = TPM_ALG.SHA256,
    ):
        if nonce is None:
            nonce = os.urandom(16)  # Random nonce
        if salt is None:
            salt = (0).to_bytes(2, BYTE_ORDER)  # Empty salt

        tpm_key = tpm_key.value if isinstance(tpm_key, TPM_RH) else tpm_key
        bind = bind.value if isinstance(bind, TPM_RH) else bind

        params = (
            tpm_key.to_bytes(4, BYTE_ORDER)
            + bind.to_bytes(4, BYTE_ORDER)
            + len(nonce).to_bytes(2, BYTE_ORDER)
            + nonce  # TPM2B_NONCE
            + salt  # TPM2B_ENCRYPTED_SECRET
            + session_type.value.to_bytes(1, BYTE_ORDER)  # TPM_SE
            + symmetric.to_bytes()  # TPMT_SYM_DEF
            + auth_hash.value.to_bytes(2, BYTE_ORDER)  # TPMI_ALG_HASH
        )

        super().__init__(TPM_ST.NO_SESSIONS, TPM_CC.STARTAUTHSESSION, params)


class TPMGetCapability(TPMCommand):
    def __init__(self, capability: TPM_CAP, property: int, property_count: int):
        params = (
            capability.value.to_bytes(4, BYTE_ORDER)
            + property.to_bytes(4, BYTE_ORDER)
            + property_count.to_bytes(4, BYTE_ORDER)
        )
        super().__init__(TPM_ST.NO_SESSIONS, TPM_CC.GETCAPABILITY, params)


class TPMSelfTest(TPMCommand):
    def __init__(self, full_test: TPMI_YES_NO):
        super().__init__(
            TPM_ST.NO_SESSIONS, TPM_CC.SELFTEST, full_test.value.to_bytes(1, BYTE_ORDER)
        )


class TPMReadClock(TPMCommand):
    def __init__(self):
        super().__init__(TPM_ST.NO_SESSIONS, TPM_CC.READCLOCK, b"")


class TPMHash(TPMCommand):
    def __init__(self, data: bytes, hashAlg: TPM_ALG, hierarchy: TPM_RH):
        params = (
            len(data).to_bytes(2, byteorder=BYTE_ORDER)
            + data
            + hashAlg.value.to_bytes(2, byteorder=BYTE_ORDER)
            + hierarchy.value.to_bytes(4, byteorder=BYTE_ORDER)
        )
        super().__init__(TPM_ST.NO_SESSIONS, TPM_CC.HASH, params)


class TPMGetTestResult(TPMCommand):
    def __init__(self):
        super().__init__(TPM_ST.NO_SESSIONS, TPM_CC.GETTESTRESULT, b"")


class TPMECCParameters(TPMCommand):
    def __init__(self, curve: Union[int, TPM_ECC_CURVE]):
        curve_value = curve.value if isinstance(curve, TPM_ECC_CURVE) else curve
        params = curve_value.to_bytes(2, BYTE_ORDER)

        super().__init__(
            TPM_ST.NO_SESSIONS,
            TPM_CC.ECC_PARAMETERS,
            params=params,
        )
