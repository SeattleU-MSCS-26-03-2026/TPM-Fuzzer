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
        params = len(data).to_bytes(2, BYTE_ORDER) + data

        super().__init__(TPM_ST.NO_SESSIONS, TPM_CC.STIRRANDOM, params)


class TPMVendorTCGTest(TPMCommand):
    def __init__(self, data: bytes):
        params = len(data).to_bytes(2, BYTE_ORDER) + data  # TPM2B size  # buffer

        super().__init__(TPM_ST.NO_SESSIONS, TPM_CC.VENDORTCGTEST, params)


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
        public_template: Optional[TPM2B_PUBLIC] = None,
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
        if public_template is None:
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


class TPMLoadExternal(TPMCommand):
    def __init__(
        self,
        hash_alg: TPM_ALG,
        key_bits: int,
        hierarchy: TPM_RH = TPM_RH.NULL,
        include_private: bool = False,
    ):

        key_bytes = key_bits // 8

        if include_private:
            key_bytes = key_bits // 8

            private_key = b"\x80" + b"\x01" * ((key_bytes // 2) - 1)

            in_private = TPM2B_SENSITIVE(
                sensitive_type=TPM_ALG.RSA,
                private_key=private_key,
            ).to_bytes()

        else:
            in_private = (0).to_bytes(2, BYTE_ORDER)

        public_key = b"\x80" + b"\x01" * (key_bytes - 1)

        public_area = TPMT_PUBLIC(
            type=TPM_ALG.RSA,
            name_alg=hash_alg,
            object_attributes=[
                TPMA_OBJECT.FIXEDTPM,
                TPMA_OBJECT.USERWITHAUTH,
            ],
            rsa_parameters=TPMS_RSA_PARMS(
                symmetric=TPMS_SYM_DEF_OBJECT(
                    algorithm=TPM_ALG.NULL,
                ),
                scheme=TPM_ALG.NULL,
                key_bits=key_bits,
                exponent=0,
            ),
            unique=public_key,
        )

        in_public = TPM2B_PUBLIC(public_area=public_area).to_bytes()

        hierarchy_bytes = hierarchy.value.to_bytes(4, BYTE_ORDER)

        params = in_private + in_public + hierarchy_bytes

        super().__init__(TPM_ST.NO_SESSIONS, TPM_CC.LOADEXTERNAL, params)


class TPMSign(TPMCommand):
    """
    TPM2_Sign command.

    Command structure (TPM_ST_SESSIONS):
      keyHandle(4) | authArea | digest: TPM2B_DIGEST |
      inScheme: TPMT_SIG_SCHEME | validation: TPMT_TK_HASHCHECK
    """

    def __init__(
        self,
        key_handle: int,
        digest: bytes,
        in_scheme: TPMT_SIG_SCHEME,
        validation: TPMT_TK_HASHCHECK,
        session_handle: Union[int, TPM_RS] = TPM_RS.PW,
    ):
        session_handle = (
            session_handle.value
            if isinstance(session_handle, TPM_RS)
            else session_handle
        )

        auth = TPMS_AUTH_COMMAND(session_handle=session_handle)
        auth_area = TPM_AUTH_AREA(commands=[auth])

        # TPM2B_DIGEST: size(2) + bytes
        digest_bytes = len(digest).to_bytes(2, BYTE_ORDER) + digest

        params = (
            key_handle.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
            + digest_bytes
            + in_scheme.to_bytes()
            + validation.to_bytes()
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.SIGN, params=params)


class TPMPCRRead(TPMCommand):
    """
    TPM2_PCR_Read — read PCR values.

    Command Structure (TPM_ST_NO_SESSIONS):
      [tag][commandSize][TPM_CC_PCR_READ][TPML_PCR_SELECTION]
    """

    def __init__(self, pcr_selection: TPML_PCR_SELECTION):
        super().__init__(
            TPM_ST.NO_SESSIONS,
            TPM_CC.PCR_READ,
            params=pcr_selection.to_bytes(),
        )


class TPMPCRExtend(TPMCommand):
    """
    TPM2_PCR_Extend — extend a PCR with one or more digests.

    Command Structure (TPM_ST_SESSIONS):
      [tag][commandSize][TPM_CC_PCR_EXTEND]
      [pcrHandle][authArea][TPML_DIGEST_VALUES]
    """

    def __init__(
        self,
        pcr_handle: Union[int, TPM_RH],
        digests: TPML_DIGEST_VALUES,
        session_handle: Union[int, TPM_RS] = TPM_RS.PW,
    ):
        pcr_handle = pcr_handle.value if isinstance(pcr_handle, TPM_RH) else pcr_handle
        session_handle = (
            session_handle.value
            if isinstance(session_handle, TPM_RS)
            else session_handle
        )

        auth = TPMS_AUTH_COMMAND(session_handle=session_handle)
        auth_area = TPM_AUTH_AREA(commands=[auth])

        params = (
            pcr_handle.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
            + digests.to_bytes()
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.PCR_EXTEND, params=params)


class TPMPCRReset(TPMCommand):
    """
    TPM2_PCR_Reset — reset a resettable PCR to zero.

    Command Structure (TPM_ST_SESSIONS):
      [tag][commandSize][TPM_CC_PCR_RESET]
      [pcrHandle][authArea]
    """

    def __init__(
        self,
        pcr_handle: int,
        session_handle: Union[int, TPM_RS] = TPM_RS.PW,
    ):
        session_handle = (
            session_handle.value
            if isinstance(session_handle, TPM_RS)
            else session_handle
        )

        auth = TPMS_AUTH_COMMAND(session_handle=session_handle)
        auth_area = TPM_AUTH_AREA(commands=[auth])

        params = pcr_handle.to_bytes(4, BYTE_ORDER) + auth_area.to_bytes()

        super().__init__(TPM_ST.SESSIONS, TPM_CC.PCR_RESET, params=params)


class TPMTestParms(TPMCommand):
    def __init__(self, params: Optional[TPMT_PUBLIC_PARMS] = None):
        params = params or TPMT_PUBLIC_PARMS(TPM_ALG.RSA)
        super().__init__(TPM_ST.NO_SESSIONS, TPM_CC.TESTPARMS, params.to_bytes())


class TPMNVDefineSpace(TPMCommand):
    def __init__(
        self,
        nv_index: int = TPM_HT.NV_INDEX.value << 24,
        attributes: List[TPMA_NV] = [TPMA_NV.AUTHREAD, TPMA_NV.AUTHWRITE],
        session_handle: int = TPM_RS.PW.value,
    ):
        auth_cmd = TPMS_AUTH_COMMAND(session_handle=session_handle)
        auth_area = TPM_AUTH_AREA(commands=[auth_cmd])

        auth_value = TPM2B_DATA()

        nv_public = TPM2B_NV_PUBLIC(
            TPMS_NV_PUBLIC(
                nv_index=nv_index,
                name_alg=TPM_ALG.SHA256,
                attributes=attributes,
                data_size=32,
            )
        )

        params = (
            TPM_RH.OWNER.value.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
            + auth_value.to_bytes()
            + nv_public.to_bytes()
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.NV_DEFINESPACE, params)


class TPMNVWriteLock(TPMCommand):
    def __init__(
        self,
        nv_index: int,
        auth_handle: Union[int | TPM_RH] = TPM_RH.OWNER,
        session_handle: int = TPM_RS.PW.value,
    ):
        auth_cmd = TPMS_AUTH_COMMAND(session_handle=session_handle)
        auth_area = TPM_AUTH_AREA(commands=[auth_cmd])
        auth_handle = (
            auth_handle.value if isinstance(auth_handle, TPM_RH) else auth_handle
        )

        params = (
            auth_handle.to_bytes(4, BYTE_ORDER)
            + nv_index.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.NV_WRITELOCK, params)


class TPMNVWrite(TPMCommand):
    """
    TPM2_NV_Write command.

    Command structure (TPM_ST_SESSIONS):
      authHandle(4) | nvIndex(4) | authArea | data: TPM2B_MAX_NV_BUFFER | offset(UINT16)

    Typical usage after NV_DefineSpace with AUTHWRITE and empty authValue:
      TPMNVWrite(nv_index, b"\\xAA"*32, 0)
    """

    def __init__(
        self,
        nv_index: Union[int, TPM_HT],
        data: bytes,
        offset: int = 0,
        auth_handle: Optional[Union[int, TPM_RH]] = None,
        session_handle: Union[int, TPM_RS] = TPM_RS.PW,
    ):
        # Resolve session handle
        session_handle_val = (
            session_handle.value
            if isinstance(session_handle, TPM_RS)
            else session_handle
        )

        # Resolve nv_index (allow passing TPM_HT, but usually caller gives int)
        nv_index_val = nv_index.value if isinstance(nv_index, TPM_HT) else int(nv_index)

        # Default authHandle = nvIndex (NV index authorization)
        if auth_handle is None:
            auth_handle_val = nv_index_val
        else:
            auth_handle_val = (
                auth_handle.value
                if isinstance(auth_handle, TPM_RH)
                else int(auth_handle)
            )

        # Build auth area: password session, empty nonce/hmac is fine for empty authValue
        auth_cmd = TPMS_AUTH_COMMAND(session_handle=session_handle_val)
        auth_area = TPM_AUTH_AREA(commands=[auth_cmd])

        # TPM2B_MAX_NV_BUFFER (we encode as UINT16 size + buffer)
        data_2b = len(data).to_bytes(2, BYTE_ORDER) + data

        params = (
            auth_handle_val.to_bytes(4, BYTE_ORDER)
            + nv_index_val.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
            + data_2b
            + int(offset).to_bytes(2, BYTE_ORDER)
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.NV_WRITE, params=params)


class TPMNVRead(TPMCommand):
    def __init__(
        self,
        nv_index: int,
        size: int,
        offset: int,
        auth_handle: int | TPM_RH = TPM_RH.OWNER,
        session_handle: int = TPM_RS.PW.value,
    ):

        auth_cmd = TPMS_AUTH_COMMAND(session_handle=session_handle)
        auth_area = TPM_AUTH_AREA(commands=[auth_cmd])
        auth_handle = (
            auth_handle.value if isinstance(auth_handle, TPM_RH) else auth_handle
        )

        params = (
            auth_handle.to_bytes(4, BYTE_ORDER)
            + nv_index.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
            + size.to_bytes(2, BYTE_ORDER)
            + offset.to_bytes(2, BYTE_ORDER)
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.NV_READ, params)
