import os

from typing import List, Optional, Union
from tpm2_types import *
import tpm_commands_pb2
from constants import tpm_rh_pb2, tpm_alg_pb2, tpm_se_pb2
from tpm_types import (
    tpm_header_pb2,
    tpm_session_pb2,
    tpm2b_sensitive_create_pb2,
    tpm2b_public_pb2,
    tpm2b_data_pb2,
    tpml_pcr_selection_pb2,
    tpm2b_digest_pb2,
)


class TPMCommand(object):
    """
    Represents a concrete `TPM2_<COMMAND>` that can be
    converted into bytes.
    """

    ST_LEN = 2
    CC_LEN = 4
    SIZE_LEN = 4
    PROTO_COMMAND: Optional[tpm_commands_pb2.TPMCommand] = None  # type: ignore

    def __init__(self, st: TPM_ST, cc: TPM_CC, params: bytes):
        self.tag = st
        self.cc = cc
        self.params = params

    def _command_size(self) -> int:
        return self.ST_LEN + self.CC_LEN + self.SIZE_LEN + len(self.params)

    def __bytes__(self) -> bytes:
        return (
            self.tag.value.to_bytes(self.ST_LEN, BYTE_ORDER)
            + self._command_size().to_bytes(self.SIZE_LEN, BYTE_ORDER)
            + self.cc.value.to_bytes(self.CC_LEN, BYTE_ORDER)
            + self.params
        )

    def _proto_header(self) -> tpm_header_pb2.TPMHeader:  # type: ignore
        return tpm_header_pb2.TPMHeader(  # type: ignore
            tag=self.tag.proto_value(),
            command_size=self._command_size(),
            command_code=self.cc.proto_value(),
        )

    @staticmethod
    def _parse_tpm2b(buffer: bytes, offset: int) -> tuple[bytes, int]:
        size = int.from_bytes(buffer[offset : offset + 2], BYTE_ORDER)
        end = offset + 2 + size
        return buffer[offset:end], end

    @staticmethod
    def _proto_tpm2b_data(data: bytes) -> tpm2b_data_pb2.TPM2BData:  # type: ignore
        return tpm2b_data_pb2.TPM2BData(size=len(data), buffer=data)  # type: ignore

    @staticmethod
    def _proto_sensitive_create(
        payload: bytes,
    ) -> tpm2b_sensitive_create_pb2.TPM2BSensitiveCreate:  # type: ignore
        inner_size = int.from_bytes(payload[0:2], BYTE_ORDER)
        inner = payload[2 : 2 + inner_size]

        user_auth_size = int.from_bytes(inner[0:2], BYTE_ORDER)
        user_auth = inner[2 : 2 + user_auth_size]

        data_offset = 2 + user_auth_size
        data_size = int.from_bytes(inner[data_offset : data_offset + 2], BYTE_ORDER)
        sensitive_data = inner[data_offset + 2 : data_offset + 2 + data_size]

        return tpm2b_sensitive_create_pb2.TPM2BSensitiveCreate(  # type: ignore
            size=inner_size,
            sensitive=tpm2b_sensitive_create_pb2.TPMSSensitiveCreate(  # type: ignore
                user_auth=tpm2b_sensitive_create_pb2.TPM2BAuth(  # type: ignore
                    size=user_auth_size,
                    buffer=user_auth,
                ),
                data=tpm2b_sensitive_create_pb2.TPM2BSensitiveData(  # type: ignore
                    size=data_size,
                    buffer=sensitive_data,
                ),
            ),
        )

    @staticmethod
    def _proto_public(payload: bytes) -> tpm2b_public_pb2.TPM2BPublic:  # type: ignore
        size = int.from_bytes(payload[0:2], BYTE_ORDER)
        public = payload[2 : 2 + size]
        offset = 0

        public_type = int.from_bytes(public[offset : offset + 2], BYTE_ORDER)
        offset += 2
        name_alg = int.from_bytes(public[offset : offset + 2], BYTE_ORDER)
        offset += 2
        object_attributes = int.from_bytes(public[offset : offset + 4], BYTE_ORDER)
        offset += 4

        auth_policy_size = int.from_bytes(public[offset : offset + 2], BYTE_ORDER)
        auth_policy = public[offset + 2 : offset + 2 + auth_policy_size]
        offset += 2 + auth_policy_size

        parameters = tpm2b_public_pb2.TPMUPublicParms()  # type: ignore
        unique = tpm2b_public_pb2.TPMUPublicId()  # type: ignore

        if public_type == TPM_ALG.RSA.value:
            symmetric = int.from_bytes(public[offset : offset + 2], BYTE_ORDER)
            offset += 2
            scheme = int.from_bytes(public[offset : offset + 2], BYTE_ORDER)
            offset += 2
            key_bits = int.from_bytes(public[offset : offset + 2], BYTE_ORDER)
            offset += 2
            exponent = int.from_bytes(public[offset : offset + 4], BYTE_ORDER)
            offset += 4
            unique_bytes, offset = TPMCommand._parse_tpm2b(public, offset)

            parameters.rsa.CopyFrom(
                tpm2b_public_pb2.TPMSRSAParms(  # type: ignore
                    symmetric=symmetric,
                    scheme=scheme,
                    key_bits=key_bits,
                    exponent=exponent,
                )
            )
            unique.rsa = unique_bytes[2:]
        elif public_type == TPM_ALG.KEYEDHASH.value:
            scheme = int.from_bytes(public[offset : offset + 2], BYTE_ORDER)
            offset += 2
            unique_bytes, offset = TPMCommand._parse_tpm2b(public, offset)

            parameters.keyedhash.CopyFrom(
                tpm2b_public_pb2.TPMSKeyedHashParms(scheme=scheme)  # type: ignore
            )
            unique.keyedhash.CopyFrom(
                tpm2b_digest_pb2.TPM2BDigest(  # type: ignore
                    size=len(unique_bytes[2:]),
                    buffer=unique_bytes[2:],
                )
            )
        else:
            raise NotImplementedError(
                f"Unsupported public type for proto: {public_type}"
            )

        return tpm2b_public_pb2.TPM2BPublic(  # type: ignore
            size=size,
            public_area=tpm2b_public_pb2.TPMTPublic(  # type: ignore
                type=public_type,
                name_alg=name_alg,
                object_attributes=object_attributes,
                auth_policy=tpm2b_digest_pb2.TPM2BDigest(  # type: ignore
                    size=auth_policy_size,
                    buffer=auth_policy,
                ),
                parameters=parameters,
                unique=unique,
            ),
        )

    @staticmethod
    def _proto_pcr_selection(
        payload: bytes,
    ) -> tpml_pcr_selection_pb2.TPMLPCRSelection:  # type: ignore
        count = int.from_bytes(payload[0:4], BYTE_ORDER)
        offset = 4
        selections = []

        for _ in range(count):
            hash_alg = int.from_bytes(payload[offset : offset + 2], BYTE_ORDER)
            offset += 2
            sizeof_select = payload[offset]
            offset += 1
            pcr_select = payload[offset : offset + sizeof_select]
            offset += sizeof_select

            selections.append(
                tpml_pcr_selection_pb2.TPMSPCRSelection(  # type: ignore
                    hash=hash_alg,
                    sizeof_select=sizeof_select,
                    pcr_select=pcr_select,
                )
            )

        return tpml_pcr_selection_pb2.TPMLPCRSelection(  # type: ignore
            count=count,
            pcr_selections=selections,
        )

    @staticmethod
    def _proto_sessions(auth_bytes: bytes) -> list[tpm_session_pb2.TPMSession]:  # type: ignore
        sessions = []
        session_offset = 4
        while session_offset < len(auth_bytes):
            session_handle = int.from_bytes(
                auth_bytes[session_offset : session_offset + 4], BYTE_ORDER
            )
            session_offset += 4

            nonce_size = int.from_bytes(
                auth_bytes[session_offset : session_offset + 2], BYTE_ORDER
            )
            session_offset += 2
            nonce = auth_bytes[session_offset : session_offset + nonce_size]
            session_offset += nonce_size

            session_attributes = auth_bytes[session_offset]
            session_offset += 1

            hmac_size = int.from_bytes(
                auth_bytes[session_offset : session_offset + 2], BYTE_ORDER
            )
            session_offset += 2
            hmac = auth_bytes[session_offset : session_offset + hmac_size]
            session_offset += hmac_size

            sessions.append(
                tpm_session_pb2.TPMSession(  # type: ignore
                    session_handle=session_handle,
                    nonce_size=nonce_size,
                    nonce=nonce,
                    session_attributes=session_attributes,
                    hmac_size=hmac_size,
                    hmac=hmac,
                )
            )

        return sessions

    def to_proto(self) -> Optional[dict]:
        return None


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
        session_handle: Union[int, TPM_RS],
        hashAlg: TPM_ALG,
        key_type: TPM_ALG,
        keyBits: int,
        object_attributes: Optional[Union[int, list]] = None,
        rsa_parameters: Optional[TPMS_RSA_PARMS] = None,
        keyedhash_scheme: Optional[TPMS_KEYEDHASH_PARMS] = None,
        sensitive_data: bytes = b"",
    ):
        session_handle_val = (
            session_handle.value
            if isinstance(session_handle, TPM_RS)
            else session_handle
        )
        auth = TPMS_AUTH_COMMAND(session_handle=session_handle_val)
        auth_area = TPM_AUTH_AREA(commands=[auth])

        sensitive = TPM2B_SENSITIVE_CREATE(
            sensitive=TPMS_SENSITIVE_CREATE(data=sensitive_data)
        )

        public_template = TPM2B_PUBLIC(
            public_area=TPMT_PUBLIC(
                type=key_type,
                name_alg=hashAlg,
                object_attributes=object_attributes
                or [
                    TPMA_OBJECT.FIXEDTPM,
                    TPMA_OBJECT.FIXEDPARENT,
                    TPMA_OBJECT.SENSITIVEDATAORIGIN,
                    TPMA_OBJECT.USERWITHAUTH,
                    TPMA_OBJECT.NODA,
                    TPMA_OBJECT.RESTRICTED,
                    TPMA_OBJECT.DECRYPT,
                ],
                rsa_parameters=rsa_parameters or TPMS_RSA_PARMS(key_bits=keyBits),
                keyedhash_scheme=keyedhash_scheme,
            )
        )

        params = (
            parent_handle.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
            + sensitive.to_bytes()
            + public_template.to_bytes()
            + TPM2B_DATA().to_bytes()
            + TPML_PCR_SELECTION().to_bytes()
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.CREATE, params=params)

    def to_proto(self) -> Optional[dict]:
        params = self.params
        offset = 0

        parent_handle = params[offset : offset + 4]
        offset += 4

        auth_size = int.from_bytes(params[offset : offset + 4], BYTE_ORDER)
        auth_end = offset + 4 + auth_size
        offset = auth_end

        in_sensitive, offset = self._parse_tpm2b(params, offset)
        in_public, offset = self._parse_tpm2b(params, offset)
        outside_info, offset = self._parse_tpm2b(params, offset)
        creation_pcr = params[offset:]

        return {
            "create": tpm_commands_pb2.tpm__commands_dot_tpm__create__pb2.TPMCreate(  # type: ignore
                header=self._proto_header(),
                parent_handle=parent_handle,
                in_sensitive=self._proto_sensitive_create(in_sensitive),
                in_public=self._proto_public(in_public),
                outside_info=self._proto_tpm2b_data(outside_info[2:]),
                creation_pcr=self._proto_pcr_selection(creation_pcr),
            )
        }


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
                    type=TPM_ALG.RSA,
                    name_alg=hashAlg,
                    rsa_parameters=TPMS_RSA_PARMS(key_bits=keyBits),
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

    def to_proto(self) -> Optional[dict]:
        params = self.params
        offset = 0

        hierarchy = int.from_bytes(params[offset : offset + 4], BYTE_ORDER)
        offset += 4

        sessions = []
        if self.tag != TPM_ST.NO_SESSIONS:
            auth_size = int.from_bytes(params[offset : offset + 4], BYTE_ORDER)
            auth_end = offset + 4 + auth_size
            auth_bytes = params[offset:auth_end]
            offset = auth_end
            sessions = self._proto_sessions(auth_bytes)

        in_sensitive, offset = self._parse_tpm2b(params, offset)
        in_public, offset = self._parse_tpm2b(params, offset)
        outside_info, offset = self._parse_tpm2b(params, offset)
        creation_pcr = params[offset:]

        return {
            "createprimary": tpm_commands_pb2.tpm__commands_dot_tpm__createprimary__pb2.TPMCreatePrimary(  # type: ignore
                header=self._proto_header(),
                hierarchy=hierarchy,
                sessions=sessions,
                in_sensitive=self._proto_sensitive_create(in_sensitive),
                in_public=self._proto_public(in_public),
                outside_info=self._proto_tpm2b_data(outside_info[2:]),
                creation_pcr=self._proto_pcr_selection(creation_pcr),
            )
        }


class TPMGetRandom(TPMCommand):
    def __init__(
        self,
        req_bytes: int,
        st: TPM_ST = TPM_ST.NO_SESSIONS,
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

    def to_proto(self) -> Optional[dict]:
        return {
            "getrandom": tpm_commands_pb2.tpm__commands_dot_tpm__getrandom__pb2.TPMGetRandom(  # type: ignore
                header=self._proto_header(),
                bytes_requested=int.from_bytes(self.params[-2:], BYTE_ORDER),
            )
        }


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

    def to_proto(self) -> Optional[dict]:
        tpm_key = int.from_bytes(self.params[0:4], BYTE_ORDER)
        bind = int.from_bytes(self.params[4:8], BYTE_ORDER)

        nonce_size = int.from_bytes(self.params[8:10], BYTE_ORDER)
        nonce_start = 10
        nonce_end = nonce_start + nonce_size
        nonce = self.params[nonce_start:nonce_end]

        salt_size = int.from_bytes(self.params[nonce_end : nonce_end + 2], BYTE_ORDER)
        salt_start = nonce_end + 2
        salt_end = salt_start + salt_size
        encrypted_salt = self.params[salt_start:salt_end]

        session_type = self.params[salt_end]

        symmetric_alg = int.from_bytes(
            self.params[salt_end + 1 : salt_end + 3], BYTE_ORDER
        )
        symmetric_key_bits = 0
        symmetric_mode = TPM_ALG.NULL.value
        auth_hash_offset = salt_end + 3
        if symmetric_alg != TPM_ALG.NULL.value:
            symmetric_key_bits = int.from_bytes(
                self.params[salt_end + 3 : salt_end + 5], BYTE_ORDER
            )
            symmetric_mode = int.from_bytes(
                self.params[salt_end + 5 : salt_end + 7], BYTE_ORDER
            )
            auth_hash_offset = salt_end + 7

        auth_hash = int.from_bytes(
            self.params[auth_hash_offset : auth_hash_offset + 2], BYTE_ORDER
        )

        return {
            "startauthsession": tpm_commands_pb2.tpm__commands_dot_tpm__startauthsession__pb2.TPMStartAuthSession(  # type: ignore
                header=self._proto_header(),
                tpm_key=tpm_key,
                bind=bind,
                nonce=self._proto_tpm2b_data(nonce),
                encrypted_salt=self._proto_tpm2b_data(encrypted_salt),
                session_type=tpm_se_pb2.TPMSE.Name(session_type),  # type: ignore
                symmetric=tpm_commands_pb2.tpm__commands_dot_tpm__startauthsession__pb2.tpm__types_dot_tpmt__sym__def__pb2.TPMTSymDef(  # type: ignore
                    algorithm=tpm_alg_pb2.TPMALG.Name(symmetric_alg),  # type: ignore
                    key_bits=symmetric_key_bits,
                    mode=tpm_alg_pb2.TPMALG.Name(symmetric_mode),  # type: ignore
                ),
                auth_hash=tpm_alg_pb2.TPMALG.Name(auth_hash),  # type: ignore
            )
        }


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
        hierarchy: TPM_RH = TPM_RH.OWNER,
        data_size: int = 32,
    ):
        auth_cmd = TPMS_AUTH_COMMAND(session_handle=session_handle)
        auth_area = TPM_AUTH_AREA(commands=[auth_cmd])

        auth_value = TPM2B_DATA()

        nv_public = TPM2B_NV_PUBLIC(
            TPMS_NV_PUBLIC(
                nv_index=nv_index,
                name_alg=TPM_ALG.SHA256,
                attributes=attributes,
                data_size=data_size,
            )
        )

        params = (
            hierarchy.value.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
            + auth_value.to_bytes()
            + nv_public.to_bytes()
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.NV_DEFINESPACE, params)


class TPMNVUndefineSpace(TPMCommand):
    def __init__(
        self,
        nv_index: int,
        hierarchy: TPM_RH = TPM_RH.OWNER,
        session_handle: int = TPM_RS.PW.value,
    ):
        auth_cmd = TPMS_AUTH_COMMAND(session_handle)
        auth_area = TPM_AUTH_AREA(commands=[auth_cmd])

        params = (
            hierarchy.value.to_bytes(4, BYTE_ORDER)
            + nv_index.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.NV_UNDEFINESPACE, params)


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


class TPMNVReadLock(TPMCommand):
    def __init__(
        self,
        nv_index: int,
        auth_handle: Union[int, TPM_RH] = TPM_RH.OWNER,
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

        super().__init__(TPM_ST.SESSIONS, TPM_CC.NV_READLOCK, params)


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


class TPMNVExtend(TPMCommand):
    """
    TPM2_NV_Extend command.

    Command structure (TPM_ST_SESSIONS):
      authHandle(4) | nvIndex(4) | authArea | data: TPM2B_MAX_NV_BUFFER
    """

    def __init__(
        self,
        nv_index: int,
        data: bytes,
        auth_handle: Optional[Union[int, TPM_RH]] = None,
        session_handle: Union[int, TPM_RS] = TPM_RS.PW,
    ):
        session_handle_val = (
            session_handle.value
            if isinstance(session_handle, TPM_RS)
            else session_handle
        )
        nv_index_val = int(nv_index)
        if auth_handle is None:
            auth_handle_val = nv_index_val
        else:
            auth_handle_val = (
                auth_handle.value
                if isinstance(auth_handle, TPM_RH)
                else int(auth_handle)
            )

        auth_cmd = TPMS_AUTH_COMMAND(session_handle=session_handle_val)
        auth_area = TPM_AUTH_AREA(commands=[auth_cmd])

        data_2b = len(data).to_bytes(2, BYTE_ORDER) + data

        params = (
            auth_handle_val.to_bytes(4, BYTE_ORDER)
            + nv_index_val.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
            + data_2b
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.NV_EXTEND, params=params)


class TPMNVSetBits(TPMCommand):
    """
    TPM2_NV_SetBits

    authHandle(4) | nvIndex(4) | authArea | bits(UINT64)
    """

    def __init__(
        self,
        nv_index: int,
        bits: int,
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
            + bits.to_bytes(8, BYTE_ORDER)
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.NV_SET_BITS, params)


class TPMLoad(TPMCommand):
    """
    TPM2_Load — load a private/public blob (output of TPM2_Create) into the TPM.

    Command structure (TPM_ST_SESSIONS):
      parentHandle(4) | authArea | inPrivate: TPM2B_PRIVATE | inPublic: TPM2B_PUBLIC

    `in_private` is the raw bytes of TPM2B_PRIVATE from the Create response.
    `in_public`  is the raw bytes of TPM2B_PUBLIC  from the Create response.
    Both include the leading 2-byte size field.
    """

    def __init__(
        self,
        parent_handle: int,
        in_private: bytes,
        in_public: bytes,
        session_handle: Union[int, TPM_RS] = TPM_RS.PW,
    ):
        session_handle_val = (
            session_handle.value
            if isinstance(session_handle, TPM_RS)
            else session_handle
        )
        auth = TPMS_AUTH_COMMAND(session_handle=session_handle_val)
        auth_area = TPM_AUTH_AREA(commands=[auth])

        params = (
            parent_handle.to_bytes(4, BYTE_ORDER)
            + auth_area.to_bytes()
            + in_private
            + in_public
        )

        super().__init__(TPM_ST.SESSIONS, TPM_CC.LOAD, params=params)


class TPMUnseal(TPMCommand):
    """
    TPM2_Unseal — return the data held in a sealed data blob.

    Command structure (TPM_ST_SESSIONS):
      itemHandle(4) | authArea
    """

    def __init__(
        self,
        item_handle: int,
        session_handle: Union[int, TPM_RS] = TPM_RS.PW,
    ):
        session_handle_val = (
            session_handle.value
            if isinstance(session_handle, TPM_RS)
            else session_handle
        )
        auth = TPMS_AUTH_COMMAND(session_handle=session_handle_val)
        auth_area = TPM_AUTH_AREA(commands=[auth])

        params = item_handle.to_bytes(4, BYTE_ORDER) + auth_area.to_bytes()

        super().__init__(TPM_ST.SESSIONS, TPM_CC.UNSEAL, params=params)
