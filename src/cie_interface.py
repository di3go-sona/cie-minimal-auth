from src.smartcard_interface import *

import Crypto.PublicKey.RSA
import Crypto.Hash

class CIE(SmartCard):
    ef_map = {
        0x1000: "EF.1000",
        0x1001: "EF.ID_Servizi",
        0x1002: "EF.Seriale",
        0x1003: "EF.Cert_CIE",
        0x1004: "EF.Int.Kpub",
        0x1005: "EF.Servizi_Int.Kpub",
        0x1006: "EF.SOD",
        0x1007: "EF.CIE.Kpub",
        **SmartCard.ef_map}

    status_map = {
        '6282': "End of file reached before reading Ne bytes",
        '6981': "Command incompatible with file structure",
        '6982': "Security status not satisfied",
        '6985': "Conditions of use not satisfied",
        '6986': "Command not allowed (no current EF)",
        '6a88': "Referenced certs or reference certs not found ",
        '6a82': "File not found",
        '6b00': "Wrong parameters P1 - P2: Offset + length is beyond the end of file",
        '9000': "Ok"
    }

    def __init__(self, connection=None):
        super().__init__(connection,)


        self.select_ADF_IAS()
        self.select_ADF_CIE()

        self.b_nis = None # bytes_array
        self.nis = None

        self.b_pub_key = None
        self.pub_key = None


        self.b_sod = None
        self.sod = None

    def select_ADF_IAS(self):
        """
		Sends the apdu to be select the Application Directory Folder IAS

		Return:
			None
		"""
        logger.debug(f"Selecting ADF IAS")
        apdu = [0x00,  # CLA
                0xa4,  # INS = SELECT FILE
                0x04,  # P1 = Select By AID
                0x0c,  # P2 = Return No Data
                0x0d,  # LC = lenght of AID
                0xA0, 0x00, 0x00, 0x00, 0x30, 0x80, 0x00, 0x00, 0x00, 0x09, 0x81, 0x60, 0x01  # AID
                ]

        return self.transmit(apdu)

    def select_ADF_CIE(self):
        """
		Sends the apdu to select the Application Directory Folder with id CIE

		Return:
			None
		"""
        logger.debug(f"Selecting ADF CIE")
        apdu = [
            0x00,  # CLA
            0xa4,  # INS = SELECT FILE
            0x04,  # P1 = Select By AID
            0x0c,  # P2 = Return No Data
            0x06,  # LC = lenght of AID
            0xA0, 0x00, 0x00, 0x00, 0x00, 0x39  # AID
        ]

        return self.transmit(apdu)

    def read_EF_pub_key(self):
        d = bytes(self.read_EF(0x1005))
        self._set_pub_key(d)
        return d

    def read_EF_SOD(self):
        d = bytes(self.read_EF(0x1006))
        self._set_SOD(d)
        return d

    def read_EF_nis(self):
        d = self.read_EF(0x1001)

        self.b_nis = d
        self.h_nis = bytes(d).hex()
        self.nis = int.from_bytes(self.b_nis, 'big')
        return d

    def exec_servizi_int_auth(self, data):
        self.set_CSE_servizi_int_auth()
        apdu = [
            0x00,  # CLA
            0x88,  # INS = C/R INT AUTH
            0x00,  # P1 = 0x00
            0x00,  # P2 = 0x00
        ]
        apdu += [len(data)]
        apdu += data
        _, s, t = self.transmit(apdu)
        return self.get_resp()
    # return d

    def read_EF_SN(self):
        """
        Reads the ias-ec card serial number
        :return: The response sent by the CIE
        """
        return bytes(self.read_EF(0xd003))

    def read_EF_DH(self):
        """
        Reads the ias-ec diffie-hellman parameters serial number
        :return: The response sent by the CIE
        """
        return bytes(self.read_EF(0xd004))

    def read_EF_DIR(self):
        self.select_ADF_IAS()
        # self.select_ADF_CIE()
        return bytes(self.read_EF(0x2f00))

    def read_EF_ATR(self):
        self.select_ADF_IAS()
        return bytes(self.read_EF(0x2f01))

    def verify_SOD(self):
        logger.warning("SOD verify not implemented")
        return True

    def verify_SOD_cert(self):

        trust_roots = []
        with open('certs/ItalyCA-3.cert', 'rb') as f:
            for _, _, der_bytes in pem.unarmor(f.read(), multiple=True):
                trust_roots.append(der_bytes)
        context = ValidationContext(trust_roots=trust_roots)

        # Tamper test
        # self.b_sod_cert = self.b_sod_cert.replace(b'IT', b'XX')

        validator = CertificateValidator(self.b_sod_cert, validation_context=context)

        try:
            validator.validate_usage({'digital_signature'})
            logger.log("PROGRESS",f"SOD Certificate Ok")
            return True
        except:
            logger.error(f"SOD Certificate Ko")
            return False

    def verify_nis(self):
        correct = self.get_nis_hash() == self.get_SOD_nis_hash()
        if correct:
            logger.log("PROGRESS",f"NIS Ok ")
        else:
            logger.error(f"NIS Ko")
        return correct

    def verify_pub_key(self):
        correct = self.get_pub_key_hash() == self.get_SOD_pub_key_hash()
        if correct:
            logger.log("PROGRESS",f"Public Key  Ok ")
        else:
            logger.error(f"Public Key  Ko")
        return correct

    def get_nis_hash(self):
        # print(type( self.b_nis))
        hash = Crypto.Hash.SHA256.new()
        hash.update(self.b_nis)
        self.nis_hash = hash.hexdigest()
        # logger.debug(f"nis hash: {self.nis_hash}")
        return self.nis_hash

    def get_pub_key_hash(self):
        hash = Crypto.Hash.SHA256.new()
        hash.update(self.b_pub_key.strip(b'\00'))
        self.pub_key_hash = hash.hexdigest()
        # logger.debug(f"servizi pubkey hash: {self.pub_key_hash}")
        return self.pub_key_hash

    def get_SOD_nis_hash(self):
        h = self.sod_hashes[b'\xa1'].hex()
        # logger.debug(f"sod nis  hash: {h}")
        # print(self.sod_hashes.items())
        return h

    def get_SOD_pub_key_hash(self):
        h = self.sod_hashes[b'\xa5'].hex()
        # logger.debug(f"sod servizi pubkey hash: {h}")
        # print(self.sod_hashes.items())
        return h

    def _set_SOD(self, b_sod):

        self.b_sod = b_sod
        self.cached_efs[0x1006] = b_sod

        self.h_sod = self.b_sod.hex()


        sod = ASN1_Tag(self.b_sod)
        sod_seq = sod.children[0]
        oid, content = sod_seq.children
        pkcs7 = content.children[0]
        pkcs7_signed_data_items = pkcs7.children

        version = pkcs7_signed_data_items.pop(0)
        digest_algo = pkcs7_signed_data_items.pop(0)
        content_info = pkcs7_signed_data_items.pop(0)
        certificate = None
        crl = None
        signer_info = pkcs7_signed_data_items.pop(-1)

        hashes = (ASN1_Tag(content_info.children.pop(-1).children.pop(0).content).children.pop(2).children)
        self.sod_hashes = {}
        for h_tag in hashes:
            id, hash = (t.content for t in (h_tag.children))
            self.sod_hashes[id] = hash

        for e in pkcs7_signed_data_items:
            if e.tag == 0xa0:
                certificate = e
            if e.tag == 0xa1:
                crl = e

        self.b_sod_data = bytes(content_info.content)
        self.b_sod_cert = bytes(certificate.content)
        self.b_sod_sig = bytes(signer_info.content)

        return

    def _set_pub_key(self, b_pub_key):
        self.b_pub_key = b_pub_key
        self.cached_efs[0x1005] = b_pub_key

        self.h_pub_key = self.b_pub_key.hex()


        pub_key = ASN1_Tag(self.b_pub_key)
        n_tag, e_tag = pub_key.children
        n = int.from_bytes(n_tag.content, byteorder='big')
        e = int.from_bytes(e_tag.content, byteorder='big')

        self.pub_key = Crypto.PublicKey.RSA.construct((n, e))
        return



if __name__ == '__main__':
    card = CIE()
    print(card.exec_servizi_int_auth([0x33]*40))
