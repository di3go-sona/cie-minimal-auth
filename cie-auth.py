import Crypto, OpenSSL
import re

from utils import *

from utils.asn_parser import ASN1

from time import time
from loguru import logger


# logger.add(lambda msg: tqdm.write(msg, end=""))
logger.level("TIME", no=45, color="<red>", icon="🚨")

MAX_APDU_SIZE = 200  # 231 <-> E7

class DEBUG:
	status = True
	progress = True

	debug = False
	text = True

	cache = False


class CIE:

	ef_map = {
		0x1000: "EF.1000",
		0x1001: "EF.ID_Servizi",
		0x1002: "EF.Seriale",
		0x1003: "EF.Cert_CIE",
		0x1004: "EF.Int.Kpub",
		0x1005: "EF.Servizi_Int.Kpub",
		0x1006: "EF.SOD",
		0x1007: "EF.CIE.Kpub",
	}

	status_map = {
		'6282': "End of file reached before reading Ne bytes",
		'6981': "Command incompatible with file structure",
		'6982': "Security status not satisfied",
		'6985': "Conditions of use not satisfied",
		'6986': "Command not allowed (no current EF)",
		'6a88': "Referenced data or reference data not found ",
		'6a82': "File not found",
		'6b00': "Wrong parameters P1 - P2: Offset + length is beyond the end of file",
		'9000': "Ok"
	}

	def __init__(self, cached=False):

		self.connection = None

		self.cached = cached
		self.ef = None
		self.ef_size = None

		if not self.cached:
			r = get_first_reader()
			self.connection = r.createConnection()
			self.connection.connect()

		self.select_ADF_IAS()
		self.select_ADF_CIE()

	def transmit(self, apdu):
		"""
		Transmits an apdu to the card

		Args:
			apdu (Bytearray): The apdu to be transmitted to the card
		Return:
			( Bytearray, str , int ): Data returned by the card, Code of the card, time of the operation
		"""


		if self.cached:
			return '', 'OFFLINE', 0

		t_start = time()
		response, sw1, sw2 = self.connection.transmit(apdu)
		status = '%02x%02x' % (sw1, sw2)
		t_end = time()

		status_text = self.status_map.get(status, 'Unknown status code')

		elapsed_time = (t_end - t_start) * 1000
		# return toHexString(response), status, elapsed_time
		return (response), status, elapsed_time

	def select_ADF_IAS(self):
		"""
		Sends the apdu to be select the Application Directory Folder IAS

		Return:
			None
		"""

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

		apdu = [
			0x00,  # CLA
			0xa4,  # INS = SELECT FILE
			0x04,  # P1 = Select By AID
			0x0c,  # P2 = Return No Data
			0x06,  # LC = lenght of AID
			0xA0, 0x00, 0x00, 0x00, 0x00, 0x39  # AID
		]

		return self.transmit(apdu)

	def select_ADF_ROOT(self):
		"""
		Sends the apdu to select the Root Directory

		Return:
			None
		"""

		apdu = [
			0x00,  # CLA
			0xa4,  # INS = SELECT FILE
			0x04,  # P1 = Select By AID
			0x0c,  # P2 = Return No Data
			0x06,  # LC = lenght of AID
			0xA0, 0x00, 0x00, 0x00, 0x00, 0x39  # AID
		]

		return self.transmit(apdu)

	def select_EF(self, EFID):
		"""
		Sends the apdu to select the Application Directory Folder with the specified EFID

		Return:
			( Bytearray): The return of the SELECT command
		"""

		logger.debug(f"Selecting EF: {hex(EFID)}")

		if (EFID > 0xFFFF):
			logger.error("Invalid EFID ")
			exit(1)

		efid_high = (EFID >> 8) & 0xff
		efid_low = EFID & 0xff

		apdu = [
			0x00,  # CLA
			0xa4,  # INS = SELECT FILE
			0x02,  # P1 = Select EF under the current DF
			0x04,  # P2 = Return FCP template, mandatory use of FCP tag and length
			0x02,  # LC = Select by EFID
			efid_high, efid_low,  # Data = EFID
			0x100,  # Le = Boh
		]

		d, s, t = self.transmit(apdu)

		if len(d) == 0:
			self.ef = EFID
			self.ef_size = -1
			return []

		size = int(d[4] * 256 + d[5])

		self.ef = EFID
		self.ef_size = size

		return d

	def read_EF(self, EFID=None):
		"""
		Reads the file with id EFID if present, otherwise reads the currently selected EF

		Args:
			EFID (int): The id of the EF to read, if empty reads the currently selected EF
		Return:
			( Bytearray ) Data returned by the card
		"""

		if DEBUG.text:
			logger.debug(f"Reading: {hex(EFID)}")


		if self.cached:
			if EFID:
				self.ef = EFID

			return open(join('data', f'{self.ef_map[self.ef]}'), 'rb').read()

		if EFID:
			self.select_EF(EFID)

		if self.ef_size == -1:
			logger.error("unable to select File")
			return []

		if (EFID > 0x7FFF):
			logger.error("EFID should be less than 0x7FFF")
			return []

		bytes_left = self.ef_size
		offset = 0
		data = []

		bytes_to_read = min(MAX_APDU_SIZE, bytes_left)
		logger.debug('reading file')

		while bytes_left > 0:

			apdu = [
				0x00,  # CLA
				0xb0,  # INS = BINARY READ
				(offset >> 8) & 0xff,  # P1 = High byte of offset in current file
				offset & 0xff,  # P2 = Low byte of offset in current file
				bytes_to_read,  # LC = Bytes to read
			]

			d, s, t = self.transmit(apdu)

			logger.debug(f"Reading EF {hex(self.ef)} - {self.ef_map[self.ef]}: {offset + len(d)}/{self.ef_size}")
			# print(d)

			if s in '6982|6a82':
				return []

			data += d
			bytes_left -= len(d)
			offset += len(d)
			bytes_to_read = min(MAX_APDU_SIZE, bytes_left)

			# saveFile(data, self.ef_map[self.ef])
		return data

	def read_DOCP(self, SDOID):

		sdo_1 = (SDOID >> 16) & 0xff
		sdo_2 = (SDOID >> 8) & 0xff
		sdo_3 = (SDOID >> 0) & 0xff

		apdu = [
			0x00,  # CLA -> ISO
			0xcb,  # INS -> SDO GET DATA
			0x3f,  # P1 -> curr DF
			0xff,  # P2 -> curr DF
			0x0a,  # Lc -> Data lEN
			0x4d, 0x08, 0x70, 0x06, sdo_1, sdo_2, sdo_3, 0x2, 0xa0, 0x80  # Data -> refer to IASECC 9.8.1.1
		]

		d, _, _ = self.transmit(apdu)
		return d

	def set_CSE_servizi_int_auth(self):
		apdu = [
			0x00,  # CLA
			0x22,  # INS = MSE SET
			0x41,  # P1 = 41
			0xa4,  # P2 = a4
			0x06,  # LC = Data len
			# 0x80, Len, 02 = PKCS#1 - SHA1 with no formatting, 0x84, Len, Servizi.INI.kpub ref id
			0x80, 0x01, 0x02, 0x84, 0x01, 0x83,
		]
		d, s, t = self.transmit(apdu)


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

	def get_resp(self):
		apdu = [
			0x00,  # CLA
			0xC0,  # INS = C/R INT AUTH
			0x00,  # P1 = 0x00
			0x00,  # P2 = 0x00
			0x00, 0x01, 0x00
		]

		d, s, t = self.transmit(apdu)
		while not s == '9000' and False:
			data, s, t = self.transmit(apdu)
			d += data

		return d

	def get_EF_pub_key(self):

		k = bytes(self.read_EF(0x1005))

		return k

	def get_EF_SOD(self):
		k = self.read_EF(0x1006)
		return k

	def get_EF_nis(self):
		if DEBUG.cache:
			with open(join('data', self.ef_map[0x1001]), 'rb') as fin:
				return fin.read()

		k = self.read_EF(0x1001)

		return k


class CIE_Dumper(CIE):
	def __init__(self, cached=False):
		CIE.__init__(self,cached)

	def ef(self, efid):
		name = self.ef_map[efid]
		d = self.read_EF(efid)
		try:
			dump_tag(bytes(d))
		except:
			pass

	def ef_all(self, dump=True, cached=False):
		for efid, name in self.ef_map.items():

			d = None
			if cached:
				d = load_file(self.ef_map[efid])
			else:
				d = self.read_EF(efid)
			try:
				if dump:
					saveFile(d, CIE.ef_map[efid])

				dump_tag(bytes(d))
			except:
				pass

	def ef_fcp_all(self):
		for efid, name in self.ef_map.items():
			fcp = self.select_EF(efid)
			print(toHexString(fcp))

	def sign(self):
		self.set_CSE_servizi_int_auth()
		s = self.exec_servizi_int_auth([0xFF] * 256)
		print(toHexString(s))


class CIE_Token(CIE):
	nonce_size = 0x33

	def __init__(self, cached=False):
		super().__init__(cached)
		self.b_pub_key = None
		self.pub_key = None
		self.b_nis = None
		self.nis = None
		self.b_sod = None

	def active_auth(self):
		t_start = time()
		logger.info("Active Authentication")
		if self.pub_key is None:
			self.set_pub_key()
		nonce = [0x47] * self.nonce_size

		signature = bytes(self.exec_servizi_int_auth(nonce))

		decrypted_sig = self.pub_key.encrypt(signature, "Dummy")[0]
		m = re.search(b"(\xff)*\x00(.*)", decrypted_sig)
		decrypted_sig = m.group(2)
		ok = (decrypted_sig == bytes(nonce))
		t_end = time()
		logger.log("TIME", f"Active auth: {t_end - t_start}")
		logger.debug(f"Nonce[{len(nonce)}]: {bytes(nonce)}")
		logger.debug(f"Signature[{len(signature)}]: {signature}")
		logger.debug(f"Dec Sig[{len(decrypted_sig)}]: {decrypted_sig}")
		logger.debug(f"Ok ? {ok}")
		return ok

	def passive_auth(self):

		if self.b_sod is None:
			self.set_SOD()
		if self.pub_key is None:
			self.set_pub_key()
		if self.nis is None:
			self.set_nis()

		correct = True

		correct &= self.verify_SOD_cert()
		correct &= self.verify_SOD()
		correct &= self.verify_nis()
		correct &= self.verify_pub_key()

		return correct

	def verify_SOD(self):
		logger.warning("SOD verify nog implemented")
		return True

	def verify_SOD_cert(self):

		self.cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, self.b_sod_cert)
		self.root_ca_cert_3 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
															  open('data/ItalyCA-3.cert', 'rb').read())
		# self.root_ca_cert_4 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
		#                                                       open('data/ItalyCA-4.cert','rb').read())
		#

		self.store = OpenSSL.crypto.X509Store()
		self.store.add_cert(self.root_ca_cert_3)
		self.store_context = OpenSSL.crypto.X509StoreContext(self.store, self.cert)
		c = False
		try:
			self.store_context.verify_certificate()
			c = True
		except:
			pass
		finally:
			if c:
				logger.success(f"SOD Certificate Ok")
			else:
				logger.error(f"SOD Certificate Ko")
			return c

	def verify_nis(self):
		correct = self.get_nis_hash() == self.get_SOD_nis_hash()
		if correct:
			logger.success(f"Numero Identificativo Servizi Hash Ok ")
		else:
			logger.error(f"Numero Identificativo Servizi Cert O Ko")
		return correct

		return correct

	def verify_pub_key(self):
		correct = self.get_pub_key_hash() == self.get_SOD_pub_key_hash()
		if correct:
			logger.success(f"Public Key Hash Ok ")
		else:
			logger.error(f"Public Key Hash Ko")
		return correct
		return correct

	def get_nis_hash(self):
		hash = Crypto.Hash.SHA256.new()
		hash.update(self.b_nis)
		self.nis_hash = hash.hexdigest()
		logger.debug(f"nis hash: {self.nis_hash}")
		return self.nis_hash

	def get_pub_key_hash(self):
		hash = Crypto.Hash.SHA256.new()
		hash.update(self.b_pub_key.strip(b'\00'))
		self.pub_key_hash = hash.hexdigest()
		logger.debug(f"pub key hash: {self.pub_key_hash}")
		return self.pub_key_hash

	def get_SOD_nis_hash(self):

		sod_data_parser = ASN1(self.b_sod_data)
		oid_tag, oid_len = sod_data_parser.parse()
		cont_tag, cont_len = sod_data_parser.parse(oid_len)

		sod_inn_data_parser = ASN1(cont_tag['children'][0]['bytes'])

		sod_tag, sod_len = sod_inn_data_parser.parse()

		self.b_sod_hashes_oid = sod_tag['children'][1]['children'][0]['bytes']
		self.sod_nis_hash = sod_tag['children'][2]['children'][2]['children'][1]['bytes'].hex()

		logger.debug(f"sod nis hash: {self.sod_nis_hash}")

		return self.sod_nis_hash

	def get_SOD_pub_key_hash(self):

		sod_data_parser = ASN1(self.b_sod_data)
		oid_tag, oid_len = sod_data_parser.parse()
		cont_tag, cont_len = sod_data_parser.parse(oid_len)

		sod_inn_data_parser = ASN1(cont_tag['children'][0]['bytes'])

		sod_tag, sod_len = sod_inn_data_parser.parse()

		self.b_sod_hashes_oid = sod_tag['children'][1]['children'][0]['bytes']
		self.sod_pub_key_hash = sod_tag['children'][2]['children'][0]['children'][1]['bytes'].hex()

		logger.debug(f"sod pub key hash: {self.sod_pub_key_hash}")
		return self.sod_pub_key_hash

	def set_SOD(self, SOD=None):
		if SOD is None:
			self.b_sod = bytes(self.get_EF_SOD())
		else:
			self.b_sod = SOD

		sod, sod_l = ASN1(self.b_sod).parse()

		b_pkcs7_outer = sod['bytes']
		pkcs7_outer, pkcs7_outer_l = ASN1(b_pkcs7_outer).parse()

		self.b_sod_pkcs7 = pkcs7_outer['bytes']
		oid, oid_l = ASN1(self.b_sod_pkcs7).parse()
		pkcs7, pkcs7_l = ASN1(self.b_sod_pkcs7).parse(oid_l)

		b_pkcs7_inner = pkcs7['bytes']
		pkcs7_inner, pkcs7_inner_l = ASN1(b_pkcs7_inner).parse()

		pkcs7_tags = pkcs7_inner['children']

		self.b_sod_data = pkcs7_tags[2]['bytes']
		self.b_sod_cert = pkcs7_tags[3]['bytes']
		self.b_sod_sig = pkcs7_tags[4]['bytes']

	def set_pub_key(self, pub_key=None):
		if pub_key is None:
			self.b_pub_key = bytes(self.get_EF_pub_key())
		else:
			self.b_pub_key = pub_key

		pub_key_tag_asn1_onj = ASN1(self.b_pub_key)
		offset = 0
		pub_key_tag, l = pub_key_tag_asn1_onj.parse(offset)
		mod_tag, exp_tag = pub_key_tag['children']

		n = int.from_bytes(mod_tag['bytes'], byteorder='big')
		e = int.from_bytes(exp_tag['bytes'], byteorder='big')
		pub_key = RSA.construct((n, e))

		# logger.debug(f"N:{n}\nE:{e}")

		self.pub_key = pub_key

	def set_nis(self):
		self.b_nis = bytes(self.get_EF_nis())
		self.nis = int.from_bytes(self.b_nis, 'big')
		logger.debug(f"b_nis: {len(self.b_nis), self.b_nis}")
		logger.debug(f"nis: {self.nis}")


token = CIE_Token(cached=False)
print(token.passive_auth())
print(token.active_auth())
