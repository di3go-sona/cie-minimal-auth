from sys import stderr,stdout,stdin
from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.sw.ISO7816_8ErrorChecker import ISO7816_8ErrorChecker
from smartcard.sw.ISO7816_9ErrorChecker import ISO7816_9ErrorChecker
from smartcard.sw.SWExceptions import SWException, WarningProcessingException

from src.utils import *

MAX_APDU_SIZE = 231 # Max APDU SIZE = 231

class SmartCard:

	ef_map = {
		0x2f00 : 'EF.DIR'
	}

	def __init__(self, connection=None):

		self.connection = connection
		self.ef = None
		self.ef_size = None
		self.cached_efs = {}
		self.start_time = time()
		self.part_start_time = {}

		if not self.connection:
			r = get_first_reader()
			self.connection = r.createConnection()


		errorchain = []
		errorchain = [ErrorCheckingChain(errorchain, ISO7816_9ErrorChecker())]
		errorchain = [ErrorCheckingChain(errorchain, ISO7816_8ErrorChecker())]
		errorchain = [ErrorCheckingChain(errorchain, ISO7816_4ErrorChecker())]
		self.connection.setErrorCheckingChain(errorchain)
		self.connection.addSWExceptionToFilter(WarningProcessingException)

		# observer = ConsoleCardConnectionObserver()
		# self.connection.addObserver(observer)

		self.connection.connect()

	def elapsed(self):
		return f"elapsed: {self._elapsed()} ms."

	def part_elapsed(self, part_name):
		return f"part_elapsed: {self._part_elapsed(part_name)} ms,"

	def _part_elapsed(self, part_name):
		return int((time() - self.part_start_time.get(part_name)) * 1000)


	def _elapsed(self):
		return int((time() - self.start_time) * 1000)

	def start_part(self, part_name):
		self.part_start_time[part_name] = time()

	def transmit(self, apdu):
		"""
		Transmits an apdu to the card

		Args:
			apdu (Bytearray): The apdu to be transmitted to the card
		Return:
			( Bytearray, str , int ): Data returned by the card, Code of the card, time of the operation
		"""

		self.start_part('trx')

		response, sw1, sw2 = self.connection.transmit(apdu)

		status = '%02x%02x' % (sw1, sw2)



		# status_text = self.status_map.get(status, 'Unknown status code')


		sent, rec = len(apdu), len(response)+2
		bits = (sent+ rec)*8
		millisecs = self._part_elapsed('trx')
		kbps = bits/millisecs

		# logger.log('TRX',f'Sent: {sent}B \tRec: {rec}B \tSpeed: {kbps}kbps,  {(self.elapsed())}')

		return (response), status, millisecs

	def select_EF(self, EFID):
		"""
		Sends the apdu to select the Application Directory Folder with the specified EFID

		Return:
			( Bytearray): The return of the SELECT command
		"""

		logger.debug(f"Selecting EF: {hex(EFID)}")
		stdin.flush()


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

		self.start_part('read')
		logger.debug(f"Reading: {hex(EFID)} - {self.ef_map.get(EFID)},{self.part_elapsed('read')}  {self.elapsed()}")
		stderr.write("\033[F")
		stderr.flush()

		if (EFID is None and self.ef in self.cached_efs) or \
			EFID in self.cached_efs:

			if EFID is None:
				EFID = self.ef

			logger.debug(f"Reading from cache: {hex(EFID)} - {self.ef_map.get(EFID)},{self.part_elapsed('read')} {self.elapsed()}")
			return self.cached_efs[EFID]

		if EFID:
			self.select_EF(EFID)



		if self.ef_size == -1:
			logger.error("unable to select File")
			return []

		if (EFID > 0xFFFF):
			logger.error("EFID should be less than 0xFFFF")
			return []

		# logger.debug(f"Reading: {hex(EFID) - self.ef_map.get(EFID)}, {self.elapsed()}")
		bytes_left = self.ef_size
		offset = 0
		data = []



		while bytes_left > 0:
			bytes_to_read = min(MAX_APDU_SIZE, bytes_left)
			logger.debug(f"Reading: {hex(EFID)} - {self.ef_map.get(EFID)}, {self.part_elapsed('read')} {self.elapsed()}")
			stderr.write("\033[F")
			stderr.flush()
			apdu = [
				0x00,  # CLA
				0xb0,  # INS = BINARY READ
				(offset >> 8) & 0xff,  # P1 = High byte of offset in current file
				offset & 0xff,  # P2 = Low byte of offset in current file
				bytes_to_read,  # LC = Bytes to read
			]

			d, s, t = self.transmit(apdu)

			# logger.debug(f"Reading EF {hex(self.ef)} - {self.ef_map[self.ef]}: {offset + len(d)}/{self.ef_size}")
			# print(d)

			if s in '6982|6a82':
				bytes_left = 0
				d = []

			data += d
			bytes_left -= len(d)
			offset += len(d)

		logger.debug(f"Reading: {hex(EFID)} - {self.ef_map.get(EFID)}, {self.part_elapsed('read')} {self.elapsed()}")


		self.cached_efs[self.ef] = bytes(data)
		return  bytes(data)

	def read_EF_CRT(self, EFID):
		return self.select_EF(EFID)

	def read_SDO_DOCP(self, SDOID):

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
		return self.get_resp()


	def read_SDO_DOUP(self, SDOID):

		sdo_1 = (SDOID >> 16) & 0xff
		sdo_2 = (SDOID >> 8) & 0xff
		sdo_3 = (SDOID >> 0) & 0xff

		apdu = [
			0x00,  # CLA -> ISO
			0xcb,  # INS -> SDO GET DATA
			0x3f,  # P1 -> curr DF
			0xff,  # P2 -> curr DF
			0x0a,  # Lc -> Data lEN
			0x4d, 0x08, 0x70, 0x06, sdo_1, sdo_2, sdo_3, 0x3, 0x7f, 0x41, 0x80  # Data -> refer to IASECC 9.8.1.1
		]

		d, _, _ = self.transmit(apdu)
		return d

	def set_CSE_servizi_int_auth(self):
		logger.debug(f"Selecting CSE")
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

	def exec_get_challenge(self):
		"""
        Sends an APDU to the CIE requesting a random number
        :return: The random number in form of integer array
        """

		apdu = [
			0x00,  # CLA
			0x84,  # INS = C/R INT AUTH
			0x00,  # P1 = 0x00
			0x00,  # P2 = 0x00
			0x08,
		]

		d, s, t = self.transmit(apdu)
		return d

