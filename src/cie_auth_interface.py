import re

from src.cie_interface import *



class CIE_Token(CIE):
	nonce_size = 64

	def __init__(self, card=None):
		super().__init__(card.createConnection())


	def active_auth(self):
		self.start_part('auth')
		logger.debug("Starting Active Auth")

		self.read_EF_pub_key()

		nonce = [random.randrange(0,256) for i in range(self.nonce_size)]
		signature = bytes(self.exec_servizi_int_auth(nonce))

		decrypted_sig = self.pub_key.encrypt(signature, "Dummy")[0]
		m = re.search(b"(\xff)*\x00(.*)", decrypted_sig)
		decrypted_sig = m.group(2)

		correct = (decrypted_sig == bytes(nonce))
		# logger.log("TIME", f"Active auth TOT: {time() - t_start}")
		# logger.debug(f"Nonce[{len(nonce)}]: {bytes(nonce)}")
		# logger.debug(f"Signature[{len(signature)}]: {signature}")
		# logger.debug(f"Dec Sig[{len(decrypted_sig)}]: {decrypted_sig}")
		# logger.debug(f"Ok ? {ok}")
		logger.log("PROGRESS", f"Response received{self.part_elapsed('auth')} {self.elapsed()}")

		if correct:
			logger.log("PROGRESS", f"Active Auth OK {self.part_elapsed('auth')} {self.elapsed()}")
		else:
			logger.log("ERR", f"Active auth KO,  {self.part_elapsed('auth')} {self.elapsed()}")
			raise Exception('Active auth Failed')


	def passive_auth(self):
		t_start = time()
		logger.debug("Performing Passive Authentication")

		self.read_EF_SOD()
		self.read_EF_pub_key()
		self.read_EF_nis()

		correct = True

		t_read = time()
		correct &= self.verify_SOD_cert()
		t_check_CERT = time()
		# logger.log('TIME',f't_check_CERT {t_check_CERT-t_read}')
		correct &= self.verify_SOD()
		t_check_SOD = time()
		# logger.log('TIME', f't_check_SOD {t_check_SOD - t_check_CERT}')
		correct &= self.verify_nis()
		t_check_NIS = time()
		# logger.log('TIME', f't_check_NIS {t_check_NIS - t_check_SOD}')
		correct &= self.verify_pub_key()
		t_check_PUBKEY = time()
		# logger.log('TIME', f't_check_PUBKEY {t_check_PUBKEY - t_check_NIS}')


		t_end = time()
		elapsed_part = f"elapsed_part: {int((t_end - t_start)*1000)} ms"

		if correct:
			logger.log("PROGRESS", f"Passive Auth OK {elapsed_part}, {self.elapsed()}")
		else:
			logger.debug("ERR", f"Passive auth KO,  {elapsed_part},{self.elapsed()}")
			raise Exception('Passive auth Failed')



		return correct


	def disconnect(self):
		self.connection.disconnect()

