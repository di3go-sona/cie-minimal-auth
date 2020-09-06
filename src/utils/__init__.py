from src.utils.misc import *
from src.utils.asn_parser import *
from src.utils.token import *
from time import time
from loguru import logger
from tqdm import tqdm

# logger.remove()
# logger.add(lambda msg: tqdm.write(msg, end=""))

logger.level("TIME", no=45, color="<red>", icon="🚨")
logger.level("APDU", no=45, color="<yellow>", icon="🚨")
logger.level("TRX", no=45, color="<white>", icon="🚨")
logger.level("PROGRESS", no=45, color="<fg ly>", icon="➱")
logger.level("ERR", no=45, color="<fg lr>", icon="x")

from smartcard.CardConnectionObserver import CardConnectionObserver



from asn1crypto import pem
from certvalidator import CertificateValidator, ValidationContext

class ConsoleCardConnectionObserver( CardConnectionObserver ):
    def update( self, cardconnection, ccevent ):
        if 'connect'==ccevent.type:
            # logger.log('TRX', 'connecting to ' + cardconnection.getReader())
            pass
        elif 'disconnect'==ccevent.type:
            # logger.log('TRX', 'disconnecting from ' + cardconnection.getReader())
            pass

        elif 'command'==ccevent.type:
            # logger.log('TRX', f'[IFD->ICC][{len(ccevent.args[0])}] {( ccevent.args[0] )}')
            pass
        elif 'response'==ccevent.type:
            # logger.log('TRX', f'[IFD<-ICC][{(len(ccevent.args[0])+2)}][{(hex(ccevent.args[1] + (ccevent.args[2]) << 8))}] {(ccevent.args[0])} ')
            pass
        else:
            logger.log('TRX', f'other event: {ccevent}')


