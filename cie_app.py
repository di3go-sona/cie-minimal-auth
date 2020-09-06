
#SmartCard Monitoring and callback
from src.utils import *
from src.cie_auth_interface import CIE_Token
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString
from time import sleep
from re import match
from sys import argv, stdin
import traceback

CIE_ATR='3B 8[EF] 80 01 80 31 80 65 [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2} 12 0F FF 82 ([0-9A-F]{2} )+'


class DB():
    s = sessionmaker(bind=engine)()

    @staticmethod
    def get_token( h_nis):
        # logger.log('PROGRESS',f'Querying DB for card {toHexString(nis)}')
        # return 0
        try:
            r = DB.s.query(Token).filter(Token.h_nis== bytes(h_nis).hex()).first()
            return r
        except Exception as e:
            logger.error(str(e))
            exit(1)

    @staticmethod
    def add_token(token):
        DB.s.add(token)
        DB.s.commit()


class App(CardObserver):

    def __init__(self, ):
        super().__init__()
        self.check_reader()
        self.init_callback()

        self.cie_tok = None
        self.register_mode = 0
        if '--register' in argv:
            self.register_mode = 1
            if '--pin' in argv:
                self.register_mode = 2

        sleep(1000)

    def init_callback(self):
        cardmonitor = CardMonitor()
        card_cb = self
        cardmonitor.addObserver(card_cb)
        print('Waiting for a card')

    def check_reader(self):
        r = get_first_reader()
        if r is None:
            raise Exception('No reader available, cannot start app')

    def update(self, observable, actions):
        (addedcards, removedcards) = actions

        for card in addedcards:
            try:
                if match(CIE_ATR,  toHexString(card.atr).strip()):
                    logger.log("PROGRESS", "Cie 3.0 Detected " )
                    self.on_card(card)
                else:
                    logger.log("ERR", "Cie 3.0 Detected, please remove card ")

            except Exception as e:
                logger.log('ERR',e)
                traceback.print_exc()

            finally:
                self.cie_tok.disconnect()

        for card in removedcards:
            # card.connection.disconnect()
            logger.log("PROGRESS", "Card Removed, Waiting for a card")


    def known_card(self):
        pass


    def on_card(self,card):

        # Creating a Wrapper around the card
        self.cie_tok = CIE_Token(card)

        # retrieving the nis - numero identificativo dei servizi
        id = self.cie_tok.read_EF_nis()

        # query the card to the db
        tok = DB.get_token(id)
        logger.log('PROGRESS', f'Querying Card {id} to the DB, {self.cie_tok.elapsed()}')


        if tok:
            logger.log('PROGRESS',f'Card found in DB! {self.cie_tok.elapsed()}')
            # Card is present in the database
            # Perform Challenge Response (Active Auth)
            self.cie_tok._set_pub_key(tok.b_pubkey())
            self.cie_tok.active_auth()

            logger.success( f'Card Authenticated! {self.cie_tok.elapsed()}')
        else:
            # Card is new, authenticate it
            # add it to the database if allowed, otherwise end
            self.new_card()

        self.cie_tok.disconnect()


    def new_card(self):
        if self.register_mode == 0:
            logger.log('ERR', f'Card not in in DB! You are not registered ! remove card, {self.cie_tok.elapsed()}')
        elif self.register_mode == 1:
            while True:
                logger.log('PROGRESS', f'Card not in in DB! Press enter to create one a new one, {self.cie_tok.elapsed()}')
                c = stdin.read(1)
                if c == '\n':
                    self.start_time = time()
                    break

            self.cie_tok.passive_auth()
            self.cie_tok.active_auth()

            t = Token.from_CIE_Token(self.cie_tok)
            DB.add_token(t)
            logger.log('SUCCESS', f'Card added to DB! {self.cie_tok.elapsed()}')



        elif self.register_mode == 2:
            logger.log('PROGRESS', f'Card not in in DB! creating a new one, elapsed: {int(self.cie_tok.elapsed()*1000)} ms')
            raise NotImplementedError()
        else:
            raise Exception('Unknow REGISTER_MODE')

@logger.catch
def main():
    App()

if __name__ == '__main__':
    main()