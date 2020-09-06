#Sql Alchemy, models & db stuff
from sqlalchemy import create_engine
from sqlalchemy.orm import session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String


engine = create_engine('sqlite:///cie-tokens.db', echo=False)
Base = declarative_base()

class Token(Base):
    __tablename__ = 'tokens'

    id = Column(Integer, primary_key=True)
    h_pubkey = Column(String)
    h_nis = Column(String)
    h_sod = Column(String)

    @staticmethod
    def from_CIE_Token(cie_token):
        return Token(h_pubkey=cie_token.h_pub_key, h_nis=cie_token.h_nis, h_sod=cie_token.h_sod)

    def b_pubkey(self):
        return bytes.fromhex(self.h_pubkey)


Base.metadata.create_all(engine)
