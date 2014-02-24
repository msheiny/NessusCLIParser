#!/usr/bin/env python
import ConfigParser
import os
from sqlalchemy import create_engine
from sqlalchemy import Column, String, DateTime
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
class dhcp_table(Base):
    """ Table definitions for DHCP """
    __tablename__ = 'dhcp'

    MAC = Column(String, primary_key=True)
    IP = Column(String)
    Hostname = Column(String)
    Bootfile = Column(String)
    options = Column(String)
    Timestamp = Column(DateTime)
    Root = Column(String)
    Owner = Column(String)
    Location = Column(String)
    Comment = Column(String)
    PrimaryInt = Column(String)

class TrollDB(object):
    """Troll database connector class. Should only initiate one class object
    per session """

    def __init__(self):
        script_dir = os.path.dirname(os.path.realpath(__file__))
        mysql_cfg_file = os.path.join(script_dir,"mysql.txt")
        try:
            open(mysql_cfg_file)
            mysql_cfg = ConfigParser.RawConfigParser()
            mysql_cfg.read(mysql_cfg_file)
            user = mysql_cfg.get('Credentials', 'user')
            passwd = mysql_cfg.get('Credentials', 'pass')
            uri = mysql_cfg.get('Credential','uri')
        except (ConfigParser.Error, IOError): 
            print mysql_cfg
            raise UserWarning('Problems with getting credentials for user db')

        read_engine = create_engine('mysql://{0}:{1}@{2}/dhcp'.format(
                                    user, passwd, uri))
        session = sessionmaker(bind=read_engine)
        self.db = session()

    def UserForMac(self, mac):
        try:
            owner = self.db.query(dhcp_table.Owner).filter(dhcp_table.MAC==mac)[0]
            return owner[0]
        except:
            return None

    def Close(self):
        self.db.close()
