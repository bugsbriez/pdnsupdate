import requests
import logging
import configparser
import shelve
from RFC2136 import *

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)
config = configparser.ConfigParser()
config.read('config.ini')
logger.debug("Config file read")
shelf = shelve.open(config['PERSIST']['persit_file'])
logger.debug('shelf loaded')


def main(force=False):
    ip = get_public_ip(config['DEFAULT']['public_ip_provider'])
    logger.info("Public IP is " + ip)
    if has_changed(ip) or force:
        logger.info("Updating IP")
        update_ip(ip)
    shelf.close()


def get_public_ip(url):
    r = requests.get(url)
    ip = r.text
    return ip


def has_changed(ip):
    if 'last_ip' in shelf:
        logger.debug('Last IP was ' + shelf['last_ip'])
        if ip == shelf['last_ip']:
            logger.debug("Ip is still valid")
            return False
        else:
            logger.debug("Ip has changed")
            return True
    logger.debug("No previous IP")
    return True


def update_ip(ip):
    client = RFC2136Client(config['DNS']['dns_server'],
                           config['DNS']['dns_port'],
                           config['DNS']['dns_tsig_name'],
                           config['DNS']['dns_tsig_value'],
                           config['DNS']['dns_tsig_algorithm'])
    client.del_record(config['DEFAULT']['local_name'])
    client.add_record(config['DEFAULT']['local_name'], "A", ip, 600)
    shelf['last_ip'] = ip
    return


if __name__ == '__main__':
    main()
