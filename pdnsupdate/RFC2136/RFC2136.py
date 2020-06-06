import logging
import dns.tsigkeyring
import dns.message
import dns.query
import dns.update
from . import errors

logger = logging.getLogger(__name__)


class RFC2136Client(object):
    """
    Manage RFC2136 communication
    """
    def __init__(self, server, port, key_name, key_secret, key_algorithm):
        self.server = server
        self.port = int(port)
        self.keyring = dns.tsigkeyring.from_text({
            key_name: key_secret
        })
        self.algorithm = dns.tsig.HMAC_MD5

    def add_record(self, record_name, record_type, record_content, record_ttl):
        """
        Add a record using the supplied information.
        :param str record_name: The record name (typically the server name for a A record).
        :param str record_type: The record type (A for an IPv4 address, AAAA for IPv6 ...).
        :param record_content: The record content (The IP for A or AAAA type ...).
        :param record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises: RFC2136.error.UpdateError : if an error occurs communicating with the DNS server
        """
        domain = self._find_domain(record_name)

        n = dns.name.from_text(record_name)
        o = dns.name.from_text(domain)
        t = dns.rdatatype.from_text(record_type)
        rel = n.relativize(o)

        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyalgorithm=self.algorithm)
        update.add(rel, record_ttl, t, record_content)

        try:
            response = dns.query.tcp(update, self.server, port=self.port)
        except Exception as e:
            raise errors.UpdateError('Encountered error adding record: {0}'
                                     .format(e))
        rcode = response.rcode()

        if rcode == dns.rcode.NOERROR:
            logger.debug('Successfully added TXT record %s', record_name)
        else:
            raise errors.UpdateError('Received response from server: {0}'
                                     .format(dns.rcode.to_text(rcode)))

    def del_record(self, record_name, record_type="A", record_content=None):
        """
        Delete a record using the supplied information.
        :param str record_name: The record name.
        :param str record_type: The record type.
        :param str record_content: The record content.
        :raises RFC2136.errors.PluginError: if an error occurs communicating with the DNS server
        """

        domain = self._find_domain(record_name)

        n = dns.name.from_text(record_name)
        o = dns.name.from_text(domain)
        rel = n.relativize(o)
        t = dns.rdatatype.from_text(record_type)

        update = dns.update.Update(
            domain,
            keyring=self.keyring,
            keyalgorithm=self.algorithm)
        update.delete(rel, t)

        try:
            response = dns.query.tcp(update, self.server, port=self.port)
        except Exception as e:
            raise errors.UpdateError('Encountered error deleting record: {0}'
                                     .format(e))
        rcode = response.rcode()

        if rcode == dns.rcode.NOERROR:
            logger.debug('Successfully deleted record %s', record_name)
        else:
            raise errors.UpdateError('Received response from server: {0}'
                                     .format(dns.rcode.to_text(rcode)))

    def _find_domain(self, record_name):
        """
        Find  the closest domain with an SOA record for a given domain name.
        :param str record_name: The record name for which to find the closest SOA record.
        :returns: The domain, if found.
        :rtype: str
        :raises RFC2136.error.UpdateError : if no SOA record can be found.
        """
        domain_name_guesses = self.base_domain_name_guesses(record_name)

        # Loop through until we find an authoritative SOA record
        for guess in domain_name_guesses:
            if self._query_soa(guess):
                return guess

        raise errors.UpdateError('Unable to determine base domain for {0} using names: {1}.'
                                 .format(record_name, domain_name_guesses))

    def _query_soa(self, domain_name):
        """
        Query a domain name for an authoritative SOA record.
        :param str domain_name: The domain name to query for an SOA record.
        :returns: True if found, False otherwise.
        :rtype: bool
        :raises RFC2136.errors.PluginError: if no response is received.
        """

        domain = dns.name.from_text(domain_name)

        request = dns.message.make_query(domain, dns.rdatatype.SOA, dns.rdataclass.IN)
        # Turn off Recursion Desired bit in query
        request.flags ^= dns.flags.RD

        try:
            try:
                response = dns.query.tcp(request, self.server, port=self.port)
            except OSError as e:
                logger.debug('TCP query failed, fallback to UDP: %s', e)
                response = dns.query.udp(request, self.server, port=self.port)
            rcode = response.rcode()

            # Authoritative Answer bit should be set
            if (rcode == dns.rcode.NOERROR
                    and response.get_rrset(response.answer,
                                           domain, dns.rdataclass.IN, dns.rdatatype.SOA)
                    and response.flags & dns.flags.AA):
                logger.debug('Received authoritative SOA response for %s', domain_name)
                return True

            logger.debug('No authoritative SOA record found for %s', domain_name)
            return False
        except Exception as e:
            raise errors.UpdateError('Encountered error when making query: {0}'
                                     .format(e))

    @staticmethod
    def base_domain_name_guesses(domain):
        """Return a list of progressively less-specific domain names.
        One of these will probably be the domain name known to the DNS provider.
        :Example:
        >>> base_domain_name_guesses('foo.bar.baz.example.com')
        ['foo.bar.baz.example.com', 'bar.baz.example.com', 'baz.example.com', 'example.com', 'com']
        :param str domain: The domain for which to return guesses.
        :returns: The a list of less specific domain names.
        :rtype: list
        """

        fragments = domain.split('.')
        return ['.'.join(fragments[i:]) for i in range(0, len(fragments))]


