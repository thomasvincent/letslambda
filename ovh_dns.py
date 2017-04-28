# -*- coding: utf-8 -*-

import json

import ovh
import string
import random
import time

import dns
import dns.name
import dns.query
import dns.resolver


def ovh_create_dns_challenge(logger, conf, domain, dns_payload):

    acme_domain = "_acme-challenge"

    # Instanciate an OVH Client.
    # You can generate new credentials with full access to your account on
    # the token creation page

    if 'dns_auth' not in domain:
        logger.critical('[ovh] Couldn\'t find OVH authentication credentials. Aborting.')
        return None

    ovh_auth = json.loads(domain['dns_auth'])[0]
    client = ovh.Client(**ovh_auth)

    acme_domain = '{0}.{1}'.format(
        acme_domain,
        domain['name'].replace(
            '.{0}'.format(domain['dns_zone']),
            ''
        )
    )

    try:
        result = client.get('/domain/zone/{0}/record'.format(domain['dns_zone']),
            fieldType='TXT',
            subDomain=acme_domain,
        )
    except ovh.exceptions.InvalidCredential as e:
        logger.error("[ovh] Failed to list DNS zone '{0}'".format(domain['dns_zone']))
        logger.error("[ovh] Error: {0}".format(e))
        return None


    if result: # clean the DNS record from all previous value (because it's ephemeral)
        for x in xrange(len(result)):
            logger.debug("[ovh] Removing DNS entry '/domain/zone/{0}/record/{1}'".format(domain['dns_zone'], result[x]))
            result = client.delete("/domain/zone/{0}/record/{1}".format(domain['dns_zone'], result[x]))

    logger.debug("[ovh] The DNS entry '{0}.{1}' doesn't exist".format(acme_domain, domain['dns_zone']))
    result = client.post('/domain/zone/{0}/record'.format(domain['dns_zone']),
        fieldType="TXT",
        subDomain=acme_domain,
        ttl=60,
        target=dns_payload)

    result = client.post('/domain/zone/{0}/refresh'.format(domain['dns_zone']))

    return _wait_dns_refresh(logger, domain['dns_zone'], acme_domain, dns_payload, 200)


def _get_authoritative_nameserver(logger, domain):
    n = dns.name.from_text(domain)

    depth = 2
    default = dns.resolver.get_default_resolver()
    nameserver = default.nameservers[0]

    last = False
    while not last:
        s = n.split(depth)

        last = s[0].to_unicode() == u'@'
        sub = s[1]

        query = dns.message.make_query(sub, dns.rdatatype.NS)
        response = dns.query.udp(query, nameserver)

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            if rcode == dns.rcode.NXDOMAIN:
                logger.error('[ovh] {0} does not exist.'.format(sub))
            else:
                logger.warning("[ovh] Error while finding authoritative DNS server for '{0}'".format(domain))
                logger.warning("[ovh] Error: '{0}'".format(dns.rcode.to_text(rcode)))

            return default.nameservers[0]

        rrset = None
        if len(response.authority) > 0:
            rrset = response.authority[0]
        else:
            rrset = response.answer[0]

        rr = rrset[0]
        if rr.rdtype == dns.rdatatype.SOA:
            logger.debug('[ovh] Same server is authoritative for %s' % sub)
        else:
            authority = rr.target
            logger.debug('[ovh] %s is authoritative for %s' % (authority, sub))
            nameserver = default.query(authority).rrset[0].to_text()

        depth += 1

    return nameserver

def _wait_dns_refresh(logger, domain, subDomain, value, timeout = 60):

    wait_time = 2
    total_wait_time = 0
    ret = None
    nx_retry = 2
    nx_wait_time = 2

    # FIXME when domain doesn't exists
    nameserver = _get_authoritative_nameserver(logger, domain)
    if nameserver == None:
        logger.error("[ovh] Name server for '{0}' not found".format(domain))

    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = [ nameserver ]

    while total_wait_time < timeout:
        try:
            r = dns.resolver.query('{0}.{1}'.format(subDomain, domain), 'TXT')
        except dns.resolver.NXDOMAIN:
            # OVH seems to randomly return a NXDOMAIN when a zone is being refreshed
            # the code below attempts to deal with this by waiting a bit and retrying
            logger.error("[ovh] Received exception NXDOMAIN for domain '{0}'.{1} attemp(s) left.".format(domain, nx_retry))
            if nx_retry > 0:
                nx_retry = nx_retry-1
                time.sleep(nx_wait_time)
                total_wait_time = total_wait_time + nx_wait_time
                continue
            else:
                return None
        except dns.resolver.NameError:
            logger.error("[ovh] Receive exception NameError for domain '{0}'".format(domain))
            return None
        except dns.resolver.Timeout:
            logger.error("[ovh] Receive exception Timeout for domain '{0}'".format(domain))
            return None
        except dns.exception.DNSException:
            logger.error("[ovh] Receive exception DNSException for domain '{0}'".format(domain))
            return None

        if len(r.response.answer[0]) > 0:
            for x in xrange(len(r.response.answer[0])): # if past executions have failed, ensure to iterte over all TXT records
                answer = '{0}'.format(r.response.answer[0][x])[1:-1]
                logger.debug("[ovh] Got '{0}', looking for '{1}'".format(answer, value))
                if answer == value:
                    logger.debug("[ovh] DNS in sync")
                    return True


        time.sleep(wait_time)
        total_wait_time = total_wait_time + wait_time
        wait_time = wait_time+2

    logger.error("[ovh] DNS NOT in sync")
    return False

