# -*- coding: utf-8 -*-


import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from time import sleep

# this is the entry point
def route53_create_dns_challenge(logger, conf, domain, dns_payload):
     # Let's update the DNS on our R53 account
    zone_id = _get_route53_zone_id(logger, conf, domain['dns_zone'])
    if zone_id == None:
        logger.error("[route53] Cannot determine zone id for zone '{0}'".format(domain['dns_zone']))
        return None

    logger.info("[route53] Domain '{0}' has '{1}' for Id".format(domain['dns_zone'], zone_id))

    zone_id = _get_route53_zone_id(logger, conf, domain['dns_zone'])
    if zone_id == None:
        logger.error("[route53] Cannot find R53 zone {}, are you controling it ?".format(domain['dns_zone']))
        return None

    acme_domain = "_acme-challenge.{}".format(domain['name'])

    res = _reset_route53_letsencrypt_record(logger, conf, zone_id, domain['name'], acme_domain)
    if res == None:
        logger.error("[route53] An error occured while trying to remove a previous resource record. Skipping domain {0}".format(domain['name']))
        return None

    add_status = _create_route53_letsencrypt_record(logger, conf, zone_id, domain['name'], acme_domain, 'TXT', '"' + dns_payload + '"')
    if add_status == None:
        logger.error("[route53] An error occured while creating the dns record. Skipping domain {0}".format(domain['name']))
        return None

    add_status = _wait_letsencrypt_record_insync(logger, conf, add_status)
    if add_status == None:
        logger.error("[route53] Cannot determine if the dns record has been correctly created. Skipping domain {0}".format(domain['name']))
        return None

    if add_status == False:
        logger.error("[route53] We updated R53 but the servers didn't sync within 60 seconds. Skipping domain {0}".format(domain['name']))
        return None

    if add_status is not True:
        logger.error("[route53] An unexpected result code has been returned. Please report this bug. Skipping domain {0}".format(domain['name']))
        logger.error("[route53] add_status={0}".format(add_status))
        return None

    return True

def _get_route53_zone_id(logger, conf, zone_name):
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if zone_name.endswith('.') is not True:
        zone_name += '.'

    try:
        dn = ''
        zi = ''
        zone_list = r53.list_hosted_zones_by_name(DNSName=zone_name)
        while True:
            for zone in zone_list['HostedZones']:
                if zone['Name'] == zone_name:
                    return zone['Id']

            if zone_list['IsTruncated'] is not True:
                return None

            dn = zone_list['NextDNSName']
            zi = zone_list['NextHostedZoneId']

            logger.debug("[route53] Continuing to fetch mode Route53 hosted zones...")
            zone_list = r53.list_hosted_zones_by_name(DNSName=dn, HostedZoneId=zi)

    except ClientError as e:
        logger.error("[route53] Failed to retrieve Route53 zone Id for '{0}'".format(zone_name))
        logger.error("[route53] Error: {0}".format(e))
        return None

    return None

def _get_route53_zone_id(logger, conf, zone_name):
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if zone_name.endswith('.') is not True:
        zone_name += '.'

    try:
        dn = ''
        zi = ''
        zone_list = r53.list_hosted_zones_by_name(DNSName=zone_name)
        while True:
            for zone in zone_list['HostedZones']:
                if zone['Name'] == zone_name:
                    return zone['Id']

            if zone_list['IsTruncated'] is not True:
                return None

            dn = zone_list['NextDNSName']
            zi = zone_list['NextHostedZoneId']

            logger.debug("[route53] Continuing to fetch mode Route53 hosted zones...")
            zone_list = r53.list_hosted_zones_by_name(DNSName=dn, HostedZoneId=zi)

    except ClientError as e:
        logger.error("[route53] Failed to retrieve Route53 zone Id for '{0}'".format(zone_name))
        logger.error("[route53] Error: {0}".format(e))
        return None

    return None

def _reset_route53_letsencrypt_record(logger, conf, zone_id, zone_name, rr_fqdn):
    """
    Remove previous challenges from the hosted zone
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    rr_list = []
    results = r53.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordType='TXT',
                StartRecordName=rr_fqdn,
                MaxItems='100')

    while True:
        rr_list = rr_list + results['ResourceRecordSets']
        if results['IsTruncated'] == False:
            break

        results = r53.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordType='TXT',
            StartRecordName=results['NextRecordName'])

    r53_changes = { 'Changes': []}
    for rr in rr_list:
        if rr['Name'] == rr_fqdn and rr['Type'] == 'TXT':
            r53_changes['Changes'].append({
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': rr['Name'],
                    'Type': rr['Type'],
                    'TTL': rr['TTL'],
                    'ResourceRecords': rr['ResourceRecords']
                }
            })
            try:
                res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
                logger.info("[route53] Removed resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                return True

            except ClientError as e:
                logger.error("[route53] Failed to remove resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                logger.error("[route53] Error: {0}".format(e))
                return None

            break

    logger.debug("[route53] No Resource Record to delete.")
    return False

def _create_route53_letsencrypt_record(logger, conf, zone_id, zone_name, rr_fqdn, rr_type, rr_value):
    """
    Create the required dns record for letsencrypt to verify
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    r53_changes = { 'Changes': [{
        'Action': 'CREATE',
        'ResourceRecordSet': {
            'Name': rr_fqdn,
            'Type': rr_type,
            'TTL': 60,
            'ResourceRecords': [{
                'Value': rr_value
            }]
        }
    }]}

    try:
        res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
        logger.info("[route53] Create letsencrypt verification record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        return res

    except ClientError as e:
        logger.error("[route53] Failed to create resource record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        logger.error("[route53] Error: {0}".format(e))
        return None

def _wait_letsencrypt_record_insync(logger, conf, r53_status):
    """
    Wait until the new record set has been created
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    logger.info("[route53] Waiting for DNS to synchronize with new TXT value")
    timeout = 60

    status = r53_status['ChangeInfo']['Status']
    while status != 'INSYNC':
        sleep(1)
        timeout = timeout-1
        try:
            r53_status = r53.get_change(Id=r53_status['ChangeInfo']['Id'])
            status = r53_status['ChangeInfo']['Status']

            if timeout == -1:
                return False

        except ClientError as e:
            logger.error("[route53] Failed to retrieve record creation status.")
            logger.error("[route53] Error: {0}".format(e))
            return None

    logger.debug("[route53] Route53 synchronized in {0:d} seconds.".format(60-timeout))
    return True

