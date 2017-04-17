# -*- coding: utf-8 -*-

import base64
import boto3
import datetime
import hashlib
import json
import logging
import os
import ovh
import pytz
import re
import requests
import threading
import time
import yaml
from acme import challenges
from acme import client
from acme import errors
from acme import messages
from acme.jose.util import ComparableX509
from botocore.config import Config
from botocore.exceptions import ClientError
from Crypto import Random
from Crypto.PublicKey import RSA
from datetime import datetime
from OpenSSL import crypto
from ovh import exceptions as ovhExceptions
from time import sleep

LOG = logging.getLogger("letslambda")
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
LOG.addHandler(handler)
LOG.setLevel(logging.DEBUG)

def load_from_s3(conf, s3_key):
    """
    Try to load a file from the s3 bucket and return it as a string
    Return None on error
    """
    try:
        s3 = conf['s3_client']
        content = s3.get_object(Bucket=conf['s3_bucket'], Key=s3_key)["Body"].read()
    except ClientError as e:
        LOG.error("Failed to load '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        LOG.error("Error: {0}".format(e))
        return None

    return content

def load_config(s3, s3_bucket, letslambda_config):
    """
    Try to load the letlambda.yml out of the user bucket
    Will return None if the configuration file does not exist
    """

    try:
        conf = s3.get_object(Bucket=s3_bucket, Key=letslambda_config)["Body"].read()
    except ClientError as e:
        LOG.error("Failed to fetch letslambda configuration '{0}' in bucket '{1}'".format(letslambda_config, s3_bucket))
        LOG.error("Error: {0}".format(e))
        return None

    return yaml.load(conf)

def load_letsencrypt_account_key(conf):
    """
    Try to load the RSA account key from S3. If it doesn't
    succeed, it will create a new account key and try a registration
    with your provided information
    The letsenrypt account key is needed to avoid redoing the Proof of
    Possession challenge (PoP). It is also used to revoke an existing
    certificate.

    The old naming convention is .key.ras for the private key, but for
    consistency's sake crypto material were all named with .pem
    the function takes care of both, but defaults to the new behavior.
    """
    LOG.debug("Loading account key from s3")

    newAccountNeeded = False

    # check if an 'old' .key.rsa is present and load it
    account_key = load_from_s3(conf, conf['base_path']+'account.key.rsa')
    if account_key == None:
        # but if not, then use the new naming of '.key.pem'
        account_key = load_from_s3(conf, conf['base_path']+'account.key.pem')
        if account_key == None:
            account_key = create_and_save_key(conf, conf['base_path']+'account.key.pem', conf['kms_key'], 4096)
            newAccountNeeded = True
        conf['extension'] = 'pem'
    else:
        LOG.info("Using original private key naming convention (.key.rsa). You may rename to .key.pem for consistance purpose.")
        conf['extension'] = 'rsa'


    key = client.jose.JWKRSA.load(account_key)
    if newAccountNeeded:
        register_new_account(conf, key)

    return key

def register_new_account(conf, key):
    """
    Attempt to create a new account on the ACME server
    with the key. No problem if it fails because this
    kye is already used.
    """
    LOG.info("Registering with ACME server with the new account key")
    newReg = messages.NewRegistration(contact=tuple(conf['info']), key=key.public_key())
    acme_client = client.Client(conf['directory'], key)
    registration_resource = acme_client.register(newReg)
    LOG.info("Agreeing on the TOS on your behalf")
    acme_client.agree_to_tos(registration_resource)

def get_authorization(client, domain):
    authorization_resource = client.request_domain_challenges(domain['name'])
    return authorization_resource

def get_dns_challenge(authorization_resource):
    """
    Ask the ACME server to give us a list of challenges.
    Later, we will pick only the DNS one.
    """
    # Now let's look for a DNS challenge
    dns_challenges = filter(lambda x: isinstance(x.chall, challenges.DNS01), authorization_resource.body.challenges)
    return list(dns_challenges)[0]

def get_route53_zone_id(conf, zone_name):
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

            LOG.debug("Continuing to fetch mode Route53 hosted zones...")
            zone_list = r53.list_hosted_zones_by_name(DNSName=dn, HostedZoneId=zi)

    except ClientError as e:
        LOG.error("Failed to retrieve Route53 zone Id for '{0}'".format(zone_name))
        LOG.error("Error: {0}".format(e))
        return None

    return None

def reset_route53_letsencrypt_record(conf, zone_id, zone_name, rr_fqdn):
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
                LOG.info("Removed resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                return True

            except ClientError as e:
                LOG.error("Failed to remove resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                LOG.error("Error: {0}".format(e))
                return None

            break

    LOG.debug("No Resource Record to delete.")
    return False

def create_route53_letsencrypt_record(conf, zone_id, zone_name, rr_fqdn, rr_type, rr_value):
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
        LOG.info("Create letsencrypt verification record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        return res

    except ClientError as e:
        LOG.error("Failed to create resource record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        LOG.error("Error: {0}".format(e))
        return None

def wait_letsencrypt_record_insync(conf, r53_status):
    """
    Wait until the new record set has been created
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    LOG.info("Waiting for DNS to synchronize with new TXT value")
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
            LOG.error("Failed to retrieve record creation status.")
            LOG.error("Error: {0}".format(e))
            return None

    LOG.debug("Route53 synchronized in {0:d} seconds.".format(60-timeout))
    return True

def save_certificates_to_s3(conf, domain, chain_certificate, certificate):
    """
    Save/overwite newly requested certificate and corresponding chain certificate
    """
    if chain_certificate is not False:
        LOG.info("Saving certificate to S3")
        save_to_s3(conf, domain['base_path']+domain['name']+".chain.pem", chain_certificate)

    LOG.info("Saving chain certificate to S3")
    save_to_s3(conf, domain['base_path']+domain['name']+".cert.pem", certificate)


def upload_to_iam(conf, domain, chain_certificate, certificate, key):
    """
    Create a new IAM certificate from ACME and private key.
    It also fetched the chain certificate from ACME if provided
    """
    LOG.info("Loading certificate elements for domain '{0}' into IAM".format(domain['name']))

    iam = boto3.client('iam', config=Config(signature_version='v4', region_name=conf['region']))

    kwargs = {
        'Path': '/cloudfront/',
        'ServerCertificateName': domain['name'] + "-" + datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S"),
        'CertificateBody': certificate,
        'PrivateKey': key
        }
    try:
        if chain_certificate is not False:
            kwargs['CertificateChain'] = chain_certificate

        res = iam.upload_server_certificate(**kwargs)
    except ClientError as e:
        LOG.error("Failed to upload certificate for domain '{0}'".format(domain['name']))
        LOG.error("Exception: {0}".format(e))
        return False

    return res

def update_elb_server_certificate(conf, elb_region, elb_name, elb_port, server_certificate_arn):
    """
    Assign the new SSL certificate to the desired ELB
    """
    elb = boto3.client('elb', config=Config(signature_version='v4', region_name=elb_region))

    timeout = 60
    while timeout > -1:
        try:
            res = elb.set_load_balancer_listener_ssl_certificate(
                LoadBalancerName=elb_name,
                LoadBalancerPort=elb_port,
                SSLCertificateId=server_certificate_arn)
            break
        except ClientError as e:
            if e.response['Error']['Code']  == 'CertificateNotFound':
                # occasionally server certificate may be reported as not found, even in the same region.
                # let's give a chance to iam to be aware of our changes especially when  an ELB is in a
                # different region
                sleep(1)
                timeout = timeout - 1
                continue

            LOG.error("Failed to set server certificate '{0}' on ELB '{0}:{1}' in region '{2}'".format(server_certificate_arn, elb_name, elb_port, elb_region))
            LOG.error("Exception: {0}".format(e))
            return False

    if timeout < 0:
        LOG.error("Could not set server certificate '{0}' within 60 seconds on ELB '{1}:{2}' in region '{3}'.".format(server_certificate_arn, elb_name, elb_port, elb_region))
        return False

    LOG.debug("Set server certificate '{0}' on ELB '{1}:{2}' in region '{3}' in {4} seconds.".format(
        server_certificate_arn,
        elb_name,
        elb_port,
        elb_region,
        60-timeout))

    return True

def update_cf_server_certificate(conf, domain, cf_id, server_certificate_id):
    """
    Assign the new SSL certificate to the desired CloudFront distribution
    """
    cf = boto3.client('cloudfront', config=Config(signature_version='v4', region_name=conf['region']))

    try:
        res = cf.get_distribution(Id=cf_id)
        cf_conf = res['Distribution']['DistributionConfig']
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchDistribution':
            return False
        print e

    if res['Distribution']['Status'] != 'Deployed':
        LOG.error("Could not set server certificate '{0}' on CloudFront distribution {1} as the current status is '{2}'.".format(server_certificate_id, cf_id, res['Distribution']['Status']))
        return False

    cf_conf['ViewerCertificate'] = {
        'IAMCertificateId': server_certificate_id,
        'SSLSupportMethod': 'sni-only',
        'MinimumProtocolVersion': 'TLSv1'
    }

    kwargs = {
        'DistributionConfig': cf_conf,
        'Id': cf_id,
        'IfMatch': res['ETag']
    }

    # CF api is not very helpful when a certificate cannot be attached to a distribution
    # in that many errors are collated under the same error code. So, it's hard to tell
    # if the certificate wasn't available yet, or if it's a genuine error.
    timeout = 60
    while timeout > -1:
        try:
            res = cf.update_distribution(**kwargs)
            break
        except ClientError as e:
            if e.response['Error']['Code']  == 'InvalidViewerCertificate':
                sleep(1)
                timeout = timeout - 1
                continue

            LOG.error("Failed to set server certificate '{0}' on CloudFront distribution {1}".format(server_certificate_id, cf_id))
            LOG.error("Exception: {0}".format(e))
            return False

    if timeout < 0:
        LOG.error("Could not set server certificate '{0}' within 60 seconds on CloudFront distribution {1}".format(server_certificate_id, cf_id))
        return False

    LOG.debug("Set server certificate '{0}' on CloudFront distribution {1} in {2} seconds.".format(server_certificate_id, cf_id, 60-timeout))
    return True


def answer_dns_challenge(conf, client, domain, challenge):
    """
    Compute the required answer and set it in the DNS record
    for the domain.
    """
    authorization = "{}.{}".format(
        base64.urlsafe_b64encode(challenge.get("token")).decode("ascii").replace("=", ""),
        base64.urlsafe_b64encode(client.key.thumbprint()).decode("ascii").replace("=", "")
        )

    dns_response = base64.urlsafe_b64encode(hashlib.sha256(authorization.encode()).digest()).decode("ascii").replace("=", "")

    # Let's update the DNS on our R53 account
    zone_id = get_route53_zone_id(conf, domain['dns_zone'])
    if zone_id == None:
        LOG.error("Cannot determine zone id for zone '{0}'".format(domain['dns_zone']))
        return None

    LOG.info("Domain '{0}' has '{1}' for Id".format(domain['dns_zone'], zone_id))

    zone_id = get_route53_zone_id(conf, domain['dns_zone'])
    if zone_id == None:
        LOG.error("Cannot find R53 zone {}, are you controling it ?".format(domain['dns_zone']))
        return None

    acme_domain = "_acme-challenge.{}".format(domain['name'])

    res = reset_route53_letsencrypt_record(conf, zone_id, domain['name'], acme_domain)
    if res == None:
        LOG.error("An error occured while trying to remove a previous resource record. Skipping domain {0}".format(domain['name']))
        return None

    add_status = create_route53_letsencrypt_record(conf, zone_id, domain['name'], acme_domain, 'TXT', '"' + dns_response + '"')
    if add_status == None:
        LOG.error("An error occured while creating the dns record. Skipping domain {0}".format(domain['name']))
        return None

    add_status = wait_letsencrypt_record_insync(conf, add_status)
    if add_status == None:
        LOG.error("Cannot determine if the dns record has been correctly created. Skipping domain {0}".format(domain['name']))
        return None

    if add_status == False:
        LOG.error("We updated R53 but the servers didn't sync within 60 seconds. Skipping domain {0}".format(domain['name']))
        return None

    if add_status is not True:
        LOG.error("An unexpected result code has been returned. Please report this bug. Skipping domain {0}".format(domain['name']))
        LOG.error("add_status={0}".format(add_status))
        return None

    ## Now, let's tell the ACME server that we are ready
    challenge_response = challenges.DNS01Response(key_authorization=authorization)
    challenge_resource = client.answer_challenge(challenge, challenge_response)

    if challenge_resource.body.error != None:
        return False

    return True

def create_and_save_key(conf, s3_key, kms_key='AES256', key_size=2048):
    """
    Generate a RSA 4096 key for general purpose (account or CSR)
    """
    LOG.info("Generating new RSA key")
    key = RSA.generate(key_size).exportKey("PEM")
    save_to_s3(conf, s3_key, key, True, kms_key)
    return key

def save_to_s3(conf, s3_key, content, encrypt=False, kms_key='AES256'):
    """
    Save the rsa key in PEM format to s3 .. for later use
    """
    LOG.debug("Saving object '{0}' to in 's3://{1}'".format(s3_key, conf['s3_bucket']))
    s3 = conf['s3_client']
    kwargs = {
        'Bucket': conf['s3_bucket'],
        'Key': s3_key,
        'Body': content,
        'ACL': 'private'
    }
    if encrypt == True:
        if  kms_key != 'AES256':
            kwargs['ServerSideEncryption'] = 'aws:kms'
            kwargs['SSEKMSKeyId'] = kms_key
        else:
            kwargs['ServerSideEncryption'] = 'AES256'

    try:
        s3.put_object(**kwargs);
    except ClientError as e:
        LOG.error("Failed to save '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        LOG.error("Error: {0}".format(e))
        return None

def load_private_key(conf, domain):
    key = None
    s3_key = domain['base_path'] + domain['name'] + ".key." + conf['extension']

    if 'reuse_key' in domain.keys() and domain['reuse_key'] == True:
        LOG.debug("Attempting to load private key from S3 '{0}' for domain '{1}'".format(s3_key, domain['name']))
        key = load_from_s3(conf, s3_key)

    if key == None:
        key = create_and_save_key(conf, s3_key, domain['kmsKeyArn'], domain['key_size'])

    return crypto.load_privatekey(crypto.FILETYPE_PEM, key)

def generate_certificate_signing_request(conf, domain):
    key = load_private_key(conf, domain)

    LOG.info("Creating Certificate Signing Request.")
    csr = crypto.X509Req()
    csr.get_subject().countryName = domain['countryName']
    csr.get_subject().CN = domain['name']
    csr.set_pubkey(key)
    csr.sign(key, "sha1")
    return (csr, key)

def request_certificate(conf, domain, client, auth_resource):
    (csr, key) = generate_certificate_signing_request(conf, domain)

    try:
        (certificate, ar) = client.poll_and_request_issuance(ComparableX509(csr), [auth_resource])
    except errors.PollError as e:
        LOG.error("Failed to get certificate issuance for '{0}'.".format(domain['name']))
        LOG.error("Error: {0}".format(e))
        return (False, False, False)

    chain = requests.get(certificate.cert_chain_uri)
    chain_certificate = None

    if chain.status_code == 200:
        chain_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, chain.content)
        pem_chain_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, chain_certificate).decode("ascii")
    else:
        LOG.error("Failed to retrieve chain certificate. Status was '{0}'.".format(chain.status_code))
        pem_chain_certificate = False

    pem_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate.body.wrapped).decode("ascii")
    pem_private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("ascii")

    return (pem_chain_certificate, pem_certificate, pem_private_key)

def clean_file_path(path):
    """
    Normalize a file path so it can be used with the S3 service
    """
    path = os.path.normpath(path)
    path = re.sub('^.$', '', path)
    path = path.replace('//', '/')
    path = re.sub('^/', '', path)
    return path

def clean_dir_path(path):
    """
    Normalize a directory path so it can be used with the S3 service
    """
    path = clean_file_path(path)
    if path == '':
        return path
    else:
        return path + '/'

def list_expired_server_certificates(conf):
    """
    Returns a complete list of IAM server certificates
    """
    iam = boto3.client('iam', config=Config(signature_version='v4', region_name=conf['region']))

    server_certificates = []
    now = datetime.now(pytz.UTC)

    # this helps simulate expired certificates by moving 'now' one year in advance
    # uncomment as needed
    #now = now.replace(year = now.year + 1)
    try:
        result = iam.list_server_certificates(MaxItems=1)
        while True:
            for server_certificate in result['ServerCertificateMetadataList']:
                if now > server_certificate['Expiration']:
                    server_certificates.append(server_certificate)

            if result['IsTruncated'] == False:
                break

            result = iam.list_server_certificates(Marker=result['Marker'], MaxItems=1)

    except ClientError as e:
        LOG.error("Failed to load the list of IAM server certificates.")
        LOG.error("Error: {0}".format(e))
        return False

    return server_certificates

def delete_server_certificate(conf, server_certificate):
    """
    Attempt to delete an IAM server certificate. It's important to note that a
    server certificate cannot be deleted if it's being used by another AWS
    resource, like an ELB or CloudFront.
    """
    iam = boto3.client('iam', config=Config(signature_version='v4', region_name=conf['region']))

    try:
        LOG.info("Attempting to delete '{0}'".format(server_certificate['ServerCertificateName']))
        iam.delete_server_certificate(ServerCertificateName=server_certificate['ServerCertificateName'])

    except ClientError as e:
        LOG.error("Failed to delete IAM server certificate '{0}'".format(server_certificate['ServerCertificateName']))
        LOG.error("Error: {0}".format(e))
        return False

    return True

def update_dynamodb_table_throughput(conf, read_throughput, write_throughput):
    """
    Update the read and write throughput of a dynamodb table
    """
    matchobj = re.match(r'.*:dynamodb:(.*):\d{12}:table/(.*)', conf['notification_table'], re.M)
    ddb_region = matchobj.group(1)
    ddb_name = matchobj.group(2)

    ddb = boto3.client('dynamodb', region_name=ddb_region)

    timeout = 15
    while timeout > -1:
        try:
            ddb.update_table(TableName=ddb_name, ProvisionedThroughput={'ReadCapacityUnits': read_throughput, 'WriteCapacityUnits': write_throughput})
            break
        except ClientError as e:
            if e.response['Error']['Code'] == ValidationException:
                LOG.warning("The DynamoDB table '{0}' throughput hasn't changed because it's already at the desired capacity. Read: '{1}, Write: '{2}'.".format(ddb_name, read_throughput, write_throughput))
                break
            elif e.response['Error']['Code'] == 'ResourceInUseException':
                LOG.error("The DynamoDB table '{0}' throughput hasn't changed because it's already pending changes.".format(ddb_name))
                sleep(1)
                continue
            else:
                LOG.error("Failed to change DynamoDB table '{0}' throughput".format(ddb_name))
                LOG.error("Exception: {0}".format(e))
                return False

    if timeout < 0:
        LOG.error("Failed to change DynamoDB table '{0}' throughput within 15 seconds as the table is pending changes.".format(ddb_name))
        return False
    else:
        return True

def update_dynamodb_item(conf, domain):
    """
    Insert/update a dynamodb item into the LetsLambda notification table
    """
    matchobj = re.match(r'.*:dynamodb:(.*):\d{12}:table/(.*)', conf['notification_table'], re.M)
    ddb_region = matchobj.group(1)
    ddb_name = matchobj.group(2)

    table = boto3.resource('dynamodb', region_name=ddb_region).Table(ddb_name)

    kwargs = {
        'Key': {
            'domain': domain['name']
        },
        'UpdateExpression': 'set update_date=:d, reuse_key=:reuse_key, s3_region=:s3_region, s3_bucket=:b, key_path=:key_path, cert_path=:cert_path, chain_path=:chain_path',
        'ExpressionAttributeValues': {
            ':d': int(time.mktime(time.gmtime())),
            ':reuse_key': domain['reuse_key'],
            ':s3_region': conf['region'],
            ':b': conf['s3_bucket'],
            ':key_path': domain['base_path'] + domain['name'] + ".key." + conf['extension'],
            ':cert_path': domain['base_path'] + domain['name'] + ".cert." + conf['extension'],
            ':chain_path': domain['base_path'] + domain['name'] + ".chain." + conf['extension']
        },
        'ReturnValues': 'NONE',
        'ReturnConsumedCapacity': 'TOTAL'
    }

    timeout = 15
    while timeout > -1:
        try:
            res = table.update_item(**kwargs)
            break
        except ClientError as e:
            if e.response['Error']['Code']  == 'ProvisionedThroughputExceededException':
                timeout = timeout -1
                sleep(1)
                continue

            LOG.error("An error has occured while updating DynamoDB table '{0}'".format(ddb_name))
            LOG.error("Exception: {0}".format(e))
            return False

    if timeout < 0:
        LOG.error("Failed to update DynamoDB table within 15 seconds")
        return False

    if 'ResponseMetadata' not in res.keys() or 'HTTPStatusCode' not in res['ResponseMetadata'].keys():
        LOG.critical("Cannot determine DynamoDB operation result.")
        return None
    else:
        LOG.debug("RequestID: '{0}'".format(res['ResponseMetadata']['RequestId']))
        return True


def issue_certificates_handler(event, context):
    """
    This is the event handler that will perform the DNS challenge and retrieve
    the Let's Encrypt issued certificates
    """

    if 'bucket' not in event:
        LOG.critical("No bucket name has been provided. Exiting.")
        exit(1)
    s3_bucket = event['bucket']

    if 'region' not in event.keys() and 'AWS_DEFAULT_REGION' not in os.environ.keys():
        LOG.critical("Unable to determine AWS region code. Exiting.")
        exit(1)
    else:
        if 'region' not in event.keys():
            LOG.warning("Using local environment to determine AWS region code.")
            s3_region = os.environ['AWS_DEFAULT_REGION']
            LOG.warning("Local region set to '{0}'.".format(s3_region))
        else:
            s3_region = event['region']

    if 'defaultkey' not in event:
        LOG.warning("No default KMS key provided, defaulting to 'AES256'.")
        kms_key = 'AES256'
    else:
        LOG.info("Using {0} as default KMS key.".format(event['defaultkey']))
        kms_key = event['defaultkey']

    if 'configfile' not in event:
        LOG.warning("Using 'letslambda.yml' as the default configuration file.")
        letslambda_config = 'letslambda.yml'
    else:
        letslambda_config = event['configfile']

    letslambda_config = clean_file_path(letslambda_config)

    LOG.info("Retrieving configuration file '{0}' from bucket '{1}' in region '{2}' ".format(letslambda_config, s3_bucket, s3_region))
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=s3_region))

    conf = load_config(s3_client, s3_bucket, letslambda_config)
    if conf == None:
        LOG.critical("Cannot load letslambda configuration. Exiting.")
        exit(1)

    if 'notification_table' not in event:
        LOG.error("No DynamoDB table has been provided, so no notification will be issued.")
    else:
        conf['notification_table'] = event['notification_table']

    conf['region'] = os.environ['AWS_DEFAULT_REGION']
    conf['s3_bucket'] = s3_bucket
    conf['letslambda_config'] = letslambda_config
    conf['kms_key'] = kms_key

    if 'base_path' not in conf.keys():
        conf['base_path'] = ''
    else:
        conf['base_path'] = clean_dir_path(conf['base_path'])

    for domain in conf['domains']:
        payload = event
        payload['action'] = 'issue_certificate'
        payload['domain'] = domain
        payload['conf'] = conf
        payload['conf'].pop('domains', None)

        lambda_payload = json.dumps(payload, ensure_ascii=False)

        lambda_client = boto3.client('lambda')

        LOG.debug("Execution payload for domain '{0}'.".format(
            domain['name']
        ))
        LOG.debug(lambda_payload)

        try:
            r = lambda_client.invoke(
                FunctionName=context.function_name,
                InvocationType='Event',
                LogType='Tail',
                Payload=lambda_payload)

            LOG.debug("Execution in progress for domain '{0}'. RequestId: '{1}', StatusCode: '{2}'".format(
                domain['name'],
                r['ResponseMetadata']['RequestId'],
                r['StatusCode']
            ))
        except ClientError as e:
            LOG.error("Failed to execute lambda function '{0}'. Skipping domain '{1}'.".format(context.function_name, domain['name']))
            LOG.error("Error: {0}".format(e))
            continue


def issue_certificate_handler(event, context):
    """
    This is the event handler that will perform the DNS challenge and retrieve
    the Let's Encrypt issued certificates

    """

    if 'bucket' not in event:
        LOG.critical("No bucket name has been provided. Exiting.")
        exit(1)
    s3_bucket = event['bucket']

    if 'region' not in event.keys() and 'AWS_DEFAULT_REGION' not in os.environ.keys():
        LOG.critical("Unable to determine AWS region code. Exiting.")
        exit(1)
    else:
        if 'region' not in event.keys():
            LOG.warning("Using local environment to determine AWS region code.")
            s3_region = os.environ['AWS_DEFAULT_REGION']
            LOG.warning("Local region set to '{0}'.".format(s3_region))
        else:
            s3_region = event['region']

    if 'defaultkey' not in event:
        LOG.warning("No default KMS key provided, defaulting to 'AES256'.")
        kms_key = 'AES256'
    else:
        LOG.info("Using {0} as default KMS key.".format(event['defaultkey']))
        kms_key = event['defaultkey']


    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=s3_region))

    try:
        conf = event['conf']
    except KeyError as e:
        LOG.warning("No configuration statement was provided, trying to load a default one.")

        if 'configfile' not in event:
            LOG.warning("Using 'letslambda.yml' as the default configuration file.")
            letslambda_config = 'letslambda.yml'
        else:
            letslambda_config = event['configfile']

        letslambda_config = clean_file_path(letslambda_config)

        LOG.info("Retrieving configuration file '{0}' from bucket '{1}' in region '{2}' ".format(letslambda_config, s3_bucket, s3_region))
        conf = load_config(s3_client, s3_bucket, letslambda_config)

        if conf == None:
            LOG.critical("Cannot load letslambda configuration. Exiting.")
            exit(1)

    if 'notification_table' not in event:
        LOG.error("No DynamoDB table has been provided, so no notification will be issued.")
    else:
        conf['notification_table'] = event['notification_table']

    conf['s3_client'] = s3_client

    if 'base_path' not in conf.keys():
        conf['base_path'] = ''
    else:
        conf['base_path'] = clean_dir_path(conf['base_path'])

    account_key = load_letsencrypt_account_key(conf)

    acme_client = client.Client(conf['directory'], account_key)

    domain = event['domain']

    if 'dns_zone' not in domain.keys():
        LOG.critical("Missing parameter 'dns_zone' for domain '{0}'. Skipping domain.".format(domain['name']))
        exit(1)

    if 'kmsKeyArn' not in domain.keys():
        domain['kmsKeyArn'] = conf['kms_key']

    if 'reuse_key' not in domain.keys():
        domain['reuse_key'] = True

    if 'key_size' not in domain.keys():
        domain['key_size'] = 2048

    if 'base_path' not in domain.keys():
        domain['base_path'] = conf['base_path']
    else:
        domain['base_path'] = clean_dir_path(domain['base_path'])

    # start a separate thread to ensure private key is generated (if needed)
    # while the dns challenge occur to maximize efficiency
    private_key_thread = threading.Thread(target=load_private_key, args=(conf, domain,))
    private_key_thread.setDaemon(True)
    private_key_thread.start()

    authorization_resource = get_authorization(acme_client, domain)
    challenge = get_dns_challenge(authorization_resource)
    res = answer_dns_challenge(conf, acme_client, domain, challenge)
    if res is not True:
        LOG.critical("An error occurred while answering the DNS challenge. Skipping domain '{0}'.".format(domain['name']))
        exit(1)

    time_spent = 0.0
    while private_key_thread.is_alive() == True:
        private_key_thread.join(0.1)
        time_spent = time_spent + 0.1

        if time_spent % 5 == 0:
            LOG.debug("Waiting for the domain private key of '{0}' to be generated and saved in S3. Total time: {1:.2f}s".format(domain['name'], time_spent))

    (chain, certificate, key) = request_certificate(conf, domain, acme_client, authorization_resource)
    if key == False or certificate == False:
        LOG.critical("An error occurred while requesting the signed certificate. Skipping domain '{0}'.".format(domain['name']))
        exit(1)

    save_certificates_to_s3(conf, domain, chain, certificate)
    update_dynamodb_item(conf, domain)
    iam_cert = upload_to_iam(conf, domain, chain, certificate, key)
    if iam_cert is False or iam_cert['ResponseMetadata']['HTTPStatusCode'] is not 200:
        LOG.critical("An error occurred while saving your server certificate in IAM. Skipping domain '{0}'.".format(domain['name']))
        exit(1)

    # single ELB mode (compatibility)
    if 'elb' in domain.keys():
        if 'elb_port' not in domain.keys():
            domain['elb_port'] = 443
            LOG.warning("The ELB '{0}' has no port set. Using '{1}' as a default.".format(domain['elb'], domain['elb_port']))

        if 'elb_region' not in domain.keys():
            domain['elb_region'] = conf['region']
            LOG.warning("The ELB '{0}' has no region set. Using '{1}' as a default.".format(domain['elb'], domain['elb_region']))

        res = update_elb_server_certificate(conf,
                domain['elb_region'],
                domain['elb'],
                domain['elb_port'],
                iam_cert['ServerCertificateMetadata']['Arn'])
        if res is not True:
            LOG.error("An error occurred while attaching your server certificate to your ELB.")

    # Muti ELB mode
    if 'elbs' in domain.keys():
        for elb in domain['elbs']:
            if 'name' not in  elb.keys():
                LOG.error("The name of an ELB is missing. You should check {0}. Skipping this ELB.".format(conf['letslambda_config']))
                continue

            if 'port' not in elb.keys():
                elb['port'] = 443
                LOG.warning("The ELB '{0}' has no port set. Using '{1}' as a default.".format(elb['name'], elb['port']))

            if 'region' not in elb.keys():
                elb['region'] = conf['region']
                LOG.warning("The ELB '{0}' has no region set. Using '{1}' as a default.".format(elb['name'], elb['region']))

            res = update_elb_server_certificate(conf, elb['region'], elb['name'], elb['port'], iam_cert['ServerCertificateMetadata']['Arn'])
            if res is not True:
              LOG.error("An error occurred while attaching your server certificate to your ELB.")

    if 'cfs' in domain.keys():
        for cf in domain['cfs']:
            res = update_cf_server_certificate(conf, domain, cf['id'], iam_cert['ServerCertificateMetadata']['ServerCertificateId'])
            if res is not True:
                LOG.error("An error occurred while attaching your server certificate to your CloudFront distribution")


def purge_expired_certificates_handler(event, context):
    """
    Iterate hrough the IAM certificates and attempt to remove the ones that have expired
    """
    if 'bucket' not in event:
        LOG.critical("No bucket name has been provided. Exiting.")
        exit(1)
    s3_bucket = event['bucket']

    if 'region' not in event.keys() and 'AWS_DEFAULT_REGION' not in os.environ.keys():
        LOG.critical("Unable to determine AWS region code. Exiting.")
        exit(1)
    else:
        if 'region' not in event.keys():
            LOG.warning("Using local environment to determine AWS region code.")
            s3_region = os.environ['AWS_DEFAULT_REGION']
            LOG.warning("Local region set to '{0}'.".format(s3_region))
        else:
            s3_region = event['region']

    if 'configfile' not in event:
        LOG.warning("Using 'letslambda.yml' as the default configuration file.")
        letslambda_config = 'letslambda.yml'
    else:
        letslambda_config = event['configfile']

    letslambda_config = clean_file_path(letslambda_config)

    LOG.info("Retrieving configuration file '{0}' from bucket '{1}' in region '{2}' ".format(letslambda_config, s3_bucket, s3_region))
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=s3_region))

    conf = load_config(s3_client, s3_bucket, letslambda_config)
    if conf == None:
        LOG.critical("Cannot load letslambda configuration. Exiting.")
        exit(1)

    conf['region'] = os.environ['AWS_DEFAULT_REGION']
    conf['s3_client'] = s3_client
    conf['s3_bucket'] = s3_bucket
    conf['letslambda_config'] = letslambda_config

    server_certificates = list_expired_server_certificates(conf)
    if server_certificates == False:
        LOG.critical("Cannot load the list of IAM server certificates. Exiting.")
        exit(1)

    if 'delete_expired_certificates' in conf.keys() and conf['delete_expired_certificates'] == True:
        for server_certificate in server_certificates:
            delete_server_certificate(conf, server_certificate)
    else:
        LOG.info("The following IAM server certificates have expired and should be removed")
        for server_certificate in server_certificates:
            LOG.warning("IAM Server certificate '{0}' has expired as of '{1}'".format(
                server_certificate['ServerCertificateName'],
                server_certificate['Expiration']))

def lambda_handler(event, context):
    """
    This is the Lambda function handler from which all executions are routed.
    The appropriate routing is determine by event['action']
    """
    LOG.error("Starting execution of Let's Lamda")
    LOG.error(json.dumps(event))
    routing = {
        'purge': purge_expired_certificates_handler, # removes expired certs. this is declared in the cloudformation template
        'issue_certificates': issue_certificates_handler, # issue multiple certificates. this is the routing path
        'issue_certificate': issue_certificate_handler # issue a single certificate. this is usually executed via 'issue_certificates' routing path
    }

    if 'action' in event.keys() and event['action'] in routing.keys():
        routing[event['action']](event, context)
    else:
        issue_certificates_handler(event, context)
