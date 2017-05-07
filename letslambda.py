# -*- coding: utf-8 -*-

import base64
import boto3
import datetime
import hashlib
import json
import logging
import os
import ovh
import paramiko
import pytz
import re
import requests
import socket
import StringIO
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
from urlparse import urlparse

logger = logging.getLogger("letslambda")
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

def load_from_s3(conf, s3_key):
    """
    Try to load a file from the s3 bucket and return it as a string
    Return None on error
    """
    try:
        s3 = conf['s3_client']
        content = s3.get_object(Bucket=conf['s3_bucket'], Key=s3_key)["Body"].read()
    except ClientError as e:
        logger.error("[main] Failed to load '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        logger.error("[main] Error: {0}".format(e))
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
        logger.error("[main] Failed to fetch letslambda configuration '{0}' in bucket '{1}'".format(letslambda_config, s3_bucket))
        logger.error("[main] Error: {0}".format(e))
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
    logger.debug("[main] Loading account key from s3")

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
        logger.info("[main] Using original private key naming convention (.key.rsa). You may rename to .key.pem for consistance purpose.")
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
    logger.info("[main] Registering with ACME server with the new account key")
    newReg = messages.NewRegistration(contact=tuple(conf['info']), key=key.public_key())
    acme_client = client.Client(conf['directory'], key)
    registration_resource = acme_client.register(newReg)
    logger.info("[main] Agreeing on the TOS on your behalf")
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

def save_certificates_to_s3(conf, domain, chain_certificate, certificate):
    """
    Save/overwite newly requested certificate and corresponding chain certificate
    """
    if chain_certificate is not False:
        logger.info("[main] Saving certificate to S3")
        save_to_s3(conf, domain['base_path']+domain['name']+".chain.pem", chain_certificate)

    logger.info("[main] Saving chain certificate to S3")
    save_to_s3(conf, domain['base_path']+domain['name']+".cert.pem", certificate)


def upload_to_iam(conf, domain, chain_certificate, certificate, key):
    """
    Create a new IAM certificate from ACME and private key.
    It also fetched the chain certificate from ACME if provided
    """
    logger.info("[main] Loading certificate elements for domain '{0}' into IAM".format(domain['name']))

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
        logger.error("[main] Failed to upload certificate for domain '{0}'".format(domain['name']))
        logger.error("[main] Exception: {0}".format(e))
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

            logger.error("[main] Failed to set server certificate '{0}' on ELB '{0}:{1}' in region '{2}'".format(server_certificate_arn, elb_name, elb_port, elb_region))
            logger.error("[main] Exception: {0}".format(e))
            return False

    if timeout < 0:
        logger.error("[main] Could not set server certificate '{0}' within 60 seconds on ELB '{1}:{2}' in region '{3}'.".format(server_certificate_arn, elb_name, elb_port, elb_region))
        return False

    logger.debug("[main] Set server certificate '{0}' on ELB '{1}:{2}' in region '{3}' in {4} seconds.".format(
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
        logger.error("[main] Could not set server certificate '{0}' on CloudFront distribution {1} as the current status is '{2}'.".format(server_certificate_id, cf_id, res['Distribution']['Status']))
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

            logger.error("[main] Failed to set server certificate '{0}' on CloudFront distribution {1}".format(server_certificate_id, cf_id))
            logger.error("[main] Exception: {0}".format(e))
            return False

    if timeout < 0:
        logger.error("[main] Could not set server certificate '{0}' within 60 seconds on CloudFront distribution {1}".format(server_certificate_id, cf_id))
        return False

    logger.debug("[main] Set server certificate '{0}' on CloudFront distribution {1} in {2} seconds.".format(server_certificate_id, cf_id, 60-timeout))
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

    dns_payload = base64.urlsafe_b64encode(hashlib.sha256(authorization.encode()).digest()).decode("ascii").replace("=", "")

    provider = "{0}_dns".format(domain['dns_provider'])
    provider_func = "{0}_create_dns_challenge".format(domain['dns_provider'])

    create_dns_challenge = getattr(__import__(provider, fromlist=[provider_func]), provider_func)
    if create_dns_challenge(logger, conf, domain, dns_payload) == None:
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
    logger.info("[main] Generating new RSA key")
    key = RSA.generate(key_size).exportKey("PEM")
    save_to_s3(conf, s3_key, key, True, kms_key)
    return key

def save_to_s3(conf, s3_key, content, encrypt=False, kms_key='AES256'):
    """
    Save the rsa key in PEM format to s3 .. for later use
    """
    logger.debug("[main] Saving object '{0}' to in 's3://{1}'".format(s3_key, conf['s3_bucket']))
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
        logger.error("[main] Failed to save '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        logger.error("[main] Error: {0}".format(e))
        return None

def load_private_key(conf, domain):
    key = None
    s3_key = domain['base_path'] + domain['name'] + ".key." + conf['extension']

    if 'reuse_key' in domain.keys() and domain['reuse_key'] == True:
        logger.debug("[main] Attempting to load private key from S3 '{0}' for domain '{1}'".format(s3_key, domain['name']))
        key = load_from_s3(conf, s3_key)

    if key == None:
        key = create_and_save_key(conf, s3_key, domain['kmsKeyArn'], domain['key_size'])

    return crypto.load_privatekey(crypto.FILETYPE_PEM, key)

def generate_certificate_signing_request(conf, domain):
    key = load_private_key(conf, domain)

    logger.info("[main] Creating Certificate Signing Request.")
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
        logger.error("[main] Failed to get certificate issuance for '{0}'.".format(domain['name']))
        logger.error("[main] Error: {0}".format(e))
        return (False, False, False)
    except messages.Error as e:
        logger.error("[main] Failed to get certificate issuance for '{0}'.".format(domain['name']))
        logger.error("[main] Error: {0}".format(e))
        return (False, False, False)

    chain = requests.get(certificate.cert_chain_uri)
    chain_certificate = None

    if chain.status_code == 200:
        chain_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, chain.content)
        pem_chain_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, chain_certificate).decode("ascii")
    else:
        logger.error("[main] Failed to retrieve chain certificate. Status was '{0}'.".format(chain.status_code))
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
        logger.error("[main] Failed to load the list of IAM server certificates.")
        logger.error("[main] Error: {0}".format(e))
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
        logger.info("[main] Attempting to delete '{0}'".format(server_certificate['ServerCertificateName']))
        iam.delete_server_certificate(ServerCertificateName=server_certificate['ServerCertificateName'])

    except ClientError as e:
        logger.error("[main] Failed to delete IAM server certificate '{0}'".format(server_certificate['ServerCertificateName']))
        logger.error("[main] Error: {0}".format(e))
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
                logger.warning("[main] The DynamoDB table '{0}' throughput hasn't changed because it's already at the desired capacity. Read: '{1}, Write: '{2}'.".format(ddb_name, read_throughput, write_throughput))
                break
            elif e.response['Error']['Code'] == 'ResourceInUseException':
                logger.error("[main] The DynamoDB table '{0}' throughput hasn't changed because it's already pending changes.".format(ddb_name))
                sleep(1)
                continue
            else:
                logger.error("[main] Failed to change DynamoDB table '{0}' throughput".format(ddb_name))
                logger.error("[main] Exception: {0}".format(e))
                return False

    if timeout < 0:
        logger.error("[main] Failed to change DynamoDB table '{0}' throughput within 15 seconds as the table is pending changes.".format(ddb_name))
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

            logger.error("[main] An error has occured while updating DynamoDB table '{0}'".format(ddb_name))
            logger.error("[main] Exception: {0}".format(e))
            return False

    if timeout < 0:
        logger.error("[main] Failed to update DynamoDB table within 15 seconds")
        return False

    if 'ResponseMetadata' not in res.keys() or 'HTTPStatusCode' not in res['ResponseMetadata'].keys():
        logger.critical("[main] Cannot determine DynamoDB operation result.")
        return None
    else:
        logger.debug("[main] RequestID: '{0}'".format(res['ResponseMetadata']['RequestId']))
        return True


def deploy_certificates_handler(event, context):
    """
    This is the event handler that will deploy the issued certificates
    """

    if 'bucket' not in event:
        logger.critical("[main] No bucket name has been provided. Exiting.")
        exit(1)
    s3_bucket = event['bucket']

    if 'region' not in event.keys() and 'AWS_DEFAULT_REGION' not in os.environ.keys():
        logger.critical("[main] Unable to determine AWS region code. Exiting.")
        exit(1)
    else:
        if 'region' not in event.keys():
            logger.warning("[main] Using local environment to determine AWS region code.")
            s3_region = os.environ['AWS_DEFAULT_REGION']
            logger.warning("[main] Local region set to '{0}'.".format(s3_region))
        else:
            s3_region = event['region']

    if 'defaultkey' not in event:
        logger.warning("[main] No default KMS key provided, defaulting to 'AES256'.")
        kms_key = 'AES256'
    else:
        logger.info("[main] Using {0} as default KMS key.".format(event['defaultkey']))
        kms_key = event['defaultkey']

    if 'configfile' not in event:
        logger.warning("[main] Using 'letslambda.yml' as the default configuration file.")
        letslambda_config = 'letslambda.yml'
    else:
        letslambda_config = event['configfile']

    letslambda_config = clean_file_path(letslambda_config)

    logger.info("[main] Retrieving configuration file '{0}' from bucket '{1}' in region '{2}' ".format(letslambda_config, s3_bucket, s3_region))
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=s3_region))

    conf = load_config(s3_client, s3_bucket, letslambda_config)
    if conf == None:
        logger.critical("[main] Cannot load letslambda configuration. Exiting.")
        exit(1)

    if 'notification_table' not in event:
        logger.error("[main] No DynamoDB table has been provided, so no notification will be issued.")
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
        if 'ssh-hosts' in domain.keys():
            for sshhost in domain['ssh-hosts']:
                if 'host' not in sshhost.keys():
                    logger.error("[main] No SSH url specified. Skipping this SSH host.")
                    continue

                payload = event
                payload['action'] = 'deploy_certificate_ssh'

                payload['domain'] = domain
                payload['domain']['ssh-host'] = sshhost
                payload['domain'].pop('ssh-hosts', None) # remove unecessary data

                payload['conf'] = conf
                payload['conf'].pop('domains', None)

                lambda_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

                lambda_client = boto3.client('lambda')

                logger.debug("[main] Execution payload for domain '{0}'.".format(
                    domain['name']
                ))
                logger.debug(lambda_payload)

                # __DEBUG__

                try:
                    r = lambda_client.invoke(
                        FunctionName=context.function_name,
                        InvocationType='Event',
                        LogType='Tail',
                        Payload=lambda_payload)

                    logger.debug("[main] Execution in progress for domain '{0}'. RequestId: '{1}', StatusCode: '{2}'".format(
                        domain['name'],
                        r['ResponseMetadata']['RequestId'],
                        r['StatusCode']
                    ))
                except ClientError as e:
                    logger.error("[main] Failed to execute lambda function '{0}'. Skipping domain '{1}'.".format(context.function_name, domain['name']))
                    logger.error("[main] Error: {0}".format(e))
                    continue


def issue_certificates_handler(event, context):
    """
    This is the event handler that will perform the DNS challenge and retrieve
    the Let's Encrypt issued certificates
    """

    if 'bucket' not in event:
        logger.critical("[main] No bucket name has been provided. Exiting.")
        exit(1)
    s3_bucket = event['bucket']

    if 'region' not in event.keys() and 'AWS_DEFAULT_REGION' not in os.environ.keys():
        logger.critical("[main] Unable to determine AWS region code. Exiting.")
        exit(1)
    else:
        if 'region' not in event.keys():
            logger.warning("[main] Using local environment to determine AWS region code.")
            s3_region = os.environ['AWS_DEFAULT_REGION']
            logger.warning("[main] Local region set to '{0}'.".format(s3_region))
        else:
            s3_region = event['region']

    if 'defaultkey' not in event:
        logger.warning("[main] No default KMS key provided, defaulting to 'AES256'.")
        kms_key = 'AES256'
    else:
        logger.info("[main] Using {0} as default KMS key.".format(event['defaultkey']))
        kms_key = event['defaultkey']

    if 'configfile' not in event:
        logger.warning("[main] Using 'letslambda.yml' as the default configuration file.")
        letslambda_config = 'letslambda.yml'
    else:
        letslambda_config = event['configfile']

    letslambda_config = clean_file_path(letslambda_config)

    logger.info("[main] Retrieving configuration file '{0}' from bucket '{1}' in region '{2}' ".format(letslambda_config, s3_bucket, s3_region))
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=s3_region))

    conf = load_config(s3_client, s3_bucket, letslambda_config)
    if conf == None:
        logger.critical("[main] Cannot load letslambda configuration. Exiting.")
        exit(1)

    if 'notification_table' not in event:
        logger.error("[main] No DynamoDB table has been provided, so no notification will be issued.")
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

    # falsely attempt to load the LE account key so it is created when
    # child functions are invoked they account key won't have to be generated
    # by multiple child functions at the same time
    conf['s3_client'] = s3_client
    account_key = load_letsencrypt_account_key(conf)
    conf.pop('s3_client', None)

    for domain in conf['domains']:
        payload = event
        payload['action'] = 'issue_certificate'
        payload['domain'] = domain
        payload['conf'] = conf
        payload['conf'].pop('domains', None)

        lambda_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        lambda_client = boto3.client('lambda')

        logger.debug("[main] Execution payload for domain '{0}'.".format(
            domain['name']
        ))
        logger.debug(lambda_payload)

        # __DEBUG__

        try:
            r = lambda_client.invoke(
                FunctionName=context.function_name,
                InvocationType='Event',
                LogType='Tail',
                Payload=lambda_payload)

            logger.debug("[main] Execution in progress for domain '{0}'. RequestId: '{1}', StatusCode: '{2}'".format(
                domain['name'],
                r['ResponseMetadata']['RequestId'],
                r['StatusCode']
            ))
        except ClientError as e:
            logger.error("[main] Failed to execute lambda function '{0}'. Skipping domain '{1}'.".format(context.function_name, domain['name']))
            logger.error("[main] Error: {0}".format(e))
            continue


def issue_certificate_handler(event, context):
    """
    This is the event handler that will perform the DNS challenge and retrieve
    the Let's Encrypt issued certificates

    """

    if 'bucket' not in event:
        logger.critical("[main] No bucket name has been provided. Exiting.")
        exit(1)
    s3_bucket = event['bucket']

    if 'region' not in event.keys() and 'AWS_DEFAULT_REGION' not in os.environ.keys():
        logger.critical("[main] Unable to determine AWS region code. Exiting.")
        exit(1)
    else:
        if 'region' not in event.keys():
            logger.warning("[main] Using local environment to determine AWS region code.")
            s3_region = os.environ['AWS_DEFAULT_REGION']
            logger.warning("[main] Local region set to '{0}'.".format(s3_region))
        else:
            s3_region = event['region']

    if 'defaultkey' not in event:
        logger.warning("[main] No default KMS key provided, defaulting to 'AES256'.")
        kms_key = 'AES256'
    else:
        logger.info("[main] Using {0} as default KMS key.".format(event['defaultkey']))
        kms_key = event['defaultkey']


    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=s3_region))

    try:
        conf = event['conf']
    except KeyError as e:
        logger.warning("[main] No configuration statement was provided, trying to load a default one.")

        if 'configfile' not in event:
            logger.warning("[main] Using 'letslambda.yml' as the default configuration file.")
            letslambda_config = 'letslambda.yml'
        else:
            letslambda_config = event['configfile']

        letslambda_config = clean_file_path(letslambda_config)

        logger.info("[main] Retrieving configuration file '{0}' from bucket '{1}' in region '{2}' ".format(letslambda_config, s3_bucket, s3_region))
        conf = load_config(s3_client, s3_bucket, letslambda_config)

        if conf == None:
            logger.critical("[main] Cannot load letslambda configuration. Exiting.")
            exit(1)

    if 'notification_table' not in event:
        logger.warning("[main] No DynamoDB table has been provided, so no notification will be issued.")
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

    if 'r53_zone' in domain.keys():
        logger.warning("[main] The parameter 'r53_zone' associated to '{0}' has been deprecated in favor of 'dns_zone' and 'dns_provider'. Consider upgrading your configuration.".format(domain['name']))
        domain['dns_zone'] = domain['r53_zone']
        domain['dns_provider'] = 'route53'

    if 'dns_zone' not in domain.keys():
        logger.critical("[main] Missing parameter 'dns_zone' for domain '{0}'. Skipping domain.".format(domain['name']))
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
        logger.critical("[main] An error occurred while answering the DNS challenge. Skipping domain '{0}'.".format(domain['name']))
        exit(1)

    time_spent = 0.0
    while private_key_thread.is_alive() == True:
        private_key_thread.join(0.1)
        time_spent = time_spent + 0.1

        if time_spent % 5 == 0:
            logger.debug("[main] Waiting for the domain private key of '{0}' to be generated and saved in S3. Total time: {1:.2f}s".format(domain['name'], time_spent))

    (chain, certificate, key) = request_certificate(conf, domain, acme_client, authorization_resource)
    if key == False or certificate == False:
        logger.critical("[main] An error occurred while requesting the signed certificate. Skipping domain '{0}'.".format(domain['name']))
        exit(1)

    save_certificates_to_s3(conf, domain, chain, certificate)
    update_dynamodb_item(conf, domain)
    iam_cert = upload_to_iam(conf, domain, chain, certificate, key)
    if iam_cert is False or iam_cert['ResponseMetadata']['HTTPStatusCode'] is not 200:
        logger.critical("[main] An error occurred while saving your server certificate in IAM. Skipping domain '{0}'.".format(domain['name']))
        exit(1)

    # Multi SSH servers mode
    if 'ssh-hosts' in domain.keys():
        for sshhost in domain['ssh-hosts']:
            if 'host' not in sshhost.keys():
                logger.error("[main] No SSH url specified. Skipping this SSH host.")
                continue

            payload = event
            payload['action'] = 'deploy_certificate_ssh'

            payload['domain'] = domain
            payload['domain']['ssh-host'] = sshhost
            payload['domain'].pop('ssh-hosts', None) # remove unecessary data

            payload['conf'] = conf
            payload['conf'].pop('s3_client', None) # remove python object
            payload['conf'].pop('domains', None) # remove unecessary data

            lambda_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

            lambda_client = boto3.client('lambda')

            logger.debug("[main] Execution payload for domain '{0}'.".format(
                domain['name']
            ))
            logger.debug(lambda_payload)

            # __DEBUG__

            try:
                r = lambda_client.invoke(
                    FunctionName=context.function_name,
                    InvocationType='Event',
                    LogType='Tail',
                    Payload=lambda_payload)

                logger.debug("[main] Execution in progress for domain '{0}'. RequestId: '{1}', StatusCode: '{2}'".format(
                    domain['name'],
                    r['ResponseMetadata']['RequestId'],
                    r['StatusCode']
                ))
            except ClientError as e:
                logger.error("[main] Failed to execute lambda function '{0}'. Skipping SSH deployment for domain '{1}'.".format(context.function_name, domain['name']))
                logger.error("[main] Error: {0}".format(e))
                continue


    # single ELB mode (compatibility)
    if 'elb' in domain.keys():
        if 'elb_port' not in domain.keys():
            domain['elb_port'] = 443
            logger.warning("[main] The ELB '{0}' has no port set. Using '{1}' as a default.".format(domain['elb'], domain['elb_port']))

        if 'elb_region' not in domain.keys():
            domain['elb_region'] = conf['region']
            logger.warning("[main] The ELB '{0}' has no region set. Using '{1}' as a default.".format(domain['elb'], domain['elb_region']))

        res = update_elb_server_certificate(conf,
                domain['elb_region'],
                domain['elb'],
                domain['elb_port'],
                iam_cert['ServerCertificateMetadata']['Arn'])
        if res is not True:
            logger.error("[main] An error occurred while attaching your server certificate to your ELB.")

    # Muti ELB mode
    if 'elbs' in domain.keys():
        for elb in domain['elbs']:
            if 'name' not in  elb.keys():
                logger.error("[main] The name of an ELB is missing. You should check {0}. Skipping this ELB.".format(conf['letslambda_config']))
                continue

            if 'port' not in elb.keys():
                elb['port'] = 443
                logger.warning("[main] The ELB '{0}' has no port set. Using '{1}' as a default.".format(elb['name'], elb['port']))

            if 'region' not in elb.keys():
                elb['region'] = conf['region']
                logger.warning("[main] The ELB '{0}' has no region set. Using '{1}' as a default.".format(elb['name'], elb['region']))

            res = update_elb_server_certificate(conf, elb['region'], elb['name'], elb['port'], iam_cert['ServerCertificateMetadata']['Arn'])
            if res is not True:
              logger.error("[main] An error occurred while attaching your server certificate to your ELB.")

    # Multi CF distributions mode
    if 'cfs' in domain.keys():
        for cf in domain['cfs']:
            res = update_cf_server_certificate(conf, domain, cf['id'], iam_cert['ServerCertificateMetadata']['ServerCertificateId'])
            if res is not True:
                logger.error("[main] An error occurred while attaching your server certificate to your CloudFront distribution")


def purge_expired_certificates_handler(event, context):
    """
    Iterate hrough the IAM certificates and attempt to remove the ones that have expired
    """
    if 'bucket' not in event:
        logger.critical("[main] No bucket name has been provided. Exiting.")
        exit(1)
    s3_bucket = event['bucket']

    if 'region' not in event.keys() and 'AWS_DEFAULT_REGION' not in os.environ.keys():
        logger.critical("[main] Unable to determine AWS region code. Exiting.")
        exit(1)
    else:
        if 'region' not in event.keys():
            logger.warning("[main] Using local environment to determine AWS region code.")
            s3_region = os.environ['AWS_DEFAULT_REGION']
            logger.warning("[main] Local region set to '{0}'.".format(s3_region))
        else:
            s3_region = event['region']

    if 'configfile' not in event:
        logger.warning("[main] Using 'letslambda.yml' as the default configuration file.")
        letslambda_config = 'letslambda.yml'
    else:
        letslambda_config = event['configfile']

    letslambda_config = clean_file_path(letslambda_config)

    logger.info("[main] Retrieving configuration file '{0}' from bucket '{1}' in region '{2}' ".format(letslambda_config, s3_bucket, s3_region))
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=s3_region))

    conf = load_config(s3_client, s3_bucket, letslambda_config)
    if conf == None:
        logger.critical("[main] Cannot load letslambda configuration. Exiting.")
        exit(1)

    conf['region'] = os.environ['AWS_DEFAULT_REGION']
    conf['s3_client'] = s3_client
    conf['s3_bucket'] = s3_bucket
    conf['letslambda_config'] = letslambda_config

    server_certificates = list_expired_server_certificates(conf)
    if server_certificates == False:
        logger.critical("[main] Cannot load the list of IAM server certificates. Exiting.")
        exit(1)

    if 'delete_expired_certificates' in conf.keys() and conf['delete_expired_certificates'] == True:
        for server_certificate in server_certificates:
            delete_server_certificate(conf, server_certificate)
    else:
        logger.info("[main] The following IAM server certificates have expired and should be removed")
        for server_certificate in server_certificates:
            logger.warning("[main] IAM Server certificate '{0}' has expired as of '{1}'".format(
                server_certificate['ServerCertificateName'],
                server_certificate['Expiration']))

def deploy_certificate_ssh_handler(event, context):
    """
    Deploy a certificate on its intended locations
    """
    if 'bucket' not in event:
        logger.critical("[main] No bucket name has been provided. Exiting.")
        exit(1)
    s3_bucket = event['bucket']

    if 'region' not in event.keys() and 'AWS_DEFAULT_REGION' not in os.environ.keys():
        logger.critical("[main] Unable to determine AWS region code. Exiting.")
        exit(1)
    else:
        if 'region' not in event.keys():
            logger.warning("[main] Using local environment to determine AWS region code.")
            s3_region = os.environ['AWS_DEFAULT_REGION']
            logger.warning("[main] Local region set to '{0}'.".format(s3_region))
        else:
            s3_region = event['region']

    if 'defaultkey' not in event:
        logger.warning("[main] No default KMS key provided, defaulting to 'AES256'.")
        kms_key = 'AES256'
    else:
        logger.info("[main] Using {0} as default KMS key.".format(event['defaultkey']))
        kms_key = event['defaultkey']


    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=s3_region))

    try:
        conf = event['conf']
    except KeyError as e:
        logger.warning("[main] No configuration statement was provided, trying to load a default one.")

        if 'configfile' not in event:
            logger.warning("[main] Using 'letslambda.yml' as the default configuration file.")
            letslambda_config = 'letslambda.yml'
        else:
            letslambda_config = event['configfile']

        letslambda_config = clean_file_path(letslambda_config)

        logger.info("[main] Retrieving configuration file '{0}' from bucket '{1}' in region '{2}' ".format(letslambda_config, s3_bucket, s3_region))
        conf = load_config(s3_client, s3_bucket, letslambda_config)

        if conf == None:
            logger.critical("[main] Cannot load letslambda configuration. Exiting.")
            exit(1)

    logger.debug(json.dumps(conf, ensure_ascii=False, sort_keys=True))

    conf['s3_client'] = s3_client
    conf['s3_bucket'] = s3_bucket

    if 'base_path' not in conf.keys():
        conf['base_path'] = ''
    else:
        conf['base_path'] = clean_dir_path(conf['base_path'])

    account_key = load_letsencrypt_account_key(conf)

    domain = event['domain']

    if 'ssh-host' not in domain.keys():
        logger.error("[main] No SSH host information found for domain '{0}'. Nothing to do.".format(domain['name']))
        return

    ssh_conf = domain['ssh-host']

    if 'host' not in ssh_conf.keys():
        logger.error("[main] No SSH host url provided found for domain '{0}'. Nothing to do.".format(domain['name']))
        return

    ssh_host = urlparse(ssh_conf['host'])

    if ssh_host.username is None:
        logger.error("[main] No SSH username provided for domain '{0}'. Nothing to do.".format(domain['name']))
        return

    if ssh_host.password is None and 'private_key' not in ssh_conf.keys():
        logger.error("[main] No password or SSH private key has been supplied. You *always* have an authentication method. Refusing to process domain '{0}'.".format(domain['name']))
        return

    ssh = paramiko.SSHClient()
    hostkeys = ssh.get_host_keys()

    try:

        if 'host_public_keys' in ssh_conf.keys():
            for host_key in ssh_conf['host_public_keys']:
                key = host_key['key'].split(' ')
                try:
                    key_type = key[0]
                    key_data = key[1]

                    if key_type == 'ssh-dss':
                        hostkey = paramiko.DSSKey(data=base64.b64decode(key_data))
                    elif key_type == 'ssh-rsa':
                        hostkey = paramiko.RSAKey(data=base64.b64decode(key_data))
                    elif key_type == 'ecdsa-sha2-nistp256':
                        hostkey = paramiko.ECDSAKey(data=base64.b64decode(key_data))
                    elif key_type == 'ecdsa-sha2-nistp384':
                        hostkey = paramiko.ECDSAKey(data=base64.b64decode(key_data))
                    elif key_type == 'ecdsa-sha2-nistp521':
                        hostkey = paramiko.ECDSAKey(data=base64.b64decode(key_data))
                    else:
                        continue

                    hostkeys.add(hostname=ssh_host.hostname, keytype=key_type, key=hostkey)

                except KeyError as e:
                    logger.warning("[main] Failed to load SSH key for domain '{0}'".format(domain['name']))
                    continue

        if 'ignore_host_public_key' in ssh_conf.keys():
            if ssh_conf['ignore_host_public_key'] == True:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                logger.info("[main] SSH connection will be automatically accepted even if public host key doesn't match.")
            else:
                ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
                logger.info("[main] SSH connection will be rejected if host public key doesn't match.")

        pkey = None
        if 'private_key' in ssh_conf.keys():
            priv_key_info = urlparse(ssh_conf['private_key'])

            c = {
                's3_client': s3_client,
                's3_bucket': priv_key_info.hostname
            }
            ssh_key = load_from_s3(c, clean_file_path(priv_key_info.path))
            if ssh_key == None:
                logger.error("[main] Failed to load SSH private key '{0}'.".format(priv_key_info.path))
            else:
                # current ssh private key headers:
                # -----BEGIN DSA PRIVATE KEY----- (DSA/DSS) - supported
                # -----BEGIN EC PRIVATE KEY----- (ECDSA) - supported
                # -----BEGIN OPENSSH PRIVATE KEY----- (ED25519) - not supported
                # -----BEGIN RSA PRIVATE KEY----- (RSA) - supported

                key_type = ssh_key.splitlines()[0].split(' ')[1]
                logger.debug("[main] SSH Private key type: '{0}'".format(key_type))

                if key_type == 'RSA':
                    pkey = paramiko.RSAKey.from_private_key(StringIO.StringIO(ssh_key))
                elif key_type == 'EC':
                    pkey = paramiko.ECDSAKey.from_private_key(StringIO.StringIO(ssh_key))
                elif key_type == 'DSA':
                    pkey = paramiko.DSAKey.from_private_key(StringIO.StringIO(ssh_key))
                else:
                    logger.error("[main] The SSH private key format '{0}' for domain '{1}' is not supported.".format(ssh_key.splitlines()[0].split(' ')[1], domain['name']))
                    if ssh_host.password is None:
                        logger.error("[main] No password has been supplied. Not process domain '{0}'.".format(domain['name']))
                        return
                    else:
                        logger.error("[main] Authentication will attempt to fallback on password based authentication only.".format(domain['name']))



        connect_args = {
            'hostname': ssh_host.hostname,
            'username': ssh_host.username
        }
        if ssh_host.port is not None:
            connect_args['port'] = ssh_host.port

        if ssh_host.password is not None:
            connect_args['password'] = ssh_host.password

        if pkey is not None:
            connect_args['pkey'] = pkey

        ssh.connect(**connect_args)
        t = ssh.get_transport()
        sftp = paramiko.SFTPClient.from_transport(t)

        # ==== We are connected to the remot host ====


        path_split = ssh_host.path.split('/')
        x = 2
        fs_path = ''
        while (x < len(path_split)):
            fs_path = ''
            y = 1
            while (y < x):
                fs_path = fs_path + '/' + path_split[y]
                y = y + 1
            x = x + 1

            try:
                # folders may already exists, but we still attempt to recreate
                # rather than reading each folder.
                sftp.mkdir(fs_path)
            except IOError as e:
                logger.warning("[main] Failed to create folder '{0}' on host '{1}' for domain '{2}".format(fs_path, ssh_host.hostname, domain['name']))
                logger.warning("[main] Error: {0}".format(e))

        try:
            exts = [ 'cert.pem', 'chain.pem', 'key.pem' ]
            for ext in [ 'cert.pem', 'chain.pem', 'key.pem' ]:
                fs_file = '/{0}'.format(clean_file_path('{0}/{1}.{2}'.format(fs_path, domain['name'], ext)))
                s3_file = clean_file_path('/{0}/{1}.{2}'.format(domain['base_path'], domain['name'], ext))

                s3_content = load_from_s3(conf, s3_file)

                logger.info("[main] Installing 's3://{0}/{1}' to 'ssh://{2}@{3}{4}'.".format(
                    conf['s3_bucket'],
                    s3_file,
                    ssh_host.username,
                    ssh_host.hostname,
                    fs_file))

                f = sftp.open(fs_file, 'w')
                f.write(s3_content)
                f.close()

                if 'file_mode' in ssh_conf.keys():
                    try:
                        sftp.chmod(fs_file, ssh_conf['file_mode'])
                    except IOError as e:
                        logger.error("[main] Failed to set permissions '{0}' on '{1}'.".format(
                            ssh_conf['file_mode'],
                            fs_file))
                        logger.warning("[main] Error: {0}".format(e))

                if 'file_uid' in ssh_conf.keys() or 'file_gid' in ssh_conf.keys():
                    fs_file_stats = sftp.stat(fs_file)
                    file_uid = fs_file_stats.st_uid
                    file_gid = fs_file_stats.st_gid

                    if 'file_uid' in ssh_conf.keys():
                        file_uid = int(ssh_conf['file_uid'])

                    if 'file_gid' in ssh_conf.keys():
                        file_gid = int(ssh_conf['file_gid'])

                    try:
                        sftp.chown(fs_file, file_uid, file_gid)
                    except IOError as e:
                        logger.error("[main] Failed to set ownership '{0}:{1}' on '{2}'.".format(
                            file_uid,
                            file_gid,
                            fs_file))
                        logger.warning("[main] Error: {0}".format(e))

        except IOError as e:
            logger.warning("[main] Failed to change working folder '{0}' on host '{1}' for domain '{2}".format(fs_path, ssh_host.hostname, domain['name']))
            logger.warning("[main] Error: {0}".format(e))

        sftp.close()
        ssh.close()

    except (paramiko.SSHException, socket.error) as e:
        logger.error("[main] Failed to deploy certificate over SSH on host '{0}' for domain '{1}'.".format(ssh_host.hostname, domain['name']))
        logger.error("[main] Exception: {0}".format(e))
        return


def lambda_handler(event, context):
    """
    This is the Lambda function handler from which all executions are routed.
    The appropriate routing is determine by event['action']
    """
    logger.error("[main] Starting execution of Let's Lamda")
    logger.error(json.dumps(event, ensure_ascii=False, sort_keys=True))
    routing = {
        'purge': purge_expired_certificates_handler, # removes expired certs. this is declared in the cloudformation template
        'issue_certificates': issue_certificates_handler, # issue multiple certificates. this is the routing path
        'issue_certificate': issue_certificate_handler, # issue a single certificate. this is usually executed via 'issue_certificates' routing path
        'deploy_certificates': deploy_certificates_handler, # deploy multiple certificates without issuing them
        'deploy_certificate_ssh': deploy_certificate_ssh_handler # deploy any certificate onto its relevant location(s)
    }

    if 'action' in event.keys() and event['action'] in routing.keys():
        routing[event['action']](event, context)
    else:
        issue_certificates_handler(event, context)
