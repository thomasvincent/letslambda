# LetsLambda #

A python script that gets to renew your SSL certificates from AWS Lambda via DNS challenge using [Let's Encrypt](https://letsencrypt.org/) services. It stores your keys and certificates in a S3 bucket. If the keys don't exists, it generates them and re-uses them later (useful for [public key pinning](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning)).

All in all, the script talks to [Let's Encrypt](https://letsencrypt.org/) and Amazon [Route53](https://aws.amazon.com/route53/), [OVH](https://www.ovh.co.uk/domains/dns_management_service.xml), (for the DNS challenge), Amazon [S3](https://aws.amazon.com/s3/) and Amazon [IAM](https://aws.amazon.com/iam/) (to store your certificates) and Amazon [Elastic Load Balancing](https://aws.amazon.com/elasticloadbalancing/). And optionally, Amazon [KMS](https://aws.amazon.com/kms/) can be used to encrypt your data in your S3 bucket.

## Supported Services ##
Let's Lambda is being built in a modular way so it can easily be extended through plugins.

### DNS Providers ###

 - Amazon [Route53](https://aws.amazon.com/route53/)
 - [OVH](https://www.ovh.co.uk/domains/dns_management_service.xml)

### Storage Providers ###

 - Amazon [Simple Storage Service](http://docs.aws.amazon.com/AmazonS3/latest/dev/Welcome.html) (S3)
 - AWS [IAM Server Certificates](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html)
 - Amazon [CloudFront](http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Introduction.html)
 - AWS [Elastic Load Balancer](http://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/what-is-load-balancing.html) (ELB)
 - [Secure Shell](https://en.wikipedia.org/wiki/Secure_Shell) (SSH)

## Configuration ##
The configuration file is based on YAML. It should be easy to understand by reviewing the provided configuration. Nonetheless, here is a short explanation of each configuration directive
```yaml
directory: https://acme-v01.api.letsencrypt.org/directory
base_path: letsencrypt/
delete_expired_certificates: true
renew_before_expiry: 30 days
keep_until_expired: true
info:
  - mailto:myemail@example.com
ssh-hosts:
  - host: ssh://hostname[:port]
    ignore_host_public_key: false
    host_public_keys:
     - key: ssh-dss AAAAB3NzaC1....
     - key: ssh-rsa AAAAB3NzaC1....
     - key: ecdsa-sha2-nistp256 AAAAE2VjZ....
     - key: ssh-ed25519 AAAAC3NzaC1...
  - host: ssh://...
    ignore_host_public_key: false
    host_public_keys:
     - key: ...
domains:
  - name: www.example.com
    dns_zone: example.com
    dns_provider: route53
    renew_before_expiry: 10 days
    countryName: FR
    reuse_key: true
    keep_until_expired: true
    key_size: 2048
    base_path: letsencrypt/certificates/example.com/
    elbs:
      - name: elb_name
        region: ap-southeast-2
        port: 443
    ssh-targets:
      - host: ssh://username[:password]@hostname[:port]/local/path/
        private_key: s3://bucketname/path/to/private/ssh/key
        file_uid: 1001
        file_gid: 33
        file_mode: 0640
      - host: ssh://...
    cfs:
      - id: XXXXXXXXXXXXXX
      - id: YYYYYYYYYYYYYY
  - name: api.anotherexample.com
    dns_zone: anotherexample.com
    dns_provider: ovh
    dns_auth: '[{"endpoint": "ovh-eu","application_key": "xxxxxxxxxxxxx","application_secret": "xxxxxxxxxxxxxxxxxxxxxxxx","consumer_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}]'
    countryName: AU
    reuse_key: true
    base_path: letsencrypt/certificates/
    elbs:
      - name: elb_name_2
        region: ap-southeast-2
        port: 443
      - name: elb_name_3
        region: ap-southeast-1
        port: 443
    ssh-targets:
      - host: ssh://username:password@hostname:port/path/
        private_key: s3://bucketname/path/filename
        file_uid: 1001
        file_gid: 33
        file_mode: 0640
    cfs:
      - id: XXXXXXXXXXXXXX
      - id: YYYYYYYYYYYYYY
  - name: old.example.com
    dns_zone: example.com
    dns_provider: route53
    keep_until_expired: false
    countryName: FR
    reuse_key: false
    key_size: 4096
    elb: old_elb_name
    elb_port: 8443
    elb_region: us-east-1
```

### Configuring Let's encrypt ###
`directory`: The Let's Encrypt directory endpoint to use to request the certificate issuance. This is useful when you need to switch between staging and production. Possible values are:

 - `https://acme-v01.api.letsencrypt.org/directory` for production
 - `https://acme-staging.api.letsencrypt.org/directory` for development and tests

`base_path`: This defines the location in your S3 bucket where the Let's encrypt account key stored. It also serves at the default location to store per domain private keys and issued certificates. If not specified, the root (`/`) of your S3 bucket will be used instead.

`delete_expired_cert`: This defines whether or not expired server certificates stored in IAM should be removed. By default, an AWS account can store up to 20 server certificates making this resource quite limited. And since a server certificate can only be added or removed (not updated), the renewal process may easily pass the maximum allows limit. If unspecified the default is `false` (do not remove). Server certificates stored in the S3 bucket aren't affected regardless of this value. If the server certificate is linked to an AWS service (ELB or CloudFront), the deletion will fail.

`renew_before_expiry`: This defines the interval between a certificate expiration and the date we actually renew it. A value of `30 days` would mean that a new certificate is generated if it expires in less than 30 days.

`keep_until_expired`: This defines if we keep certificates around until they enter the `renew_before_expiry` window or actually expire.

`info`: The information to be used when the script is registering your account for the first time. You should provide a valid email or the registration may fail.

    info:
        - mailto:myemail@example.com

### Configuring your domains ###
Letslambda allows you to declare multiple host names that you wish to get a certificate for.

Each is declared under the `domains` list.

Here is the details for each domain.

`domains`: a list of domain information.

 - `- name`: The host name for which you want your certificate to be issued for.
 - `renew_before_expiry`: Overrides the root value for the domain. See above.
 - `keep_until_expired`: Overrides the root value for the domain. See above.
 - `dns_zone`: the DNS hosted zone name which contains the DNS entry for `name`.
 - `dns_provider`: The service provider hosting your DNS zone. It can either be `ovh` or `route53`.
 - `dns_auth` : The service provider credentials for your account. The JSON encoded value is passed directly to the provider. Currently only `ovh` is supported.
    - _OVH_ : See https://github.com/ovh/python-ovh
 - `countryName`: This parameter is used for the `countryName` in the [Certificate Signing Request](https://en.wikipedia.org/wiki/Certificate_signing_request) (CSR). It's a 2 letters representation of the country name. It follows the [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) standard.
 - `kmsKeyArn`: Your KMS key arn to encrypt the Let's Encrypt account key and your certificate private keys. You may also use `AES256` for AWS managed at rest encryption. Default is `AES256`.
 - `reuse_key`: The Lambda function will try to reuse the same private key to generate the new CSR. This is useful if you ever want to use Public Key Pinning (Mobile App development) and yet want to renew your certificates every X months
 - `key_size`: Determine the private key size (in bits). Common values are `2048` or `4096`. Note that Amazon CloudFront [doesn't support certificates for keys longer than 2048](http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/SecureConnections.html#CNAMEsAndHTTPS). If omitted, the default value is `2048` since it's secure and it maximises compatibility with the AWS services.
 - `base_path`: This defines the location in your S3 bucket where the domain private keys and issued certificate is saved. If not specified, it defaults to the global `base_path` (see above).

### Configuring your ELBs ###
You have 2 ways to get your server certificates deployed into one or more Elastic Load Balancer (ELB). However, this section is optional is you don't have any ELB.

The initial release of Letslambda used to support only one ELB. This is done as follows:
 - `elb`: Name of your Elastic Load Balancer.
 - `elb_region`: the region is which your ELB has been deployed in. Default is the Lambda local region.
 - `elb_port`: ELB listening port. If left unspecified, the default is `443` (HTTPS).

Only **one** ELB is supported when configured this way.

The newer and preferred way to declare the deployment of your server certificate into your ELB is done as follows:
 - `elbs` which is the start of your ELB list.

 And below, per ELB specific settings:
 - `- name` is for the name of your ELB. This parameter should come first in the ELB list.
 - `region` the AWS region code in which your ELB is deployed into. If missing, this defaults to the AWS region in which Letslambda runs.
 - `port` which represents the ELB listener port. This port must already be configure ahead. If omitted, the default value is `443` (HTTPS).

### Configuring your CloudFront distributions ###
Just like Elastic Load Balancers, LetsLambda supports one or more CloudFront distributions as part of the configuration file.
 - `cfs` which is the start of your CloudFront list. You may ommit this parameter if you don't have any CloudFront distribution.

And for each CloudFront distribution:
 - `- id` which represents your CloudFront distribution ID

Unlike other AWS services, CloudFront requires some time to be fully deployed. Usually about 30 minutes but this may vary. LetsLambda will __not__ updated your distribution configuration if it's not in a deployed state (where pending configuration changes are being deployed).

### Deploying to a SSH host ###
It's possible to deploy the cetificates and the private key to a remote ssh server via SFTP. However, careful considerations should be given due to the security implications of copying a private key cwto a remote server.

The configuration is done in two parts:
 - A global section named `ssh-hosts` where remote servers are declared. For each host, associated host public keys are defined
 - Per `domain`, one or more ssh target is defined.

It's important to note that host name and ports must match to relate each element together during the deployment phase.

#### Declaring SSH hosts ####
For a SSH target (see below) to be allowed, it has to be declared first in in the global `ssh-hosts` sections.

Here is the details for each host.

`ssh-hosts`: a list of ssh host information.

 - `- host`: The SSH host details. The scheme `ssh://` is mandatory. `:port` is optional and defaults to `22` (ssh default communication port).
 - `ignore_host_public_key`: If `true`, when connecting to the ssh server, do not perform host public key verification. This is not recommended.
 - `host_public_keys`: A list of valid public ssh host keys.
 -- `key`: one ssh public  key as usually found in `/etc/ssh/ssh_host_*.pub`

#### Declaring SSH targets ####
Once you have declared a ssh host (see above), you can use it as a deployment target in one or more domain.

`ssh-targets`: a list of known ssh servers to deploy the related certificate onto.

 - `- host`: A valid url whre you wish to deploy your certificate to. The url must start with `ssh://`. This server must be declared globally in `ssh-hosts` in order to be used.
   * `username`: SSH user name used during the authentication.
   * `password`: The corresponding password for password based authentication. This parameter is optional when using `private_key` authentication.
   * `hostname`: A valid fully qualified domain name, or a valid IP address to connect to.
   * `port`: If the ssh server doesn't listen on port 22 (default), then set the correct value here. This should be matching the declaration in `ssh-hosts`.
   * `path`: The remote directory where the certificate should be deployed. (see below)
 - `private_key`: A valid S3 url to download the ssh private key used during the authentication. Supported types are `RSA`, `DSA`, `ECDSA`.
 - `file_uid`: Numerical user Id (uid) value to change the files ownership to.
 - `file_gid`: Numerical group Id (gid) value to change the files ownership to.`
 - `file_mode`: Octal value to change the files permissions to.

Note: If the remote path doesn't exist on the destination file system, Let's Lambda will attempt to create it.

## Installation ##

This project relies on third party projects that requires some files to be compiled. Since AWS Lambda runs on Amazon Linux 64 bit ([ref](http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html)), it's important that you have such instance running to prepare your Lambda function and not a custom debian/ubuntu server as you may find some libraries incompatibilities).

    $> yum install libcffi-devel libffi-devel libyaml-devel gcc openssl-devel git
    $> virtualenv .env
    $> source .env/bin/activate
    $> pip install -r requirements.txt
    $> ./make_package.sh

Once this is done, all you have to do is to upload your lambda function to a S3 bucket.
    $> aws s3 cp letslambda.zip s3://bucket/

Alternatively, you may use the Amazon Management Console to upload your package from the comfort of your web browser.

And finally, let Amazon CloudFormation do the heavy job of deploying the LetsLambda function.

    $> aws cloudformation create-stack --stack-name letslambda --template-body  file://letslambda.json \
           --parameters ParameterKey=FnBucket,ParameterValue=bucket_name \
           ParameterKey=FnPath,ParameterValue=some/path/to/letslambda.zip \
           ParameterKey=Bucket,ParameterValue=bucket_name \
           ParameterKey=ConfigFile,ParameterValue=some/path/to/letslambda.yml \
           ParameterKey=Region,ParameterValue=eu-west-1 \
           ParameterKey=KmsEncryptionKeyArn,ParameterValue=arn:aws:kms:eu-central-1:123456789012:key/30df8784-b708-4bea-8506-b12cc04335a4 \
           ParameterKey=TableName,ParameterValue=LetsLambdaNotifications \
           --capabilities CAPABILITY_IAM

As a possible alternative, you may use the CloudFormation Management Console to deploy your Lambda function. Though, you should ensure that you deploy the IAM resources included in the template.

The above parameters are:
 - `FnBucket`: S3 Bucket name where the LetsLambda is stored (not arn). This bucket must be located in your CloudFormation/Lambda region.
 - `FnPath': Path and file name to the LetsLambda package. No heading `/`
 - `Bucket`: S3 Bucket name (not arn) where the YAML configuration is located. Also used as the default location to store your certificates and priavete keys.
 - `Region`: Region short code name where the S3 bucket is located (ie: eu-west-1)
 - `ConfigFile`: Path to the YAML configuration file within the specified S3 bucket. No heading `/`
 - `KmsEncryptionKeyArn`: Default KMS Encryption Key (arn) used to securely store your SSL private keys. Use 'AES256' for S3 automatic encryption.
 - `TableName`: DynamoDB table name where certificate issuance is stored. This helps consumers to know when a new certificate has been issued.

## Role and Managed Policies ##
As part of the deployment process, the CloudFormation template will create 4 IAM managed policies and one Lambda execution role. Each managed policy has been crafted so you can access your resources securely. The Lambda execution role defines the privilege level for the Lambda function.

 - `LetsLambdaManagedPolicy` This policy is core to the Lambda function and how it interacts with CloudWatch logs, Amazon IAM, Amazon Elastic Load Balancing and Route53.
 - `LetsLambdaKmsKeyManagedPolicy` Through this policy, the Lambda function can encrypt content when storing information into S3. Only the Lambda function should be using this role.
 - `LetsLambdaKmsKeyDecryptManagedPolicy` This policy should be used by both the Lambda function and selected EC2 instances (consumers) since it provides the mean to decrypt content stored in S3.
 - `LetsLambdaS3WriteManagedPolicy`Allow the Lambda function to write into the user defined S3 bucket.
 - `LetsLambdaS3ReadManagedPolicy` This policy is used to access any objects in the S3 bucket. Encrypted objects such as private keys will remain inaccessible until `LetsLambdaKmsKeyManagedPolicy`is used in conjunction with this policy.

### Accessing your Private keys ###
Having access to private keys is sensitive by definition. You should ensure that your private keys do not leak outside in any way.

To retrieve more easily your private keys from an EC2 instance, you should create/update an EC2 role and add both `LetsLambdaKmsKeyManagedPolicy` and `LetsLambdaS3ReadManagedPolicy`. This will allow your the EC2 instances running under the corresponding role/managed policies to access the private keys without any hard coded credentials.

# External DNS providers #
Let's Lambda support multiple DNS providers through python modules. You should be looking at `route53_dns.py` and create an entry point named `???_create_dns_challenge` where `???` is the name of your DNS provider has presented in the YAML configuration.

## Credits ##
 - [Sébastien Requiem](https://github.com/kiddouk/)
 - [Aurélien Requiem](https://github.com/aureq/)

### Contributors ###
 - [Peter Mounce](https://github.com/petemounce)
