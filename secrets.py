import boto3
import base64
import os
import yaml
import json 
from botocore.exceptions import ClientError

session = boto3.session.Session()

# Create a Secrets Manager client
client = session.client(
    service_name='secretsmanager'
)


def __accountIds():
    if os.path.isfile('config.yaml') is True:
        with open('config.yaml') as f:
            config = yaml.safe_load(f.read())
            AccountIds = config['SharedAccounts']
            return AccountIds
    elif os.environ['SHARED_ACCOUNTIDS'] is None:
        print('No config or environment variables present, exiting')
        exit()
    else:
        AccountIds = os.environ['SHARED_ACCOUNTIDS']
        return AccountIds


def __environmentTags():
    if os.path.isfile('config.yaml') is True:
        with open('config.yaml') as f:
            config = yaml.safe_load(f.read())
            configTags = config['Pipeline']
            AccountIds = config['SharedAccounts']
        tags = [configTags['Portfolio'], configTags['App'], configTags['Branch']]
        return tags, AccountIds
    elif os.environ['PIPELINE_PORTFOLIO'] is None:
        print('No config or environment variables present, exiting')
        exit()
    else:
        tags = [os.environ['PIPELINE_PORTFOLIO'], os.environ['PIPELINE_APP'], os.environ['PIPELINE_BRANCH_SHORT_NAME']]
        return tags


def __errorHandler(e):
    if e.response['Error']['Code'] == 'EncryptionFailureException':
        print('Failed to encrypt or decrypt the secret, are you sure you have sufficent KMS privileges?')
        raise e
    elif e.response['Error']['Code'] == 'InternalServiceErrorException':
        print('500 Error for the internal service - see raised error below')
        raise e
    elif e.response['Error']['Code'] == 'InvalidParameterException':
        print('You have used a invalid paramater and thus, the service has thrown an exception - see raised error below')
        raise e
    elif e.response['Error']['Code'] == 'InvalidRequestException':
        print('You have asked the service to do something and it does not understand the request, marking it invalid - see error raised below')
        raise e
    elif e.response['Error']['Code'] == 'ResourceNotFoundException':
        print('You have asked the secret service for a secret that does not exist or that this role does not have permission to access')
        raise e


def __sharedSecretPolicy(name, accounts=[]):
    accountArns = []
    for account in accounts:
        accountArns.append("arn:aws:iam::{id}:root".format(id=account))
        resourcePolicyJson = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": accountArns},
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                    "Condition": {"ForAnyValue:StringEquals": {"secretsmanager:VersionStage": "AWSCURRENT"}}
                }
            ]
        }
    response = client.put_resource_policy(
        SecretId=name,
        ResourcePolicy=resourcePolicyJson
    )
    return response['ARN']


def __generatePassword():
    response = client.get_random_password(
        PasswordLength=64,
        ExcludeCharacters='|iIlL<:`\'"',
        ExcludeNumbers=False,
        ExcludePunctuation=False,
        ExcludeUppercase=False,
        ExcludeLowercase=False,
        IncludeSpace=False,
        RequireEachIncludedType=False
    )
    return response['RandomPassword']


def __checkSecret(Name):
    try:
        describe_secret = client.describe_secret(
            SecretId=Name
        )
    except ClientError as e:
            __errorHandler(e)
    else:
        print(describe_secret['Name'])
        return True


def update(Name, Value=None, Description='', kmsKeyId=''):
    if Value is None:
        Value = __generatePassword()
        try:
            update_secret_response = client.update_secret(
                SecretId=Name,
                SecretString=Value,
                Description=Description,
                KmsKeyId=kmsKeyId
            )
        except ClientError as e:
            __errorHandler(e)
        else:
            secret = update_secret_response['Name']
            return secret
    else:
        try:
            update_secret_response = client.update_secret(
                SecretId=Name,
                SecretString=Value,
                KmsKeyId=kmsKeyId
            )
        except ClientError as e:
            __errorHandler(e)
        else:
            secret = update_secret_response['Name']


def get(Name):
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=Name
        )
    except ClientError as e:
            __errorHandler(e)
            return False
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            print(secret)
            return secret
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            print(decoded_binary_secret)
            return decoded_binary_secret


def put(Name, Description='', Value='', kmsKeyId='', shared=False):
        try:
            tags = __environmentTags()
            secretName = "{Portfolio}_{App}_{Branch}_{Name}".format(Portfolio=tags[0],
                                                                    App=tags[1],
                                                                    Branch=tags[2],
                                                                    Name=Name)
            put_secret_value_response = client.create_secret(
                Name=secretName,
                Description=Description,
                KmsKeyId=kmsKeyId,
                SecretString=Value,
                Tags=[
                    {
                        'Key': 'Portfolio',
                        'Value': tags[0]
                    },
                    {
                        'Key': 'App',
                        'Value': tags[1]
                    },
                    {
                        'Key': 'Branch',
                        'Value': tags[2]
                    }
                ]
            )
        except ClientError as e:
            __errorHandler(e)
        else:
            secret = put_secret_value_response['Name']
            if shared is True:
                __sharedSecretPolicy(name=secret, accounts=__accountIds())
            return secret


def delete(Name):
    try:
        delete_secret_response = client.delete_secret(
            SecretId=Name,
            RecoveryWindowInDays=120,
            ForceDeleteWithoutRecovery=False
        )
    except ClientError as e:
        __errorHandler(e)
    else:
        secret = delete_secret_response['SecretId']
        return secret
