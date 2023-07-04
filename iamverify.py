import datetime
import getpass
import boto3
import botocore


class FailureLevel:
    ERROR = "error"
    WARNING = "warning"


class Result:
    def __init__(self, level, message, rule_id):
        self.level = level
        self.message = message
        self.rule_id = rule_id


class Message:
    def __init__(self, text):
        self.text = text


def anonymize_access_key(access_key):
    anonymized_key = access_key[:4] + '*' * (len(access_key) - 4)
    return anonymized_key


def check_root_account_mfa_enabled(iam_client):
    try:
        response = iam_client.get_account_summary()
        account_summary = response['SummaryMap']

        if not account_summary.get('AccountMFAEnabled'):
            return Result(
                level=FailureLevel.ERROR,
                message=Message(text='Enable MFA for the root account.'),
                rule_id='CIS AWS Foundations Benchmark - 1.1'
            )
    except Exception as e:
        raise Exception("Error while checking root account MFA status") from e


def check_iam_password_policy(iam_client):
    try:
        try:
            response = iam_client.get_account_password_policy()
            password_policy = response.get('PasswordPolicy')

            if not password_policy:
                return Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='IAM password policy not found.'),
                    rule_id='CIS AWS Foundations Benchmark - 1.3'
                )

            if not password_policy.get('MinimumPasswordLength') or password_policy.get(
                    'MinimumPasswordLength') < 14:
                return Result(
                    level=FailureLevel.ERROR,
                    message=Message(
                        text='Ensure the IAM password policy requires a minimum length of 14 or more characters.'),
                    rule_id='CIS AWS Foundations Benchmark - 1.3'
                )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='IAM password policy not found.'),
                    rule_id='CIS AWS Foundations Benchmark - 1.3'
                )
            else:
                raise Exception("Error while checking IAM password policy") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy") from e


def check_user_group_policies(iam_client):
    try:
        response = iam_client.list_users()
        users = response['Users']

        results = []
        for user in users:
            user_name = user['UserName']
            response = iam_client.list_user_policies(UserName=user_name)
            user_policies = response.get('PolicyNames')

            if user_policies:
                results.append(
                    Result(
                        level=FailureLevel.ERROR,
                        message=Message(text='Ensure no users have inline policies.'),
                        rule_id='CIS AWS Foundations Benchmark - 1.4'
                    )
                )
        return results
    except Exception as e:
        raise Exception("Error while checking user and group policies in IAM") from e


def check_access_keys_rotation(iam_client):
    try:
        response = iam_client.list_users()
        users = response['Users']

        results = []
        for user in users:
            user_name = user['UserName']
            response = iam_client.list_access_keys(UserName=user_name)
            access_keys = response.get('AccessKeyMetadata')

            if access_keys:
                for access_key in access_keys:
                    access_key_id = access_key['AccessKeyId']
                    access_key_last_rotated = access_key.get('CreateDate')

                    if access_key_last_rotated:
                        create_date = access_key_last_rotated.date()
                        days_since_rotation = (datetime.date.today() - create_date).days

                        if days_since_rotation > 90:
                            anonymized_access_key = anonymize_access_key(access_key_id)
                            results.append(
                                Result(
                                    level=FailureLevel.ERROR,
                                    message=Message(
                                        text=f'Rotate access key {anonymized_access_key} every 90 days or less.'),
                                    rule_id='CIS AWS Foundations Benchmark - 1.23'
                                )
                            )
        return results
    except Exception as e:
        raise Exception("Error while checking IAM access key rotation") from e


def check_unused_credentials(iam_client):
    try:
        response = iam_client.list_access_keys()
        access_keys = response.get('AccessKeyMetadata')

        if access_keys:
            results = []
            for access_key in access_keys:
                access_key_id = access_key['AccessKeyId']
                access_key_last_used = access_key.get('LastUsedDate')

                if not access_key_last_used:
                    anonymized_access_key = anonymize_access_key(access_key_id)
                    results.append(
                        Result(
                            level=FailureLevel.ERROR,
                            message=Message(text=f'Remove unused access key {anonymized_access_key}.'),
                            rule_id='CIS AWS Foundations Benchmark - 1.24'
                        )
                    )
            return results
    except Exception as e:
        raise Exception("Error while checking unused credentials in IAM") from e


def check_public_access_block(session):
    try:
        s3_client = session.client('s3')
        try:
            response = s3_client.list_buckets()
            buckets = response['Buckets']

            results = []
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    response = s3_client.get_public_access_block(Bucket=bucket_name)

                    if not response['PublicAccessBlockConfiguration']['BlockPublicAcls'] or not \
                            response['PublicAccessBlockConfiguration']['BlockPublicPolicy'] or not \
                            response['PublicAccessBlockConfiguration']['IgnorePublicAcls'] or not \
                            response['PublicAccessBlockConfiguration']['RestrictPublicBuckets']:
                        results.append(
                            Result(
                                level=FailureLevel.ERROR,
                                message=Message(
                                    text=f'Ensure public access is blocked for S3 bucket {bucket_name}.'),
                                rule_id='CIS AWS Foundations Benchmark - 3.1'
                            )
                        )
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        results.append(
                            Result(
                                level=FailureLevel.ERROR,
                                message=Message(
                                    text=f'Ensure public access is blocked for S3 bucket {bucket_name}.'),
                                rule_id='CIS AWS Foundations Benchmark - 3.1'
                            )
                        )
                    else:
                        raise Exception(f"Error while checking public access block for S3 bucket {bucket_name}") from e
                except Exception as e:
                    raise Exception(f"Error while checking public access block for S3 bucket {bucket_name}") from e
            return results
        except botocore.exceptions.ClientError as e:
            raise Exception("Error while listing S3 buckets") from e
        except Exception as e:
            raise Exception("Error while listing S3 buckets") from e
    except Exception as e:
        raise Exception("Error while creating S3 client") from e


def check_iam_policy_version(iam_client):
    try:
        response = iam_client.list_policies()
        policies = response['Policies']

        results = []
        for policy in policies:
            policy_arn = policy['Arn']
            response = iam_client.list_policy_versions(PolicyArn=policy_arn)
            policy_versions = response.get('Versions')

            if policy_versions:
                if len(policy_versions) > 1:
                    results.append(
                        Result(
                            level=FailureLevel.ERROR,
                            message=Message(text=f'Delete old versions of IAM policy {policy_arn}.'),
                            rule_id='CIS AWS Foundations Benchmark - IAM.1'
                        )
                    )
        return results
    except Exception as e:
        raise Exception("Error while checking IAM policy versions") from e


def check_iam_password_policy_expiration(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and password_policy.get('ExpirePasswords'):
            results = []
            results.append(
                Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='Disable password expiration for IAM users.'),
                    rule_id='CIS AWS Foundations Benchmark - IAM.2'
                )
            )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy expiration") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy expiration") from e


def check_iam_password_policy_reuse(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and password_policy.get('PasswordReusePrevention') > 0:
            results = []
            results.append(
                Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='Disable password reuse for IAM users.'),
                    rule_id='CIS AWS Foundations Benchmark - IAM.3'
                )
            )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy reuse") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy reuse") from e


def check_iam_password_policy_requirements(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy:
            password_policy_requirements = {
                'RequireUppercaseCharacters': 'uppercase letters (A-Z)',
                'RequireLowercaseCharacters': 'lowercase letters (a-z)',
                'RequireNumbers': 'numbers (0-9)',
                'RequireSymbols': 'non-alphanumeric characters'
            }

            results = []
            for requirement, description in password_policy_requirements.items():
                if password_policy.get(requirement):
                    results.append(
                        Result(
                            level=FailureLevel.ERROR,
                            message=Message(text=f'Disable requirement for {description} in IAM password policy.'),
                            rule_id='CIS AWS Foundations Benchmark - IAM.4'
                        )
                    )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy requirements") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy requirements") from e


def check_iam_password_policy_allow_users_change(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and not password_policy.get('AllowUsersToChangePassword'):
            results = []
            results.append(
                Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='Allow IAM users to change their own password.'),
                    rule_id='CIS AWS Foundations Benchmark - IAM.5'
                )
            )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy allow users change") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy allow users change") from e


def check_iam_password_policy_expire_root_user(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and not password_policy.get('ExpireRootPassword'):
            results = []
            results.append(
                Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='Enable password expiration for root account.'),
                    rule_id='CIS AWS Foundations Benchmark - IAM.6'
                )
            )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy expire root user") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy expire root user") from e


def check_iam_password_policy_hard_expiry(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and password_policy.get('MaxPasswordAge') and password_policy.get('HardExpiry'):
            results = []
            results.append(
                Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='Disable password hard expiry for IAM users.'),
                    rule_id='CIS AWS Foundations Benchmark - IAM.7'
                )
            )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy hard expiry") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy hard expiry") from e


def check_iam_password_policy_warning_days(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and password_policy.get('PasswordReusePrevention') > 0:
            if password_policy.get('PasswordReusePrevention') > 24:
                results = []
                results.append(
                    Result(
                        level=FailureLevel.WARNING,
                        message=Message(text='Reduce the password reuse prevention period to 24 or fewer.'),
                        rule_id='CIS AWS Foundations Benchmark - IAM.8'
                    )
                )
                return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy warning days") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy warning days") from e


def collect_iam_compliance(iam_client, session):
    try:
        iam_password_policy_result = check_iam_password_policy(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy:", e)
        iam_password_policy_result = None

    try:
        public_access_block_results = check_public_access_block(session)
    except Exception as e:
        print("Error while checking public access block:", e)
        public_access_block_results = []

    try:
        root_account_mfa_result = check_root_account_mfa_enabled(iam_client)
    except Exception as e:
        print("Error while checking root account MFA status:", e)
        root_account_mfa_result = None

    try:
        user_group_policies_results = check_user_group_policies(iam_client)
    except Exception as e:
        print("Error while checking user and group policies in IAM:", e)
        user_group_policies_results = []

    try:
        access_keys_rotation_results = check_access_keys_rotation(iam_client)
    except Exception as e:
        print("Error while checking IAM access key rotation:", e)
        access_keys_rotation_results = []

    try:
        unused_credentials_results = check_unused_credentials(iam_client)
    except Exception as e:
        print("Error while checking unused credentials in IAM:", e)
        unused_credentials_results = []

    try:
        iam_policy_version_results = check_iam_policy_version(iam_client)
    except Exception as e:
        print("Error while checking IAM policy versions:", e)
        iam_policy_version_results = []

    try:
        iam_password_policy_expiration_results = check_iam_password_policy_expiration(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy expiration:", e)
        iam_password_policy_expiration_results = []

    try:
        iam_password_policy_reuse_results = check_iam_password_policy_reuse(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy reuse:", e)
        iam_password_policy_reuse_results = []

    try:
        iam_password_policy_requirements_results = check_iam_password_policy_requirements(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy requirements:", e)
        iam_password_policy_requirements_results = []

    try:
        iam_password_policy_allow_users_change_results = check_iam_password_policy_allow_users_change(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy allow users change:", e)
        iam_password_policy_allow_users_change_results = []

    try:
        iam_password_policy_expire_root_user_results = check_iam_password_policy_expire_root_user(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy expire root user:", e)
        iam_password_policy_expire_root_user_results = []

    try:
        iam_password_policy_hard_expiry_results = check_iam_password_policy_hard_expiry(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy hard expiry:", e)
        iam_password_policy_hard_expiry_results = []

    try:
        iam_password_policy_warning_days_results = check_iam_password_policy_warning_days(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy warning days:", e)
        iam_password_policy_warning_days_results = []

    results = (
            [iam_password_policy_result]
            + public_access_block_results
            + [root_account_mfa_result]
            + user_group_policies_results
            + access_keys_rotation_results
            + unused_credentials_results
            + iam_policy_version_results
            + iam_password_policy_expiration_results
            + iam_password_policy_reuse_results
            + iam_password_policy_requirements_results
            + iam_password_policy_allow_users_change_results
            + iam_password_policy_expire_root_user_results
            + iam_password_policy_hard_expiry_results
            + iam_password_policy_warning_days_results
    )

    return results


def generate_report(results):
    compliance_count = {
        FailureLevel.ERROR: 0,
        FailureLevel.WARNING: 0
    }

    print("IAM Compliance Report")
    print("=====================")
    print("Report generated at: {}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    for result in results:
        if result is not None:
            compliance_count[result.level] += 1
            print("Rule ID: {}".format(result.rule_id))
            print("Level: {}".format(result.level))
            print("Message: {}\n".format(result.message.text))

    print("Compliance Summary")
    print("------------------")
    total_results = len([result for result in results if result is not None])
    print("Total Results: {}".format(total_results))
    print("Errors: {}".format(compliance_count[FailureLevel.ERROR]))
    print("Warnings: {}\n".format(compliance_count[FailureLevel.WARNING]))

    with open("iam_compliance_report.txt", "w") as report_file:
        report_file.write("IAM Compliance Report\n")
        report_file.write("====================\n\n")
        report_file.write("Report generated at: {}\n\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        for result in results:
            if result is not None:
                report_file.write("Rule ID: {}\n".format(result.rule_id))
                report_file.write("Level: {}\n".format(result.level))
                report_file.write("Message: {}\n".format(result.message.text))
                report_file.write("----------------------------------------\n\n")

        report_file.write("Compliance Summary\n")
        report_file.write("------------------\n")
        report_file.write("Total Results: {}\n".format(total_results))
        report_file.write("Errors: {}\n".format(compliance_count[FailureLevel.ERROR]))
        report_file.write("Warnings: {}\n".format(compliance_count[FailureLevel.WARNING]))

    print("IAM Compliance report generated successfully.")


# Solicitar as credenciais de acesso
aws_access_key_id = getpass.getpass("Digite a AWS Access Key ID: ")
aws_secret_access_key = getpass.getpass("Digite a AWS Secret Access Key: ")

# Configurar a sessão do AWS SDK
session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)
iam_client = session.client('iam')

# Coletar resultados de conformidade do IAM
results = collect_iam_compliance(iam_client, session)

# Gerar o relatório de conformidade
generate_report(results)
import datetime
import getpass
import boto3
import botocore


class FailureLevel:
    ERROR = "error"
    WARNING = "warning"


class Result:
    def __init__(self, level, message, rule_id):
        self.level = level
        self.message = message
        self.rule_id = rule_id


class Message:
    def __init__(self, text):
        self.text = text


def anonymize_access_key(access_key):
    anonymized_key = access_key[:4] + '*' * (len(access_key) - 4)
    return anonymized_key


def check_root_account_mfa_enabled(iam_client):
    try:
        response = iam_client.get_account_summary()
        account_summary = response['SummaryMap']

        if not account_summary.get('AccountMFAEnabled'):
            return Result(
                level=FailureLevel.ERROR,
                message=Message(text='Enable MFA for the root account.'),
                rule_id='CIS AWS Foundations Benchmark - 1.1'
            )
    except Exception as e:
        raise Exception("Error while checking root account MFA status") from e


def check_iam_password_policy(iam_client):
    try:
        try:
            response = iam_client.get_account_password_policy()
            password_policy = response.get('PasswordPolicy')

            if not password_policy:
                return Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='IAM password policy not found.'),
                    rule_id='CIS AWS Foundations Benchmark - 1.3'
                )

            if not password_policy.get('MinimumPasswordLength') or password_policy.get(
                    'MinimumPasswordLength') < 14:
                return Result(
                    level=FailureLevel.ERROR,
                    message=Message(
                        text='Ensure the IAM password policy requires a minimum length of 14 or more characters.'),
                    rule_id='CIS AWS Foundations Benchmark - 1.3'
                )
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='IAM password policy not found.'),
                    rule_id='CIS AWS Foundations Benchmark - 1.3'
                )
            else:
                raise Exception("Error while checking IAM password policy") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy") from e


def check_user_group_policies(iam_client):
    try:
        response = iam_client.list_users()
        users = response['Users']

        results = []
        for user in users:
            user_name = user['UserName']
            response = iam_client.list_user_policies(UserName=user_name)
            user_policies = response.get('PolicyNames')

            if user_policies:
                results.append(
                    Result(
                        level=FailureLevel.ERROR,
                        message=Message(text='Ensure no users have inline policies.'),
                        rule_id='CIS AWS Foundations Benchmark - 1.4'
                    )
                )
        return results
    except Exception as e:
        raise Exception("Error while checking user and group policies in IAM") from e


def check_access_keys_rotation(iam_client):
    try:
        response = iam_client.list_users()
        users = response['Users']

        results = []
        for user in users:
            user_name = user['UserName']
            response = iam_client.list_access_keys(UserName=user_name)
            access_keys = response.get('AccessKeyMetadata')

            if access_keys:
                for access_key in access_keys:
                    access_key_id = access_key['AccessKeyId']
                    access_key_last_rotated = access_key.get('CreateDate')

                    if access_key_last_rotated:
                        create_date = access_key_last_rotated.date()
                        days_since_rotation = (datetime.date.today() - create_date).days

                        if days_since_rotation > 90:
                            anonymized_access_key = anonymize_access_key(access_key_id)
                            results.append(
                                Result(
                                    level=FailureLevel.ERROR,
                                    message=Message(
                                        text=f'Rotate access key {anonymized_access_key} every 90 days or less.'),
                                    rule_id='CIS AWS Foundations Benchmark - 1.23'
                                )
                            )
        return results
    except Exception as e:
        raise Exception("Error while checking IAM access key rotation") from e


def check_unused_credentials(iam_client):
    try:
        response = iam_client.list_access_keys()
        access_keys = response.get('AccessKeyMetadata')

        if access_keys:
            results = []
            for access_key in access_keys:
                access_key_id = access_key['AccessKeyId']
                access_key_last_used = access_key.get('LastUsedDate')

                if not access_key_last_used:
                    anonymized_access_key = anonymize_access_key(access_key_id)
                    results.append(
                        Result(
                            level=FailureLevel.ERROR,
                            message=Message(text=f'Remove unused access key {anonymized_access_key}.'),
                            rule_id='CIS AWS Foundations Benchmark - 1.24'
                        )
                    )
            return results
    except Exception as e:
        raise Exception("Error while checking unused credentials in IAM") from e


def check_public_access_block(session):
    try:
        s3_client = session.client('s3')
        try:
            response = s3_client.list_buckets()
            buckets = response['Buckets']

            results = []
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    response = s3_client.get_public_access_block(Bucket=bucket_name)

                    if not response['PublicAccessBlockConfiguration']['BlockPublicAcls'] or not \
                            response['PublicAccessBlockConfiguration']['BlockPublicPolicy'] or not \
                            response['PublicAccessBlockConfiguration']['IgnorePublicAcls'] or not \
                            response['PublicAccessBlockConfiguration']['RestrictPublicBuckets']:
                        results.append(
                            Result(
                                level=FailureLevel.ERROR,
                                message=Message(
                                    text=f'Ensure public access is blocked for S3 bucket {bucket_name}.'),
                                rule_id='CIS AWS Foundations Benchmark - 3.1'
                            )
                        )
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        results.append(
                            Result(
                                level=FailureLevel.ERROR,
                                message=Message(
                                    text=f'Ensure public access is blocked for S3 bucket {bucket_name}.'),
                                rule_id='CIS AWS Foundations Benchmark - 3.1'
                            )
                        )
                    else:
                        raise Exception(f"Error while checking public access block for S3 bucket {bucket_name}") from e
                except Exception as e:
                    raise Exception(f"Error while checking public access block for S3 bucket {bucket_name}") from e
            return results
        except botocore.exceptions.ClientError as e:
            raise Exception("Error while listing S3 buckets") from e
        except Exception as e:
            raise Exception("Error while listing S3 buckets") from e
    except Exception as e:
        raise Exception("Error while creating S3 client") from e


def check_iam_policy_version(iam_client):
    try:
        response = iam_client.list_policies()
        policies = response['Policies']

        results = []
        for policy in policies:
            policy_arn = policy['Arn']
            response = iam_client.list_policy_versions(PolicyArn=policy_arn)
            policy_versions = response.get('Versions')

            if policy_versions:
                if len(policy_versions) > 1:
                    results.append(
                        Result(
                            level=FailureLevel.ERROR,
                            message=Message(text=f'Delete old versions of IAM policy {policy_arn}.'),
                            rule_id='CIS AWS Foundations Benchmark - IAM.1'
                        )
                    )
        return results
    except Exception as e:
        raise Exception("Error while checking IAM policy versions") from e


def check_iam_password_policy_expiration(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and password_policy.get('ExpirePasswords'):
            results = []
            results.append(
                Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='Disable password expiration for IAM users.'),
                    rule_id='CIS AWS Foundations Benchmark - IAM.2'
                )
            )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy expiration") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy expiration") from e


def check_iam_password_policy_reuse(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and password_policy.get('PasswordReusePrevention') > 0:
            results = []
            results.append(
                Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='Disable password reuse for IAM users.'),
                    rule_id='CIS AWS Foundations Benchmark - IAM.3'
                )
            )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy reuse") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy reuse") from e


def check_iam_password_policy_requirements(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy:
            password_policy_requirements = {
                'RequireUppercaseCharacters': 'uppercase letters (A-Z)',
                'RequireLowercaseCharacters': 'lowercase letters (a-z)',
                'RequireNumbers': 'numbers (0-9)',
                'RequireSymbols': 'non-alphanumeric characters'
            }

            results = []
            for requirement, description in password_policy_requirements.items():
                if password_policy.get(requirement):
                    results.append(
                        Result(
                            level=FailureLevel.ERROR,
                            message=Message(text=f'Disable requirement for {description} in IAM password policy.'),
                            rule_id='CIS AWS Foundations Benchmark - IAM.4'
                        )
                    )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy requirements") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy requirements") from e


def check_iam_password_policy_allow_users_change(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and not password_policy.get('AllowUsersToChangePassword'):
            results = []
            results.append(
                Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='Allow IAM users to change their own password.'),
                    rule_id='CIS AWS Foundations Benchmark - IAM.5'
                )
            )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy allow users change") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy allow users change") from e


def check_iam_password_policy_expire_root_user(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and not password_policy.get('ExpireRootPassword'):
            results = []
            results.append(
                Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='Enable password expiration for root account.'),
                    rule_id='CIS AWS Foundations Benchmark - IAM.6'
                )
            )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy expire root user") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy expire root user") from e


def check_iam_password_policy_hard_expiry(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and password_policy.get('MaxPasswordAge') and password_policy.get('HardExpiry'):
            results = []
            results.append(
                Result(
                    level=FailureLevel.ERROR,
                    message=Message(text='Disable password hard expiry for IAM users.'),
                    rule_id='CIS AWS Foundations Benchmark - IAM.7'
                )
            )
            return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy hard expiry") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy hard expiry") from e


def check_iam_password_policy_warning_days(iam_client):
    try:
        response = iam_client.get_account_password_policy()
        password_policy = response.get('PasswordPolicy')

        if password_policy and password_policy.get('PasswordReusePrevention') > 0:
            if password_policy.get('PasswordReusePrevention') > 24:
                results = []
                results.append(
                    Result(
                        level=FailureLevel.WARNING,
                        message=Message(text='Reduce the password reuse prevention period to 24 or fewer.'),
                        rule_id='CIS AWS Foundations Benchmark - IAM.8'
                    )
                )
                return results
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            return []
        else:
            raise Exception("Error while checking IAM password policy warning days") from e
    except Exception as e:
        raise Exception("Error while checking IAM password policy warning days") from e


def collect_iam_compliance(iam_client, session):
    try:
        iam_password_policy_result = check_iam_password_policy(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy:", e)
        iam_password_policy_result = None

    try:
        public_access_block_results = check_public_access_block(session)
    except Exception as e:
        print("Error while checking public access block:", e)
        public_access_block_results = []

    try:
        root_account_mfa_result = check_root_account_mfa_enabled(iam_client)
    except Exception as e:
        print("Error while checking root account MFA status:", e)
        root_account_mfa_result = None

    try:
        user_group_policies_results = check_user_group_policies(iam_client)
    except Exception as e:
        print("Error while checking user and group policies in IAM:", e)
        user_group_policies_results = []

    try:
        access_keys_rotation_results = check_access_keys_rotation(iam_client)
    except Exception as e:
        print("Error while checking IAM access key rotation:", e)
        access_keys_rotation_results = []

    try:
        unused_credentials_results = check_unused_credentials(iam_client)
    except Exception as e:
        print("Error while checking unused credentials in IAM:", e)
        unused_credentials_results = []

    try:
        iam_policy_version_results = check_iam_policy_version(iam_client)
    except Exception as e:
        print("Error while checking IAM policy versions:", e)
        iam_policy_version_results = []

    try:
        iam_password_policy_expiration_results = check_iam_password_policy_expiration(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy expiration:", e)
        iam_password_policy_expiration_results = []

    try:
        iam_password_policy_reuse_results = check_iam_password_policy_reuse(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy reuse:", e)
        iam_password_policy_reuse_results = []

    try:
        iam_password_policy_requirements_results = check_iam_password_policy_requirements(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy requirements:", e)
        iam_password_policy_requirements_results = []

    try:
        iam_password_policy_allow_users_change_results = check_iam_password_policy_allow_users_change(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy allow users change:", e)
        iam_password_policy_allow_users_change_results = []

    try:
        iam_password_policy_expire_root_user_results = check_iam_password_policy_expire_root_user(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy expire root user:", e)
        iam_password_policy_expire_root_user_results = []

    try:
        iam_password_policy_hard_expiry_results = check_iam_password_policy_hard_expiry(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy hard expiry:", e)
        iam_password_policy_hard_expiry_results = []

    try:
        iam_password_policy_warning_days_results = check_iam_password_policy_warning_days(iam_client)
    except Exception as e:
        print("Error while checking IAM password policy warning days:", e)
        iam_password_policy_warning_days_results = []

    results = (
            [iam_password_policy_result]
            + public_access_block_results
            + [root_account_mfa_result]
            + user_group_policies_results
            + access_keys_rotation_results
            + unused_credentials_results
            + iam_policy_version_results
            + iam_password_policy_expiration_results
            + iam_password_policy_reuse_results
            + iam_password_policy_requirements_results
            + iam_password_policy_allow_users_change_results
            + iam_password_policy_expire_root_user_results
            + iam_password_policy_hard_expiry_results
            + iam_password_policy_warning_days_results
    )

    return results


def generate_report(results):
    compliance_count = {
        FailureLevel.ERROR: 0,
        FailureLevel.WARNING: 0
    }

    print("IAM Compliance Report")
    print("=====================")
    print("Report generated at: {}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    for result in results:
        if result is not None:
            compliance_count[result.level] += 1
            print("Rule ID: {}".format(result.rule_id))
            print("Level: {}".format(result.level))
            print("Message: {}\n".format(result.message.text))

    print("Compliance Summary")
    print("------------------")
    total_results = len([result for result in results if result is not None])
    print("Total Results: {}".format(total_results))
    print("Errors: {}".format(compliance_count[FailureLevel.ERROR]))
    print("Warnings: {}\n".format(compliance_count[FailureLevel.WARNING]))

    with open("iam_compliance_report.txt", "w") as report_file:
        report_file.write("IAM Compliance Report\n")
        report_file.write("====================\n\n")
        report_file.write("Report generated at: {}\n\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        for result in results:
            if result is not None:
                report_file.write("Rule ID: {}\n".format(result.rule_id))
                report_file.write("Level: {}\n".format(result.level))
                report_file.write("Message: {}\n".format(result.message.text))
                report_file.write("----------------------------------------\n\n")

        report_file.write("Compliance Summary\n")
        report_file.write("------------------\n")
        report_file.write("Total Results: {}\n".format(total_results))
        report_file.write("Errors: {}\n".format(compliance_count[FailureLevel.ERROR]))
        report_file.write("Warnings: {}\n".format(compliance_count[FailureLevel.WARNING]))

    print("IAM Compliance report generated successfully.")


# Solicitar as credenciais de acesso
aws_access_key_id = getpass.getpass("Digite a AWS Access Key ID: ")
aws_secret_access_key = getpass.getpass("Digite a AWS Secret Access Key: ")

# Configurar a sessão do AWS SDK
session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)
iam_client = session.client('iam')

# Coletar resultados de conformidade do IAM
results = collect_iam_compliance(iam_client, session)

# Gerar o relatório de conformidade
generate_report(results)
