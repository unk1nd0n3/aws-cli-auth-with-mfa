# -*- coding: utf8 -*-
# __version__ = '1.0'


from __future__ import print_function
import boto3
import botocore
import logging
import argparse
import os
import shutil
import re

logfile = os.path.realpath(os.path.join(os.path.dirname(__file__), os.path.expanduser("~/.aws/mfa-token.log")))
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", filename=logfile)
logger = logging.getLogger("main")

AWS_CONFIG_PATH = '%s/.aws/config' % (os.path.expanduser('~'),)
AWS_CREDS_PATH = '%s/.aws/credentials' % (os.path.expanduser('~'),)
DURATION_SECONDS = 43200


def autoload_aws(profile, service):
    """
    Make connection to particular AWS service
    :param profile: string
    :param service: string
    :return: object representing connection to aws service
    """
    try:
        aws_session = boto3.Session(profile_name=profile)
        aws_client = aws_session.client(service)
        return aws_client
    except Exception as e:
        logging.exception(e)


def backup_aws_creds_files():
    """
    Backup local AWS creds files
    :return: none
    """
    shutil.copy(AWS_CONFIG_PATH, AWS_CONFIG_PATH + ".bkp")
    shutil.copy(AWS_CREDS_PATH, AWS_CREDS_PATH + ".bkp")


def get_aws_local_file(aws_creds_file):
    """
    Converting aws config and credentials files into dictionaries
    :param aws_creds_file: string
    :return: dictionary
    """
    aws_config = {}
    current_profile = ''
    input_file = open(aws_creds_file, 'r')
    for line in input_file.readlines():
        # print line
        if re.match('^\[', line):
            current_profile = line.strip()[1:-1]
            aws_config[current_profile] = {}
        if re.match('\w', line):
            key, val = line.split('=')
            aws_config[current_profile][key.strip()] = val.strip()
    input_file.close()
    return aws_config


def get_profiles_names(profiles):
    """
    AWS profiles selection for STS token generation
    :param profiles: list
    :return: list
    """
    print("Parse AWS credentials in " + AWS_CREDS_PATH + "\n")
    input_profile = "\nPlease select option from above for temp credentials generation."
    profiles_wo_mfa = [prof for prof in profiles if not re.match('^mfa-', prof)]
    input_profile += "\nType integer, integers with space or 'all' from [0 to " + str(len(profiles_wo_mfa) - 1) + "]: "
    chosen_profile_status = False
    selected_profiles = []
    while not chosen_profile_status:
        print("\nList of all found configured AWS profiles in provided config file:")
        for profile in profiles_wo_mfa:
            print('\t\t' + str(profiles_wo_mfa.index(profile)) + ") " + profile)
        print("\n\t\tall) Or type 'all' for all profiles ...")
        option_input = raw_input(input_profile)
        try:
            if not option_input.strip().lower() == 'all' and re.match('\S+', option_input):
                options = re.findall(r"\d+", option_input)
                for option in options:
                    if re.match('\d', option) and int(option) in range(len(profiles_wo_mfa)):
                        selected_profiles.append(profiles_wo_mfa[int(option)])
                return selected_profiles
            elif option_input.strip().lower() == 'all':
                return profiles_wo_mfa
            else:
                print("ERROR. Please select correct option")
        except ValueError:
            print("ERROR. You have asked to use Integer symbols. Try again...")


def get_mfa_arn(profiles):
    """
    Get MFA ARN (Serial number) for selected local AWS profiles
    :param profiles: string
    :return: dictionary
    """
    profile_mfa_arn = {}
    for profile in profiles:
        iam_client = autoload_aws(profile, 'iam')
        try:
            response = iam_client.get_user()
            user_mfa_device = iam_client.list_mfa_devices(UserName=response['User']['UserName'])['MFADevices']
            if user_mfa_device:
                profile_mfa_arn[profile] = user_mfa_device[0]['SerialNumber']
            else:
                print("\nERROR. Your account has not Virtual MFA device. Create Virtual device or use another account.")
                quit(0)
        except botocore.exceptions.NoCredentialsError:
            print("\nERROR. Can't find your credentials. Please check credentials config file.")
            quit(0)
    return profile_mfa_arn


def get_session_token(profiles, mfa_arn):
    """
    Getting STS session token with temp credentials for 12 hours
    :param profiles: list
    :param mfa_arn: dictionary
    :return: string
    """
    profiles_sts_tokens = {}
    for profile in profiles:
        profiles_sts_tokens[profile] = {}
        sts_client = autoload_aws(profile, 'sts')
        token_code_status = False
        print("\nYou have selected AWS profile: " + profile)
        input_token_code = "Provide token-code from your MFA device: "
        while not token_code_status:
            token_code = raw_input(input_token_code)
            try:
                if re.match('^\d{6}$', token_code):
                    response = sts_client.get_session_token(DurationSeconds=DURATION_SECONDS,
                                                            SerialNumber=mfa_arn[profile],
                                                            TokenCode=token_code)
                    print("Session token has been successfully generated for [profile: " + profile + "]")
                    profiles_sts_tokens[profile]['aws_access_key_id'] = response['Credentials']['AccessKeyId']
                    profiles_sts_tokens[profile]['aws_secret_access_key'] = response['Credentials']['SecretAccessKey']
                    profiles_sts_tokens[profile]['aws_session_token'] = response['Credentials']['SessionToken']
                    profiles_sts_tokens[profile]['aws_security_token'] = response['Credentials']['SessionToken']
                    token_code_status = True
                else:
                    print("Please provide 6 integers from your Virtual MFA device")
            except Exception as e:
                logging.exception(e)
                print("Access denied! Seems you provided wrong Token code or its expired. Try again...")
    return profiles_sts_tokens


def update_aws_creds_files(profiles_config, path_to_file):
    """
    Store all new Session tokens locally
    :param profiles_config:
    :param path_to_file:
    :return: none
    """
    file_update = open(path_to_file, 'w')
    final = ''
    for profile in sorted(profiles_config.keys()):
        final += '[' + profile + ']\n'
        content = profiles_config[profile]
        for val in sorted(content.keys()):
            final += val + ' = ' + content[val] + '\n'
        final += '\n'
    # print(final)
    file_update.write(final)
    file_update.close()


def main():
    """
    Main func
    :return: none
    """
    parser = argparse.ArgumentParser(
        description='Get MFA token for 2FA AWS API auth '
    )
    parser.add_argument(
        '-silent',
        '--silent',
        dest='silent',
        default=None,
        required=None,
        help='Specify this arg if you want to use this script for automation'
    )
    parser.add_argument(
        '-profile',
        '--profile',
        dest='profile',
        default=None,
        required=None,
        help='Specify profile for AWS credentials in local aws config file'
    )
    # Parse arguments
    args = parser.parse_args()
    if args.silent and args.profile:
        pass
    else:
        backup_aws_creds_files()
        aws_config_profile = get_aws_local_file(AWS_CONFIG_PATH)
        aws_creds_profile = get_aws_local_file(AWS_CREDS_PATH)
        aws_profiles = get_profiles_names(aws_creds_profile.keys())
        aws_mfa_arn = get_mfa_arn(aws_profiles)
        sts_creds = get_session_token(aws_profiles, aws_mfa_arn)
        for profile in aws_profiles:
            sts_profile = 'mfa-' + profile
            if profile in aws_config_profile.keys():
                aws_config_profile['profile ' + sts_profile] = aws_config_profile[profile].copy()
            else:
                aws_config_profile['profile ' + sts_profile] = aws_config_profile['profile ' + profile].copy()
            aws_creds_profile[sts_profile] = sts_creds[profile].copy()
        # Save credentials into local AWS config and creds files
        if aws_config_profile and aws_creds_profile:
            update_aws_creds_files(aws_config_profile, AWS_CONFIG_PATH)
            update_aws_creds_files(aws_creds_profile, AWS_CREDS_PATH)
            print("SUCCESS. Credentials were stored to local AWS creds files. Note: new aws config profile start with mfa-")


if __name__ == '__main__':
    main()

