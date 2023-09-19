import boto3
import os
import argparse
import csv



# argParser = argparse.ArgumentParser()
argParser = argparse.ArgumentParser(description="By default AWS_EOD will check all polcies (AWS and User managed) looking for actions that contain wildcard or sensitive API calls without limited resource scope.The output will be printed to standard output unless oterhwise specified.")

argParser.add_argument("-p", "--profile_creds", help="Specify AWS CLI profile to use for authentication")
argParser.add_argument("-i", "--input_creds", action="store_true", help="User prompted to provide AWS Credentials")


argParser.add_argument("-f", "--format", help="Output file format, supports json or csv")
argParser.add_argument("-o", "--output_file", help="Name of the outpu file")

argParser.add_argument("-s", "--sensitive_actions", action="store_true", help="Only check policies against list of sensitive actions, skip wildcard checks")
argParser.add_argument("-w", "--wildcard_actions", action="store_true", help="Only check policies for wildcard actions, skip sensitive actions checks")
argParser.add_argument("-r", "--remove_resource_check", action="store_true", help="Removes the check for unrestricted resources in the policy statement")


argParser.add_argument("-u", "--user_policies", action="store_true", help="Only check User Managed policies")
argParser.add_argument("-a", "--aws_policies", action="store_true", help="Only check AWS Managed policies")

args = argParser.parse_args()

# print (args)

if args.output_file is not None:
    if args.output_file != "json" and args.output_file != "csv":
        print ("Wrong output option entered, specify csv or json")
    elif args.output_file == "json":
        print ("json Incoming")
    elif args.output_file == "csv":
        print ("csv Incoming")

def print_creds():
    print(aws_access_key_id)
    print(aws_secret_access_key)
    print(aws_session_token)


def prompt_credentials():
    # Initialize the AWS IAM client using environment variables
    aws_access_key_id = input("Enter your AWS Access Key ID: ")
    aws_secret_access_key = input("Enter your AWS Secret Access Key: ")
    aws_session_token = input("Enter your AWS Session Token (if applicable): ")
    return aws_access_key_id, aws_secret_access_key, aws_session_token


def get_default_aws_credentials():
    session = boto3.Session()
    credentials = session.get_credentials()

    # Get the access key, secret key, and session token (if available)
    aws_access_key_id = credentials.access_key
    aws_secret_access_key = credentials.secret_key
    try:
        aws_session_token = credentials.token
    except:
        aws_session_token = ""
    if aws_session_token is None:
        aws_session_token = ""
    return aws_access_key_id, aws_secret_access_key, aws_session_token


def get_aws_credentials(profile_name):
    try:
        session = boto3.Session(profile_name=profile_name)
        credentials = session.get_credentials()
        # print (credentials.access_key)
        aws_access_key_id = credentials.access_key
        aws_secret_access_key = credentials.secret_key
        aws_session_token = credentials.token
        return aws_access_key_id, aws_secret_access_key, aws_session_token
    except Exception as e:
        print(f"An error occurred while fetching AWS credentials for profile '{profile_name}': {str(e)}")
        return None, None, None

def variables_credentials():
    aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_session_token = os.environ.get('AWS_SESSION_TOKEN')
    return aws_access_key_id, aws_secret_access_key, aws_session_token

def get_account_info():
    sts = session.client('sts')
    whoami = sts.get_caller_identity()
    account_id = whoami['Account']
    print ("Reviewing policies for account: "+ str(account_id))
    print ("Using the identity: " + whoami['Arn'])
    proceed = input("Would you like to proceed scanning this account? (y/n)")
    if proceed == "y" or proceed == "Y":
        return (account_id)
    elif proceed == "n" or proceed == "N":
        print ("Scan aborted")
        exit()




if args.profile_creds is None and args.input_creds == False:
    print ("default")
    # print (get_default_aws_credentials())
    aws_access_key_id, aws_secret_access_key, aws_session_token = get_default_aws_credentials()
elif args.profile_creds is not None and args.input_creds != False:
    print ("Cannot select both input and aws profile name, choose either -i or -p <PROFILE_NAME>")
elif  args.input_creds == True:
    print ("Input Credentials")
    aws_access_key_id, aws_secret_access_key, aws_session_token = prompt_credentials()

elif args.profile_creds is not None:
    print ("Specified Profile")
    aws_access_key_id, aws_secret_access_key, aws_session_token = get_aws_credentials(args.profile_creds)


# get_aws_credentials("")

# if not aws_access_key_id or not aws_secret_access_key:
#     print("AWS credentials not found in environment variables.")
#     exit(1)

session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    aws_session_token=aws_session_token)

account_id = get_account_info()



# Initialize the IAM client
iam = boto3.client('iam')

def get_trusted_entities(role_name):
    try:
        role = iam.get_role(RoleName=role_name)
        trust_policy_principal = role['Role']['AssumeRolePolicyDocument']['Statement'][0]['Principal']
        print("---- Trust Policy:" + str(trust_policy_principal))
        print(" ")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def get_user_access_info(username):
    access_key_summary = ""
    user_info = iam.get_user(UserName=username)
    try:
        iam.get_login_profile(UserName=username)
        user_login = "Enabled"
    except:
        user_login = "Disabled"
    print("--- Console Access: " + user_login)

    user_access_keys = iam.list_access_keys(UserName=username)
    if user_access_keys:
        access_key_count = 0
        print("--- Access Keys:")
        for access_key in user_access_keys['AccessKeyMetadata']:
            access_key_count = +1
            access_key_last_used = iam.get_access_key_last_used(AccessKeyId=access_key['AccessKeyId'])
            try:
                access_key_date_last_used = access_key_last_used['AccessKeyLastUsed']['LastUsedDate']
                access_key_date_last_used = access_key_date_last_used.strftime('%Y-%m-%d')
            except:
                access_key_date_last_used = "N/A"
            print("------ " + access_key['AccessKeyId'] + " [" + access_key['Status'] + "] - Last Used: " + access_key_date_last_used)



def get_group_users(group):
    # try:
    group_info = iam.get_group(GroupName=group)
    group_users = group_info.get('Users', [])
    print("--- Group Members:")
    for group_member in group_users:
        group_user = group_member['UserName']
        print("---- " + group_user)
        user_info = iam.get_user(UserName=group_user)
        try:
            iam.get_login_profile(UserName=group_user)
            user_login = "Enabled"
        except:
            user_login = "Disabled"
            password_last_used = ""
        # print("----- Console Access: " + user_login)

        if user_login == "Enabled":
            # password_last_used = user_info['PasswordLastUsed']
            # password_last_used = password_last_used.strftime('%Y-%m-%d')
            try:
                password_last_used = user_info['User']['PasswordLastUsed']
                password_last_used = password_last_used.strftime('%Y-%m-%d')
            except:
                password_last_used = "N/A"
            print("----- Console Access: " + user_login+" - Last Used: " + str(password_last_used))
        else:
            print("----- Console Access: " + user_login)
        user_access_keys = iam.list_access_keys(UserName=group_user)
        if user_access_keys:
            print("----- Access Keys:")
            for access_key in user_access_keys['AccessKeyMetadata']:
                access_key_last_used = iam.get_access_key_last_used(AccessKeyId=access_key['AccessKeyId'])
                try:
                    access_key_date_last_used = access_key_last_used['AccessKeyLastUsed']['LastUsedDate']
                    access_key_date_last_used = access_key_date_last_used.strftime('%Y-%m-%d')
                except:
                    access_key_date_last_used = "N/A"
                print("------ " + access_key['AccessKeyId'] + " [" + access_key['Status'] + "] - Last Used: " + access_key_date_last_used)
    # except:
    #     print("--- No Members in Group")

def get_attached_entities(specified_policy_arn):
    instance_role_list = []
    role_list = []

    policy = iam.get_policy(PolicyArn=specified_policy_arn)
    policy_name = policy['Policy']['PolicyName']

    response = iam.list_entities_for_policy(PolicyArn=specified_policy_arn)

    attached_entities = {
        'PolicyName': policy_name,
        'AttachedUsers': [user['UserName'] for user in response.get('PolicyUsers', [])],
        'AttachedGroups': [group['GroupName'] for group in response.get('PolicyGroups', [])],
        'AttachedRoles': [role['RoleName'] for role in response.get('PolicyRoles', [])]
    }

    if attached_entities:
        print("\nAttached entities:")
        
        if attached_entities['AttachedUsers']:
            print("- Users:")
            for user in attached_entities['AttachedUsers']:
                print("-- " + user)
                get_user_access_info(user)
                print(" ")
        
        if attached_entities['AttachedGroups']:
            print("- Groups:")
            for group in attached_entities['AttachedGroups']:
                print("-- " + group)
                get_group_users(group)
        
        if attached_entities['AttachedRoles']:
            for role in attached_entities['AttachedRoles']:
                try: 
                    instance_role_info = iam.get_instance_profile(InstanceProfileName=role)
                    instance_role_list.append(role)
                except:
                    role_list.append(role)
        
        if role_list:
            print("- User Roles:")
            for user_role in role_list:
                print("-- " + user_role)
                get_trusted_entities(user_role)
        
        if instance_role_list:
            print("- Instance Roles:")
            for instance_role in instance_role_list:
                print("-- " + instance_role)
                get_trusted_entities(instance_role)
    else:
        print("No Attached Entities")

# Initialize an empty list to store policies
user_policies = []
aws_policies = []

# Initial request to list policies
response = iam.list_policies(
    Scope='Local',
    OnlyAttached=False,
    MaxItems=100  # Maximum number of policies to retrieve per request
)

# Add the policies from the initial request to the list
user_policies.extend(response['Policies'])

# Continue making requests as long as there are more policies to retrieve
while 'Marker' in response:
    response = iam.list_policies(
        Scope='Local',
        MaxItems=100,  # Maximum number of policies to retrieve per request
        Marker=response['Marker']  # Marker from the previous response
    )
    user_policies.extend(response['Policies'])


#####
# Pull back AWS managed policies
####
Marker = ""

# Initial request to list policies
response = iam.list_policies(
    Scope='AWS',
    OnlyAttached=True,
    MaxItems=100  # Maximum number of policies to retrieve per request
)

# Add the policies from the initial request to the list
aws_policies.extend(response['Policies'])

# Continue making requests as long as there are more policies to retrieve
while 'Marker' in response:
    response = iam.list_policies(
        Scope='Local',
        MaxItems=100,  # Maximum number of policies to retrieve per request
        Marker=response['Marker']  # Marker from the previous response
    )
    aws_policies.extend(response['Policies'])

all_policies = user_policies + aws_policies



# Iterate through the policies and check for the wildcard in actions and resources
bad_policies = []
csv_output = []
for policy in all_policies:
    csv_row = []
    bad_statement_list = []
    policy_name = policy['PolicyName']
    policy_arn = policy['Arn']

    policy_version = iam.get_policy_version(
        PolicyArn=policy_arn,
        VersionId=policy['DefaultVersionId']
    )

    policy_document = policy_version['PolicyVersion']['Document']
    policy_statements = policy_document['Statement']

    if isinstance(policy_statements, list):

        for statement in policy_statements:
            effect_list = []
            action_list = []
            resource_list = []
            bad_action = ""
            bad_resource = ""

            policy_statement_action = statement.get('Action', [])
            if isinstance(policy_statement_action, str):
                action_list.append(policy_statement_action)
            else:
                action_list = policy_statement_action

            for action in action_list:
                if ":*" in action:
                    bad_action = "y"

            policy_statement_resource = statement.get('Resource', [])
            if isinstance(policy_statement_resource, str):
                resource_list.append(policy_statement_resource)
            else:
                resource_list = policy_statement_resource

            for resource in resource_list:
                if resource == "*":
                    bad_resource = "y"

            if bad_action == "y" and bad_resource == "y":
                bad_statement_list.append(statement)
            

    if bad_statement_list:
        print(policy_arn)
        bad_policies.append(policy_arn)
        for statement in bad_statement_list:
            print(statement)
        get_attached_entities(policy_arn)
        # csv_row.append(policy_name)  
    # csv_output.append(csv_row)      
    # with open('Example.csv', 'w', newline = '') as csvfile:
    #     output_file = csv.writer(csvfile, delimiter = ' ')
    #     output_file.writerow(csv_output)
        print("------------------------------------------------------------------------------------")
        print("------------------------------------------------------------------------------------")
        print("\n\n")
print("Reviewed "+ str(len((user_policies)))+" User-Managed Policies")
print("Reviewed "+ str(len((aws_policies)))+" Attached AWS-Managed Policies")
print("Found "+ str(len(bad_policies))+" Overly Permissive User-Managed Policies")
