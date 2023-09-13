import boto3
import os

# Initialize the AWS IAM client using environment variables
aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
aws_session_token = os.environ.get('AWS_SESSION_TOKEN')

if not aws_access_key_id or not aws_secret_access_key:
    print("AWS credentials not found in environment variables.")
    exit(1)

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
    user_info = iam.get_user(UserName=username)
    try:
        iam.get_login_profile(UserName=username)
        user_login = "Enabled"
    except:
        user_login = "Disabled"
    print("--- Console Access: " + user_login)

    user_access_keys = iam.list_access_keys(UserName=username)
    if user_access_keys:
        print("--- Access Keys:")
        for access_key in user_access_keys['AccessKeyMetadata']:
            access_key_last_used = iam.get_access_key_last_used(AccessKeyId=access_key['AccessKeyId'])
            try:
                access_key_date_last_used = access_key_last_used['AccessKeyLastUsed']['LastUsedDate']
                access_key_date_last_used = access_key_date_last_used.strftime('%Y-%m-%d')
            except:
                access_key_date_last_used = "N/A"
            print("---- " + access_key['AccessKeyId'] + " [" + access_key['Status'] + "] - Last Used: " + access_key_date_last_used)

def get_group_users(group):
    try:
        group_info = iam.get_group(GroupName=group)
        group_users = group_info.get('Users', [])
        print("--- Group Members:")
        for group_member in group_users:
            group_user = group_member['UserName']
            user_info = iam.get_user(UserName=group_user)
            try:
                iam.get_login_profile(UserName=group_user)
                user_login = "Enabled"
            except:
                user_login = "Disabled"
            print("---- Console Access: " + user_login)
            user_access_keys = iam.list_access_keys(UserName=group_user)
            if user_access_keys:
                print("---- Access Keys:")
                for access_key in user_access_keys['AccessKeyMetadata']:
                    access_key_last_used = iam.get_access_key_last_used(AccessKeyId=access_key['AccessKeyId'])
                    try:
                        access_key_date_last_used = access_key_last_used['AccessKeyLastUsed']['LastUsedDate']
                        access_key_date_last_used = access_key_date_last_used.strftime('%Y-%m-%d')
                    except:
                        access_key_date_last_used = "N/A"
                    print("----- " + access_key['AccessKeyId'] + " [" + access_key['Status'] + "] - Last Used: " + access_key_date_last_used)
    except:
        print("--- No Members in Group")

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
all_policies = []

# Initial request to list policies
response = iam.list_policies(
    Scope='Local',
    OnlyAttached=False,
    MaxItems=100  # Maximum number of policies to retrieve per request
)

# Add the policies from the initial request to the list
all_policies.extend(response['Policies'])

# Continue making requests as long as there are more policies to retrieve
while 'Marker' in response:
    response = iam.list_policies(
        Scope='Local',
        MaxItems=100,  # Maximum number of policies to retrieve per request
        Marker=response['Marker']  # Marker from the previous response
    )
    all_policies.extend(response['Policies'])

print(len(all_policies))

# Iterate through the policies and check for the wildcard in actions and resources
bad_policies = []

for policy in all_policies:
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
        for statement in bad_statement_list:
            print(statement)
        get_attached_entities(policy_arn)
        print("------------------------------------------------------------------------------------")
        print("------------------------------------------------------------------------------------")
        print(" ")
