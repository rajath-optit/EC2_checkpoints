import boto3
from datetime import datetime, timedelta
import json
import os
import subprocess

# Constants
HOURS_IN_MONTH = 24 * 30

def get_aws_credentials():
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_region = os.environ.get('AWS_DEFAULT_REGION')

    if aws_access_key and aws_secret_key and aws_region:
        print("Using AWS credentials from environment variables.")
        return aws_access_key, aws_secret_key, aws_region
    else:
        print("AWS credentials not found in environment variables.")
        aws_access_key = input("Enter your AWS Access Key: ")
        aws_secret_key = input("Enter your AWS Secret Key: ")
        aws_region = input("Enter your AWS Region: ")
        return aws_access_key, aws_secret_key, aws_region

def initialize_aws_clients(aws_access_key, aws_secret_key, aws_region):
    try:
        ec2_client = boto3.client('ec2', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=aws_region)
        elbv2_client = boto3.client('elbv2', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=aws_region)
        cloudwatch_client = boto3.client('cloudwatch', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=aws_region)
        eks_client = boto3.client('eks', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=aws_region)
        ecs_client = boto3.client('ecs', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=aws_region)
        return ec2_client, elbv2_client, cloudwatch_client, eks_client, ecs_client
    except Exception as e:
        print(f"Error initializing AWS clients: {str(e)}")
        return None, None, None, None, None

# Function to calculate the number of days an instance has been running
def calculate_instance_uptime(instance_launch_time):
    current_time = datetime.utcnow()
    launch_time = datetime.strptime(instance_launch_time, '%Y-%m-%dT%H:%M:%S.%fZ')
    uptime_duration = current_time - launch_time
    return uptime_duration.days

# Function to describe running instances
def describe_running_instances(ec2_client):
    try:
        response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        print("║ Describe running instances: ")
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_type = instance['InstanceType']
                ami_id = instance['ImageId']
                tags = instance.get('Tags', 'No tags')
                launch_time = instance['LaunchTime'].strftime('%Y-%m-%dT%H:%M:%S.%fZ')

                # Calculate instance uptime
                uptime_days = calculate_instance_uptime(launch_time)

                print("║   - Instance ID:", instance_id)
                print("║   - Instance Type:", instance_type)
                print("║   - AMI ID:", ami_id)
                print("║   - Tags:", tags)
                print("║   - Uptime:", uptime_days, "days")
                print("║ --------------------------------------------")
    except Exception as e:
        print(f"Error describing instances: {str(e)}")

# Function to list unused security groups
def list_unused_security_groups(ec2_client):
    try:
        regions = ec2_client.describe_regions()['Regions']
        for region in regions:
            print(f"\n║ Running command for region: {region['RegionName']}")
            ec2_client_region = boto3.client('ec2', region_name=region['RegionName'])
            response_sg = ec2_client_region.describe_security_groups(
                Filters=[{'Name': 'vpc-id', 'Values': ['']}],  # Filter security groups not attached to any VPC
            )
            unused_security_groups = [sg['GroupId'] for sg in response_sg['SecurityGroups']]
            print(f"║ Unused Security Groups in {region['RegionName']}: ")
            for group in unused_security_groups:
                print("║   -", group)
            print("║ --------------------------------------------")
    except Exception as e:
        print(f"Error listing unused security groups: {str(e)}")

# Function to check AMI encryption
def check_ami_encryption(ec2_client, ami_id):
    try:
        response = ec2_client.describe_images(ImageIds=[ami_id])
        ami = response['Images'][0]
        encryption_status = ami.get('BlockDeviceMappings', [{}])[0].get('Ebs', {}).get('Encrypted', False)
        print(f"║ Encryption Status for AMI {ami_id}: {'Encrypted' if encryption_status else 'Not Encrypted'}")
    except Exception as e:
        print(f"Error checking AMI encryption: {str(e)}")

# Function to describe custom AMIs
def list_custom_amis(ec2_client):
    try:
        response = ec2_client.describe_images(Owners=['self'])
        print("║ Describe custom AMIs: ")
        for ami in response['Images']:
            print("║   - Custom AMI ID:", ami['ImageId'])
            print("║     Creation Date:", ami['CreationDate'])
            print("║ --------------------------------------------")
    except Exception as e:
        print(f"Error listing custom AMIs: {str(e)}")

# Function to describe instances based on state
def get_instances_by_state(ec2_client, state):
    try:
        response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': [state]}])
        print(f"║ Describe instances by state {state}: ")
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                print("║   - Instance ID:", instance['InstanceId'])
        print("║ --------------------------------------------")
    except Exception as e:
        print(f"Error describing instances by state: {str(e)}")

# Function to check if an instance is attached to an Elastic Load Balancer
def is_instance_attached_to_elb(elbv2_client, instance_id):
    try:
        response = elbv2_client.describe_load_balancers()
        for elb in response['LoadBalancers']:
            target_group_arns = elbv2_client.describe_target_groups(LoadBalancerArn=elb['LoadBalancerArn'])['TargetGroups']
            for target_group in target_group_arns:
                targets = elbv2_client.describe_target_health(TargetGroupArn=target_group['TargetGroupArn'])['TargetHealthDescriptions']
                for target in targets:
                    if target['Target']['Id'] == instance_id:
                        print(f"║ Instance {instance_id} is attached to ELB {elb['LoadBalancerName']}")
                        return True
        print(f"║ Instance {instance_id} is not attached to any ELB")
        return False
    except Exception as e:
        print(f"Error checking instance attachment to ELB: {str(e)}")
        return False

# Function to check if an Elastic IP is attached to an instance
def is_eip_attached(ec2_client, instance_id):
    try:
        response = ec2_client.describe_addresses()
        for address in response['Addresses']:
            if 'InstanceId' in address and address['InstanceId'] == instance_id:
                print(f"║ Elastic IP is attached to Instance {instance_id}")
                return True
        print(f"║ Elastic IP is not attached to Instance {instance_id}")
        return False
    except Exception as e:
        print(f"Error checking EIP attachment: {str(e)}")
        return False

# Function to determine if an instance is in a public or private subnet
def is_instance_in_public_subnet(ec2_client, instance_id):
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        subnet_id = response['Reservations'][0]['Instances'][0]['SubnetId']
        response_subnet = ec2_client.describe_subnets(SubnetIds=[subnet_id])
        subnet = response_subnet['Subnets'][0]
        is_public_subnet = subnet['MapPublicIpOnLaunch']
        if is_public_subnet:
            print(f"║ Instance {instance_id} is in a public subnet")
        else:
            print(f"║ Instance {instance_id} is in a private subnet")
    except Exception as e:
        print(f"Error determining instance subnet type: {str(e)}")

# Function to check the health status of nodes in an Amazon EKS cluster
def check_eks_nodes_health(eks_client, cluster_name):
    try:
        response = eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName='ng-public')['nodegroup']
        if response['status'] == 'ACTIVE':
            print(f"║ Nodes in EKS cluster {cluster_name} are healthy")
        else:
            print(f"║ Nodes in EKS cluster {cluster_name} are not healthy")
    except Exception as e:
        print(f"Error checking EKS nodes health: {str(e)}")

# Function to describe running ECS clusters
def describe_running_ecs_clusters(ecs_client):
    try:
        response = ecs_client.list_clusters()
        print("║ Describe running ECS clusters: ")
        for cluster_arn in response['clusterArns']:
            cluster_name = cluster_arn.split('/')[-1]
            response_services = ecs_client.list_services(cluster=cluster_name)
            if len(response_services['serviceArns']) > 0:
                print(f"║   - ECS Cluster {cluster_name} is running")
            else:
                print(f"║   - ECS Cluster {cluster_name} has no running services")
        print("║ --------------------------------------------")
    except Exception as e:
        print(f"Error describing running ECS clusters: {str(e)}")

# Function to describe unused EBS volumes
def describe_unused_ebs_volumes(ec2_client):
    try:
        response = ec2_client.describe_volumes()
        print("║ Describe unused EBS volumes: ")
        for volume in response['Volumes']:
            if not volume['Attachments']:
                print(f"║   - Unused EBS Volume: {volume['VolumeId']}")
        print("║ --------------------------------------------")
    except Exception as e:
        print(f"Error describing unused EBS volumes: {str(e)}")

# Function to estimate instance cost
def estimate_instance_cost(ec2_client, instance_type):
    try:
        spot_prices = ec2_client.describe_spot_price_history(
            InstanceTypes=[instance_type],
            ProductDescriptions=['Linux/UNIX'],
            StartTime=datetime.utcnow() - timedelta(hours=1),
            EndTime=datetime.utcnow()
        )
        spot_price = float(spot_prices['SpotPriceHistory'][0]['SpotPrice'])
        estimated_cost = spot_price * HOURS_IN_MONTH
        print(f"║ Estimate instance cost: ")
        print(f"║   - Estimated monthly cost for instance {instance_type}: ${estimated_cost:.2f}")
        print("║ --------------------------------------------")
    except Exception as e:
        print(f"Error estimating instance cost: {str(e)}")

if __name__ == "__main__":
    # Get AWS credentials from user
    aws_access_key, aws_secret_key, aws_region = get_aws_credentials()  
    
    # Initialize AWS clients
    ec2_client, elbv2_client, cloudwatch_client, eks_client, ecs_client = initialize_aws_clients(aws_access_key, aws_secret_key, aws_region)

    while True:
        print("\nAWS Checkpoint Validate Options:")
        print("1. Describe running instances")
        print("2. List unused security groups")
        print("3. Check AMI encryption")
        print("4. Describe custom AMIs")
        print("5. Describe instances by state")
        print("6. Check instance attachment to ELB")
        print("7. Check EIP attachment")
        print("8. Check instance subnet type")
        print("9. Check EKS nodes health")
        print("10. Describe running ECS clusters")
        print("11. Describe unused EBS volumes")
        print("12. Estimate instance cost")
        print("13. Scan All")
        print("0. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            describe_running_instances(ec2_client)
        elif choice == "2":
            list_unused_security_groups(ec2_client)
        elif choice == "3":
            ami_id = input("Enter the AMI ID to check encryption status: ")
            check_ami_encryption(ec2_client, ami_id)
        elif choice == "4":
            list_custom_amis(ec2_client)
        elif choice == "5":
            state = input("Enter the instance state (e.g., running, stopped): ")
            get_instances_by_state(ec2_client, state)
        elif choice == "6":
            instance_id = input("Enter the instance ID to check attachment to ELB: ")
            is_instance_attached_to_elb(elbv2_client, instance_id)
        elif choice == "7":
            instance_id = input("Enter the instance ID to check EIP attachment: ")
            is_eip_attached(ec2_client, instance_id)
        elif choice == "8":
            instance_id = input("Enter the instance ID to check subnet type: ")
            is_instance_in_public_subnet(ec2_client, instance_id)
        elif choice == "9":
            cluster_name = input("Enter the Amazon EKS cluster name: ")
            check_eks_nodes_health(eks_client, cluster_name)
        elif choice == "10":
            describe_running_ecs_clusters(ecs_client)
        elif choice == "11":
            describe_unused_ebs_volumes(ec2_client)
        elif choice == "12":
            instance_type = input("Enter the instance type to estimate cost: ")
            estimate_instance_cost(ec2_client, instance_type)
        elif choice == "13":
            # Perform all checks
            describe_running_instances(ec2_client)
            list_unused_security_groups(ec2_client)
            ami_id = input("Enter the AMI ID to check encryption status: ")
            check_ami_encryption(ec2_client, ami_id)
            list_custom_amis(ec2_client)
            state = input("Enter the instance state (e.g., running, stopped): ")
            get_instances_by_state(ec2_client, state)
            instance_id = input("Enter the instance ID to check attachment to ELB: ")
            is_instance_attached_to_elb(elbv2_client, instance_id)
            instance_id = input("Enter the instance ID to check EIP attachment: ")
            is_eip_attached(ec2_client, instance_id)
            instance_id = input("Enter the instance ID to check subnet type: ")
            is_instance_in_public_subnet(ec2_client, instance_id)
            cluster_name = input("Enter the Amazon EKS cluster name: ")
            check_eks_nodes_health(eks_client, cluster_name)
            describe_running_ecs_clusters(ecs_client)
            describe_unused_ebs_volumes(ec2_client)
            instance_type = input("Enter the instance type to estimate cost: ")
            estimate_instance_cost(ec2_client, instance_type)
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please choose a valid option.")
