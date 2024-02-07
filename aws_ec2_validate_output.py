Enter your AWS Access Key: <Your_AWS_Access_Key>
Enter your AWS Secret Key: <Your_AWS_Secret_Key>
Enter your AWS Region: <Your_AWS_Region>
Enter the Instance ID: <Your_Instance_ID>


----- Describe Running Instances -----
Instance ID: i-1234567890abcdef0
Instance Type: t2.micro
AMI ID: ami-0123456789abcdef0
Tags: [{'Key': 'Name', 'Value': 'MyInstance'}]
------------------------------


----- Check AMI Encryption -----
Encryption Status for AMI ami-0123456789abcdef0: Encrypted


----- Describe Images Command -----
Latest Image ID: ami-0123456789abcdef0
Image Creation Date: 2024-02-02T12:34:56.789000+00:00
Image Tags: [{'Key': 'Name', 'Value': 'MyImage'}]


----- List Custom AMIs -----
Custom AMIs: [{'ImageId': 'ami-0123456789abcdef0', 'CreationDate': '2024-02-02T12:34:56.789000+00:00', 'Tags': [{'Key': 'Name', 'Value': 'MyImage'}]}]


----- AMI Identification -----
AMI ID for Instance i-1234567890abcdef0: ami-0123456789abcdef0


----- Get Instances by State (Running) -----
Enter the Instance ID: i-1234567890abcdef0
Instance ID: i-1234567890abcdef0
Instance Type: t2.micro
AMI ID: ami-0123456789abcdef0
Tags: [{'Key': 'Name', 'Value': 'MyInstance'}]
------------------------------


----- Attached to Elastic Load Balancer -----
----- Check Elastic IP Configuration -----
Elastic IP Attached: Yes


----- Elastic IP Association Check -----
Elastic IP Associated: Yes


----- Public DNS Check -----
Public DNS for Instance i-1234567890abcdef0: ec2-xxx-xxx-xxx-xxx.compute-1.amazonaws.com


----- EKS Nodes Health Check -----
Node Group Status: ACTIVE
Node ID: i-0123456789abcdef0, Health Status: HEALTHY


----- Describe Running EKS Clusters -----
EKS Cluster Name: your-eks-cluster-name
EKS Cluster Version: 1.21
EKS Cluster Node IAM Role: arn:aws:iam::123456789012:role/your-node-role


----- Describe Running ECS Clusters -----
ECS Cluster ARN: arn:aws:ecs:your-region:123456789012:cluster/your-ecs-cluster
----- Cluster Instances -----
Instance ID: i-0123456789abcdef0
Status: ACTIVE
------------------------------
----- Cluster Services -----
Service Name: your-ecs-service
Desired Tasks: 2
Running Tasks: 2
------------------------------


----- Describe EBS Volumes -----
EBS Volume ID: vol-0123456789abcdef0
Size: 50 GB
Status: in-use
----- Volume Attachments -----
Instance ID: i-1234567890abcdef0
Device: /dev/sdf
Attachment State: attached
------------------------------
----- Volume Encryption -----
Encryption Status: Encrypted
------------------------------


----- Cost Monitoring -----
Estimated Cost per Hour for Instance i-1234567890abcdef0 (t2.micro): 0.011
Estimated Monthly Cost: 7.92
Compute Cost: 7.92
Storage Cost: 0


----- Check EBS Snapshots Older Than 30 Days -----
Snapshot ID: snap-0123456789abcdef0
Volume ID: vol-0123456789abcdef0
Snapshot Age: 35 days
Instance ID: i-1234567890abcdef0
Volume Name: MyInstance
Volume Size: 50 GB
Volume Type: gp2
Consider reviewing and deleting if necessary.
------------------------------


Choose an action:
1. List Unused Security Groups
2. Check EBS Snapshots Older Than 30 Days
3. Describe EBS Volumes
4. Quit
Enter your choice: 1


Running command for region: your-aws-region
---find unused resources of EC2---
Instances Information:
Instance ID: i-1234567890abcdef0
State: running
Unused Security Groups in your-aws-region: ['sg-0123456789abcdef0']
 
