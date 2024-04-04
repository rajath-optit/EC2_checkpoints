Here's how the output looks like when choosing a specific option:

1. **Describe running instances**:
```
║ Describe running instances: 
║   - Instance ID: i-1234567890abcdef0
║   - Instance Type: t2.micro
║   - AMI ID: ami-12345678
║   - Tags: {'Name': 'MyInstance'}
║   - Uptime: 3 days
║ --------------------------------------------
```

2. **List unused security groups**:
```
║ Running command for region: us-east-1
║ Unused Security Groups in us-east-1: 
║   - sg-12345678
║ --------------------------------------------
```

3. **Check AMI encryption**:
```
║ Encryption Status for AMI ami-12345678: Encrypted
```

4. **Describe custom AMIs**:
```
║ Describe custom AMIs: 
║   - Custom AMI ID: ami-abcdef01
║     Creation Date: 2023-01-01T00:00:00Z
║ --------------------------------------------
```

5. **Describe instances by state**:
```
║ Describe instances by state running: 
║   - Instance ID: i-1234567890abcdef0
║ --------------------------------------------
```

6. **Check instance attachment to ELB**:
```
║ Instance i-1234567890abcdef0 is not attached to any ELB
```

7. **Check EIP attachment**:
```
║ Elastic IP is attached to Instance i-1234567890abcdef0
```

8. **Check instance subnet type**:
```
║ Instance i-1234567890abcdef0 is in a public subnet
```

9. **Check EKS nodes health**:
```
║ Nodes in EKS cluster MyCluster are healthy
```

10. **Describe running ECS clusters**:
```
║ Describe running ECS clusters: 
║   - ECS Cluster MyCluster is running
║ --------------------------------------------
```

11. **Describe unused EBS volumes**:
```
║ Describe unused EBS volumes: 
║   - Unused EBS Volume: vol-12345678
║ --------------------------------------------
```

12. **Estimate instance cost**:
```
║ Estimate instance cost: 
║   - Estimated monthly cost for instance t2.micro: $12.00
```

13. **Scan All**:
This will display the output for each individual option in sequence.
