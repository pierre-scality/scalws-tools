#!/usr/bin/env python3
import boto3
import argparse

# --- Parse Command-Line Arguments ---
parser = argparse.ArgumentParser(description="Script to list AWS EC2 resources.")
parser.add_argument('-r', '--region', help="AWS region to use (default: ap-northeast-1).")
parser.add_argument('-o', '--owner', help="Email of the instance owner to filter by.")
parser.add_argument('-n', '--network', action='store_true', help="Displays detailed network information (AZ, VPC, Subnets).")
parser.add_argument('-v', '--vpc', action='store_true', help="Searches for and displays VPCs containing 'scality' and their subnets.")
parser.add_argument('-d', '--disk', action='store_true', help="Displays disk information (size and type).")
args = parser.parse_args()

# --- Global Variables ---
AWS_REGION = args.region if args.region else 'ap-northeast-1'
TARGET_OWNER = args.owner if args.owner else 'pierre.merle@scality.com'

# Create an EC2 client using the global region variable
ec2 = boto3.client('ec2', region_name=AWS_REGION)

def get_tag_value(tags, key):
  """Helper function to extract a tag value from a list of tags."""
  if tags:
    for tag in tags:
      if tag['Key'] == key:
        return tag['Value']
  return 'N/A'

def format_output_table(data):
  """Dynamically calculates column widths and prints a formatted table."""
  if not data:
    return

  headers = list(data[0].keys())
  widths = {header: len(header) for header in headers}

  # First pass: Determine max width for each column
  for row in data:
    for header in headers:
      widths[header] = max(widths[header], len(str(row.get(header, ''))))

  # Print the header with aligned columns
  header_line = "  ".join([f"{header:<{widths[header]}}" for header in headers])
  print(header_line)

  # Second pass: Print the formatted data
  for row in data:
    row_parts = [f"{str(row.get(header, '')):<{widths[header]}}" for header in headers]
    print("  ".join(row_parts))

def list_instances_by_owner(owner_email, show_network_info, show_disk_info):
  """
  Retrieves data for EC2 instances belonging to a specific owner.
  """
  print(f"EC2 Instances owned by {owner_email} in region {AWS_REGION}:")
  instances_data = []
  
  try:
    response = ec2.describe_instances()
    
    found_instances = False
    for reservation in response['Reservations']:
      for instance in reservation['Instances']:
        owner = get_tag_value(instance.get('Tags'), 'owner')

        if owner == owner_email:
          found_instances = True
          
          # Get disk info regardless of flag, for dynamic formatting
          disk_info = []
          if 'BlockDeviceMappings' in instance:
            volume_ids = [bd['Ebs']['VolumeId'] for bd in instance['BlockDeviceMappings'] if 'Ebs' in bd]
            if volume_ids:
              volumes_response = ec2.describe_volumes(VolumeIds=volume_ids)
              volume_details = {vol['VolumeId']: f"{vol['Size']} GiB ({vol['VolumeType']})" for vol in volumes_response['Volumes']}
              disk_info = [volume_details.get(vol_id, "N/A") for vol_id in volume_ids]
          disks_str = ", ".join(disk_info) if disk_info else "N/A"

          # Build the instance dictionary based on the view flags
          if show_disk_info:
            instance_info = {
              'ID': instance['InstanceId'],
              'Name': get_tag_value(instance.get('Tags'), 'Name'),
              'Disks': disks_str
            }
          else:
            name = get_tag_value(instance.get('Tags'), 'Name')
            private_ips = []
            public_ips = []
            subnets_info = []
            if 'NetworkInterfaces' in instance:
              for interface in instance['NetworkInterfaces']:
                for ip_detail in interface.get('PrivateIpAddresses', []):
                  private_ips.append(ip_detail['PrivateIpAddress'])
                
                if 'Association' in interface and 'PublicIp' in interface['Association']:
                  public_ips.append(interface['Association']['PublicIp'])

                if show_network_info:
                  subnet_id = interface.get('SubnetId', 'N/A')
                  subnet_name = 'N/A'
                  if subnet_id != 'N/A':
                    subnet_response = ec2.describe_subnets(SubnetIds=[subnet_id])
                    if subnet_response['Subnets']:
                      subnet_name = get_tag_value(subnet_response['Subnets'][0].get('Tags'), 'Name')
                  
                  subnets_info.append(f"{subnet_name} ({subnet_id})")

            private_ips_str = ", ".join(private_ips) if private_ips else "N/A"
            public_ips_str = ", ".join(public_ips) if public_ips else "N/A"
            subnets_str = " | ".join(subnets_info)
            
            instance_info = {
              'ID': instance['InstanceId'],
              'Name': name,
              'State': instance['State']['Name'],
              'Private IPs': private_ips_str,
              'Public IPs': public_ips_str,
            }

            if show_network_info:
              availability_zone = instance['Placement']['AvailabilityZone']
              vpc_id = instance.get('VpcId', 'N/A')
              vpc_name = 'N/A'
              if vpc_id != 'N/A':
                vpc_response = ec2.describe_vpcs(VpcIds=[vpc_id])
                if vpc_response['Vpcs']:
                  vpc_name = get_tag_value(vpc_response['Vpcs'][0].get('Tags'), 'Name')
              
              instance_info.update({
                'AZ': availability_zone,
                'VPC': f"{vpc_name} ({vpc_id})",
                'Network': subnets_str
              })
          
          instances_data.append(instance_info)
    
    if not found_instances:
      print(f"No instances found for this owner in region {AWS_REGION}.")
    else:
      format_output_table(instances_data)

  except Exception as e:
    print(f"An error occurred: {e}")

def list_scality_vpcs_and_subnets():
  """
  Lists VPCs with 'scality' in their name and their subnets.
  """
  print(f"\nSearching for 'scality' VPCs in region {AWS_REGION}:")
  vpcs_data = []
  
  try:
    vpc_response = ec2.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': ['*scality*']}])
    
    if not vpc_response['Vpcs']:
      print("No VPCs containing 'scality' were found.")
      return

    for vpc in vpc_response['Vpcs']:
      vpc_id = vpc['VpcId']
      vpc_name = get_tag_value(vpc.get('Tags'), 'Name')
      
      subnets_data = []
      subnet_response = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
      if not subnet_response['Subnets']:
        subnets_data.append({'Name': 'N/A', 'ID': 'N/A'})
      else:
        for subnet in subnet_response['Subnets']:
          subnet_id = subnet['SubnetId']
          subnet_name = get_tag_value(subnet.get('Tags'), 'Name')
          subnets_data.append({'Name': subnet_name, 'ID': subnet_id})
      
      vpcs_data.append({
        'VPC Name': vpc_name,
        'VPC ID': vpc_id,
        'Subnets': subnets_data
      })
    
    for vpc_data in vpcs_data:
      print(f"\n- VPC: {vpc_data['VPC Name']} ({vpc_data['VPC ID']})")
      if vpc_data['Subnets'][0]['Name'] == 'N/A':
        print("  No subnets found.")
      else:
        format_output_table(vpcs_data['Subnets'])

  except Exception as e:
    print(f"An error occurred: {e}")

# --- Call functions with parsed arguments ---
if __name__ == "__main__":
  list_instances_by_owner(TARGET_OWNER, args.network, args.disk)
  
  if args.vpc:
    list_scality_vpcs_and_subnets()
