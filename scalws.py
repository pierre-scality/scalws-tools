#!/usr/bin/env python3
import boto3
import argparse

DEFAULT_REGION = 'ap-northeast-1'
DEFAULT_OWNER = 'pierre.merle@scality.com'

class OutputFormatter:
    """Handles formatting and printing data to the console."""
    @staticmethod
    def format_output_table(data):
        """Dynamically calculates column widths and prints a formatted table."""
        if not data:
            return

        headers = list(data[0].keys())
        widths = {header: len(header) for header in headers}

        for row in data:
            for header in headers:
                widths[header] = max(widths[header], len(str(row.get(header, ''))))

        header_line = "  ".join([f"{header:<{widths[header]}}" for header in headers])
        print(header_line)

        for row in data:
            row_parts = [f"{str(row.get(header, '')):<{widths[header]}}" for header in headers]
            print("  ".join(row_parts))

class AWSManager:
    """Manages all interactions with the AWS API."""
    def __init__(self, region, owner=None):
        self.region = region
        self.owner = owner
        self.ec2 = boto3.client('ec2', region_name=self.region)

    def _get_tag_value(self, tags, key):
        """Helper function to extract a tag value from a list of tags."""
        if tags:
            for tag in tags:
                if tag['Key'] == key:
                    return tag['Value']
        return 'N/A'

    def _get_disk_details(self, instance):
        """Gathers disk information for a given instance."""
        disk_info = []
        if 'BlockDeviceMappings' in instance:
            volume_ids = [bd['Ebs']['VolumeId'] for bd in instance['BlockDeviceMappings'] if 'Ebs' in bd]
            if volume_ids:
                volumes_response = self.ec2.describe_volumes(VolumeIds=volume_ids)
                volume_details = {vol['VolumeId']: f"{vol['Size']} GiB ({vol['VolumeType']})" for vol in volumes_response['Volumes']}
                disk_info = [volume_details.get(vol_id, "N/A") for vol_id in volume_ids]
        return ", ".join(disk_info) if disk_info else "N/A"

    def _get_private_ips(self, instance):
        """Gathers private IP addresses for a given instance."""
        private_ips = []
        if 'NetworkInterfaces' in instance:
            for interface in instance['NetworkInterfaces']:
                for ip_detail in interface.get('PrivateIpAddresses', []):
                    private_ips.append(ip_detail['PrivateIpAddress'])
        return private_ips

    def _get_public_ips(self, instance):
        """Gathers public IP addresses for a given instance."""
        public_ips = []
        if 'NetworkInterfaces' in instance:
            for interface in instance['NetworkInterfaces']:
                if 'Association' in interface and 'PublicIp' in interface['Association']:
                    public_ips.append(interface['Association']['PublicIp'])
        return public_ips

    def _get_vpc_details(self, instance):
        """Gathers VPC information for a given instance."""
        vpc_id = instance.get('VpcId', 'N/A')
        if vpc_id != 'N/A':
            vpc_response = self.ec2.describe_vpcs(VpcIds=[vpc_id])
            if vpc_response['Vpcs']:
                vpc_name = self._get_tag_value(vpc_response['Vpcs'][0].get('Tags'), 'Name')
                return vpc_name
        return 'N/A'

    def _get_subnet_details(self, instance):
        """Gathers subnet information for a given instance."""
        subnets_info = []
        if 'NetworkInterfaces' in instance:
            for interface in instance.get('NetworkInterfaces', []):
                subnet_id = interface.get('SubnetId', 'N/A')
                if subnet_id != 'N/A':
                    subnet_response = self.ec2.describe_subnets(SubnetIds=[subnet_id])
                    if subnet_response['Subnets']:
                        subnet_name = self._get_tag_value(subnet_response['Subnets'][0].get('Tags'), 'Name')
                        subnets_info.append(subnet_name)
                    else:
                        subnets_info.append('N/A')
                else:
                    subnets_info.append('N/A')
        return subnets_info

    def get_instances_by_owner(self, show_network_info, show_disk_info):
        """Retrieves data for EC2 instances by orchestrating helper methods."""
        instances_data = []
        try:
            response = self.ec2.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if self._get_tag_value(instance.get('Tags'), 'owner') != self.owner:
                        continue

                    instance_name = self._get_tag_value(instance.get('Tags'), 'Name')
                    instance_id = instance['InstanceId']

                    if show_disk_info:
                        instance_info = {
                            'Name': instance_name,
                            'Disks': self._get_disk_details(instance)
                        }
                    else:
                        private_ips = self._get_private_ips(instance)
                        public_ips = self._get_public_ips(instance)
                        instance_info = {
                            'ID': instance_id,
                            'Name': instance_name,
                            'State': instance['State']['Name'],
                            'Private IPs': ", ".join(private_ips) if private_ips else "N/A",
                            'Public IPs': ", ".join(public_ips) if public_ips else "N/A",
                        }
                        if show_network_info:
                            instance_info.update({
                                'AZ': instance['Placement']['AvailabilityZone'],
                                'VPC': self._get_vpc_details(instance),
                                'Network': ", ".join(self._get_subnet_details(instance))
                            })
                            del instance_info['State']
                            del instance_info['ID']
                    instances_data.append(instance_info)
            return instances_data
        except Exception as e:
            print(f"An error occurred while fetching instances: {e}")
            return []

    def get_scality_vpcs_and_subnets(self):
        """Lists VPCs with 'scality' in their name and their subnets."""
        vpcs_data = []
        try:
            vpc_response = self.ec2.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': ['*scality*']}])
            
            if not vpc_response['Vpcs']:
                return []

            for vpc in vpc_response['Vpcs']:
                vpc_id = vpc['VpcId']
                vpc_name = self._get_tag_value(vpc.get('Tags'), 'Name')
                
                subnets_data = []
                subnet_response = self.ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                if not subnet_response['Subnets']:
                    subnets_data.append({'Name': 'N/A', 'ID': 'N/A'})
                else:
                    for subnet in subnet_response['Subnets']:
                        subnet_id = subnet['SubnetId']
                        subnet_name = self._get_tag_value(subnet.get('Tags'), 'Name')
                        subnets_data.append({'Name': subnet_name, 'ID': subnet_id})
                
                vpcs_data.append({
                    'VPC Name': vpc_name,
                    'VPC ID': vpc_id,
                    'Subnets': subnets_data
                })
            return vpcs_data
        except Exception as e:
            print(f"An error occurred while fetching VPCs: {e}")
            return []

    def get_network_interfaces_by_owner(self):
        """Retrieves network interfaces for a given owner."""
        try:
            # First, find instances belonging to the owner
            instances_response = self.ec2.describe_instances(
                Filters=[{'Name': 'tag:owner', 'Values': [self.owner]}]
            )
            instance_ids = []
            for reservation in instances_response['Reservations']:
                for instance in reservation['Instances']:
                    instance_ids.append(instance['InstanceId'])

            if not instance_ids:
                return []

            # Then, find network interfaces attached to those instances
            ni_response = self.ec2.describe_network_interfaces(
                Filters=[{'Name': 'attachment.instance-id', 'Values': instance_ids}]
            )

            if not ni_response['NetworkInterfaces']:
                return []

            # Collect all subnet and vpc IDs to fetch their names in batches
            subnet_ids = {ni.get('SubnetId') for ni in ni_response['NetworkInterfaces'] if ni.get('SubnetId')}
            vpc_ids = {ni.get('VpcId') for ni in ni_response['NetworkInterfaces'] if ni.get('VpcId')}

            subnet_name_map = {}
            if subnet_ids:
                subnet_response = self.ec2.describe_subnets(SubnetIds=list(subnet_ids))
                for subnet in subnet_response['Subnets']:
                    subnet_name_map[subnet['SubnetId']] = self._get_tag_value(subnet.get('Tags'), 'Name')

            vpc_name_map = {}
            if vpc_ids:
                vpc_response = self.ec2.describe_vpcs(VpcIds=list(vpc_ids))
                for vpc in vpc_response['Vpcs']:
                    vpc_name_map[vpc['VpcId']] = self._get_tag_value(vpc.get('Tags'), 'Name')

            interfaces_data = []
            for ni in ni_response['NetworkInterfaces']:
                attachment = ni.get('Attachment', {})
                subnet_id = ni.get('SubnetId', 'N/A')
                vpc_id = ni.get('VpcId', 'N/A')
                
                interfaces_data.append({
                    'ID': ni['NetworkInterfaceId'],
                    'Subnet': subnet_name_map.get(subnet_id, subnet_id),
                    'VPC': vpc_name_map.get(vpc_id, vpc_id),
                    'Status': ni['Status'],
                    'Private IP': ni.get('PrivateIpAddress', 'N/A'),
                    'Public IP': ni.get('Association', {}).get('PublicIp', 'N/A'),
                    'Instance': attachment.get('InstanceId', 'N/A')
                })
            return interfaces_data
        except Exception as e:
            print(f"An error occurred while fetching network interfaces: {e}")
            return []

    def get_unattached_disks(self):
        """Retrieves all unattached EBS volumes, filtering by owner tag."""
        disks_data = []
        try:
            # We can filter by 'available' state and owner tag directly in the API call
            response = self.ec2.describe_volumes(
                Filters=[
                    {'Name': 'status', 'Values': ['available']},
                    {'Name': 'tag:owner', 'Values': [self.owner]}
                ]
            )
            for volume in response['Volumes']:
                disks_data.append({
                    'Name': self._get_tag_value(volume.get('Tags'), 'Name'),
                    'Size': f"{volume['Size']} GiB",
                    'Type': volume['VolumeType'],
                })
            return disks_data
        except Exception as e:
            print(f"An error occurred while fetching unattached volumes: {e}")
            return []

    def attach_volumes_to_instance(self, vm_name):
        """Attaches volumes matching a pattern to a specific instance."""
        try:
            # Find the instance ID from the VM name
            instance_response = self.ec2.describe_instances(
                Filters=[
                    {'Name': 'tag:Name', 'Values': [vm_name]},
                    {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
                ]
            )
            if not instance_response['Reservations'] or not instance_response['Reservations'][0]['Instances']:
                print(f"No instance found with name '{vm_name}'.")
                return
            
            instance = instance_response['Reservations'][0]['Instances'][0]
            instance_id = instance['InstanceId']
            print(f"Found instance '{vm_name}' with ID '{instance_id}'.")

            disk_name_pattern = f"{vm_name}-disk-*"
            # Find available volumes matching the owner and name pattern
            response = self.ec2.describe_volumes(
                Filters=[
                    {'Name': 'status', 'Values': ['available']},
                    {'Name': 'tag:owner', 'Values': [self.owner]},
                    {'Name': 'tag:Name', 'Values': [disk_name_pattern]}
                ]
            )

            volumes_to_attach = response['Volumes']
            if not volumes_to_attach:
                print(f"No available volumes found with pattern '{disk_name_pattern}' for owner {self.owner}.")
                return

            print(f"Found {len(volumes_to_attach)} volumes to attach.")
            # Get instance details to find out attached devices
            attached_devices = [bd['DeviceName'] for bd in instance.get('BlockDeviceMappings', [])]

            # Determine the next available device name
            device_letters = 'fghijklmnopqrstuvwxyz'
            device_index = 0
            
            for volume in volumes_to_attach:
                while True:
                    device_name = f'/dev/sd{device_letters[device_index]}'
                    if device_name not in attached_devices:
                        break
                    device_index += 1
                    if device_index >= len(device_letters):
                        print("No available device names to attach volumes.")
                        return

                volume_id = volume['VolumeId']
                volume_name = self._get_tag_value(volume.get('Tags'), 'Name')
                print(f"Attaching {volume_name} ({volume_id}) to {vm_name} ({instance_id}) as {device_name}...")
                self.ec2.attach_volume(
                    VolumeId=volume_id,
                    InstanceId=instance_id,
                    Device=device_name
                )
                attached_devices.append(device_name)
                
                # Wait for the volume to be attached
                waiter = self.ec2.get_waiter('volume_in_use')
                waiter.wait(VolumeIds=[volume_id])
                print(f"Successfully attached {volume_id}.")

        except Exception as e:
            print(f"An error occurred: {e}")

def _do_instances(manager, formatter, args):
    print(f"EC2 Instances owned by {manager.owner} in region {manager.region}:")
    instances = manager.get_instances_by_owner(show_network_info=False, show_disk_info=False)
    if not instances:
        print(f"No instances found for this owner in region {manager.region}.")
    else:
        formatter.format_output_table(instances)

def _do_network(manager, formatter, args):
    print(f"EC2 Instances (Network View) for {manager.owner} in region {manager.region}:")
    instances = manager.get_instances_by_owner(show_network_info=True, show_disk_info=False)
    if not instances:
        print(f"No instances found for this owner in region {manager.region}.")
    else:
        formatter.format_output_table(instances)

def _do_disk(manager, formatter, args):
    if args.disk_command == 'list':
        print(f"EC2 Instances (Disk View) for {manager.owner} in region {manager.region}:")
        instances = manager.get_instances_by_owner(show_network_info=False, show_disk_info=True)
        if not instances:
            print(f"No instances found for this owner in region {manager.region}.")
        else:
            formatter.format_output_table(instances)
    elif args.disk_command == 'attach':
        manager.attach_volumes_to_instance(args.vm_name)

def _do_vpc(manager, formatter, args):
    print(f"Searching for 'scality' VPCs in region {manager.region}:")
    vpcs = manager.get_scality_vpcs_and_subnets()
    if not vpcs:
        print("No VPCs containing 'scality' were found.")
    else:
        for vpc_data in vpcs:
            print(f"\n- VPC: {vpc_data['VPC Name']} ({vpc_data['VPC ID']})")
            subnets = vpc_data['Subnets']
            if subnets and subnets[0]['Name'] == 'N/A':
                print("  No subnets found.")
            elif subnets:
                formatter.format_output_table(subnets)


def _do_interface(manager, formatter, args):
    print(f"Network Interfaces for {manager.owner} in region {manager.region}:")
    interfaces = manager.get_network_interfaces_by_owner()
    if not interfaces:
        print(f"No network interfaces found for this owner in region {manager.region}.")
    else:
        formatter.format_output_table(interfaces)

def _do_newdisk(manager, formatter, args):
    print(f"Unattached Disks for {manager.owner} in region {manager.region}:")
    disks = manager.get_unattached_disks()
    if not disks:
        print(f"No unattached disks found for this owner in region {manager.region}.")
    else:
        formatter.format_output_table(disks)

def main():
    """Main function to parse arguments and run the script."""
    parser = argparse.ArgumentParser(description="Script to list AWS EC2 resources.")
    parser.add_argument('-r', '--region', help="AWS region to use (default: ap-northeast-1).")

    subparsers = parser.add_subparsers(dest='command', help='Sub-command help')
    subparsers.required = True

    # Sub-parser for "instances"
    instances_parser = subparsers.add_parser('instances', help='List EC2 instances with basic info.')
    instances_parser.add_argument('-o', '--owner', help="Email of the instance owner to filter by.")

    # Sub-parser for "network"
    network_parser = subparsers.add_parser('network', help='List instances with detailed network info.')
    network_parser.add_argument('-o', '--owner', help="Email of the instance owner to filter by.")

    # Sub-parser for "disk"
    disk_parser = subparsers.add_parser('disk', help='Disk related commands.')
    disk_subparsers = disk_parser.add_subparsers(dest='disk_command', help='Disk sub-command help')
    disk_subparsers.required = True

    disk_list_parser = disk_subparsers.add_parser('list', help='List instances with disk info.')
    disk_list_parser.add_argument('-o', '--owner', help="Email of the instance owner to filter by.")

    disk_attach_parser = disk_subparsers.add_parser('attach', help='Attach volumes to an instance.')
    disk_attach_parser.add_argument('vm_name', help="Name of the VM to attach disks to.")
    disk_attach_parser.add_argument('-o', '--owner', help="Email of the disk owner to filter by.")


    # Sub-parser for "vpc"
    vpc_parser = subparsers.add_parser('vpc', help='List Scality VPCs and their subnets.')

    # Sub-parser for "interface"
    interface_parser = subparsers.add_parser('interface', help='List network interfaces.')
    interface_parser.add_argument('-o', '--owner', help="Email of the instance owner to filter by.")

    # Sub-parser for "newdisk"
    newdisk_parser = subparsers.add_parser('newdisk', help='List unattached disks owned by a user.')
    newdisk_parser.add_argument('-o', '--owner', help="Email of the disk owner to filter by.")

    args = parser.parse_args()

    aws_region = args.region or DEFAULT_REGION
    
    # Determine owner, with a default
    owner = getattr(args, 'owner', None) or DEFAULT_OWNER

    # Initialize manager with region and owner
    manager = AWSManager(region=aws_region, owner=owner)
    formatter = OutputFormatter()

    # Command dispatcher
    command_map = {
        'instances': _do_instances,
        'network': _do_network,
        'disk': _do_disk,
        'vpc': _do_vpc,
        'interface': _do_interface,
        'newdisk': _do_newdisk,
    }
    
    # Execute command
    command_func = command_map.get(args.command)
    if command_func:
        command_func(manager, formatter, args)

if __name__ == "__main__":
    main()
