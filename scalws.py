#!/usr/bin/env python3
import argparse
import sys
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

DEFAULT_REGION = 'ap-northeast-1'
DEFAULT_OWNER = 'pierre.merle@scality.com'

class Display:
    """Handles formatting and printing data to the console."""
    def __init__(self, level='SILENT'):
        self.level = level
        self.levels = {'DEBUG': 3, 'VERBOSE': 2, 'INFO': 1, 'SILENT': 0}

    def display(self, message, level='INFO'):
        if level == 'QUERY':
            print(f"QUERY: {message}", end='')
            return
        
        if self.levels.get(self.level, 0) >= self.levels.get(level, 1):
            print(f"{level}: {message}")

    def query(self, message):
        self.display(message, level='QUERY')
        return input()

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

    def __init__(self, region, display, owner=None):
        self.region = region
        self.owner = owner
        self.display = display
        try:
            self.ec2 = boto3.client('ec2', region_name=self.region)
            self.ec2.describe_regions()
        except (NoCredentialsError, PartialCredentialsError):
            self.display.display("Authentication Error: AWS credentials not found or incomplete.", level='INFO')
            sys.exit(1)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':
                self.display.display("Authentication Error: The provided AWS credentials could not be validated.", level='INFO')
                sys.exit(1)
            else:
                self.display.display(f"An AWS service error occurred: {e}", level='INFO')
                sys.exit(1)

    def _get_tag_value(self, tags, key):
        """Helper function to extract a tag value from a list of tags."""
        if tags:
            for tag in tags:
                if tag['Key'] == key:
                    return tag['Value']
        return 'N/A'

    def create_disks(self, pattern, start, end, size, vol_type, availability_zone, owner):
        """Creates EBS volumes after checking for existing ones and asking for confirmation."""
        target_names = [f"{pattern}{i}" for i in range(start, end + 1)]

        try:
            response = self.ec2.describe_volumes(Filters=[{'Name': 'tag:owner', 'Values': [owner]}])
            existing_names = {self._get_tag_value(vol.get('Tags'), 'Name') for vol in response['Volumes']}
        except ClientError as e:
            self.display.display(f"An AWS service error occurred: {e}", level='INFO')
            sys.exit(1)

        conflicts = [name for name in target_names if name in existing_names]
        if conflicts:
            self.display.display(f"Error: The following disks already exist for owner {owner}:", level='INFO')
            for name in conflicts:
                self.display.display(f"- {name}", level='INFO')
            self.display.display("No disks will be created.", level='INFO')
            sys.exit(1)

        self.display.display("The following resources will be created:", level='INFO')
        disks_to_create = [{'Name': name, 'Size': f"{size} GiB", 'Type': vol_type, 'Owner': owner, 'Region': self.region, 'AZ': availability_zone} for name in target_names]
        Display.format_output_table(disks_to_create)
        
        try:
            confirm = self.display.query("\nDo you want to proceed with creation? (y/n): ")
        except KeyboardInterrupt:
            self.display.display("\nOperation cancelled by user.", level='INFO')
            sys.exit(1)
            
        if confirm.lower() != 'y':
            self.display.display("Operation cancelled by user.", level='INFO')
            sys.exit(0)

        self.display.display("User confirmed. Proceeding with disk creation...", level='VERBOSE')
        for name in target_names:
            try:
                self.display.display(f"Creating disk '{name}'...", level='VERBOSE')
                self.ec2.create_volume(
                    Size=size, VolumeType=vol_type, AvailabilityZone=availability_zone,
                    TagSpecifications=[{'ResourceType': 'volume', 'Tags': [{'Key': 'Name', 'Value': name}, {'Key': 'owner', 'Value': owner}]}]
                )
                self.display.display(f"Successfully initiated creation for disk '{name}'.", level='VERBOSE')
            except ClientError as e:
                self.display.display(f"An AWS error occurred while creating disk '{name}': {e}", level='INFO')
                self.display.display("Stopping due to error.", level='INFO')
                sys.exit(1)
        
        self.display.display(f"Successfully initiated creation for {len(target_names)} disks.", level='INFO')

    def delete_disks(self, pattern, numbers, owner):
        """Deletes EBS volumes after confirmation."""
        disks_to_delete = []
        try:
            paginator = self.ec2.get_paginator('describe_volumes')
            pages = paginator.paginate(Filters=[{'Name': 'tag:owner', 'Values': [owner]}])
            all_volumes = [vol for page in pages for vol in page['Volumes']]

            if not numbers:
                target_names = {self._get_tag_value(vol.get('Tags'), 'Name') for vol in all_volumes if self._get_tag_value(vol.get('Tags'), 'Name').startswith(pattern)}
            else:
                target_names = {f"{pattern}{n}" for n in numbers}

            disks_to_delete = [vol for vol in all_volumes if self._get_tag_value(vol.get('Tags'), 'Name') in target_names]

        except ClientError as e:
            self.display.display(f"An AWS service error occurred: {e}", level='INFO')
            sys.exit(1)

        if not disks_to_delete:
            self.display.display("No matching disks found to delete.", level='INFO')
            return

        self.display.display("The following disks will be DELETED:", level='INFO')
        delete_summary = [{'ID': vol['VolumeId'], 'Name': self._get_tag_value(vol.get('Tags'), 'Name'), 'Size': f"{vol['Size']} GiB", 'State': vol['State'], 'AZ': vol['AvailabilityZone']} for vol in disks_to_delete]
        Display.format_output_table(delete_summary)

        try:
            confirm = self.display.query("\nDo you want to proceed with deletion? (y/n): ")
        except KeyboardInterrupt:
            self.display.display("\nOperation cancelled by user.", level='INFO')
            sys.exit(1)
        
        if confirm.lower() != 'y':
            self.display.display("Operation cancelled by user.", level='INFO')
            sys.exit(0)

        self.display.display("User confirmed. Proceeding with disk deletion...", level='VERBOSE')
        for vol in disks_to_delete:
            vol_id = vol['VolumeId']
            vol_name = self._get_tag_value(vol.get('Tags'), 'Name')
            try:
                self.display.display(f"Deleting disk '{vol_name}' ({vol_id})...", level='VERBOSE')
                self.ec2.delete_volume(VolumeId=vol_id)
                self.display.display(f"Successfully initiated deletion for disk '{vol_name}'.", level='VERBOSE')
            except ClientError as e:
                if e.response['Error']['Code'] == 'VolumeInUse':
                    self.display.display(f"Error: Disk '{vol_name}' ({vol_id}) is currently in use and cannot be deleted.", level='INFO')
                else:
                    self.display.display(f"An AWS error occurred while deleting disk '{vol_name}': {e}", level='INFO')
                self.display.display("Stopping due to error.", level='INFO')
                sys.exit(1)
        
        self.display.display(f"Successfully initiated deletion for {len(disks_to_delete)} disks.", level='INFO')

    def list_disks(self, owner):
        """Lists all EBS volumes for a given owner, sorted by instance name."""
        self.display.display(f"Listing disks for owner: {owner} in region: {self.region}", level='VERBOSE')
        try:
            paginator = self.ec2.get_paginator('describe_volumes')
            pages = paginator.paginate(Filters=[{'Name': 'tag:owner', 'Values': [owner]}])
            all_volumes = [vol for page in pages for vol in page['Volumes']]

            if not all_volumes:
                self.display.display("No disks found for this owner.", level='INFO')
                return

            instance_ids = [vol['Attachments'][0]['InstanceId'] for vol in all_volumes if vol.get('Attachments')]
            instance_name_map = {}
            if instance_ids:
                instance_response = self.ec2.describe_instances(InstanceIds=instance_ids)
                for reservation in instance_response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_name_map[instance['InstanceId']] = self._get_tag_value(instance.get('Tags'), 'Name') or 'N/A'

            disk_summary = []
            for vol in all_volumes:
                instance_name = 'Unattached'
                if vol.get('Attachments'):
                    instance_id = vol['Attachments'][0]['InstanceId']
                    instance_name = instance_name_map.get(instance_id, instance_id)
                
                disk_summary.append({'Instance Name': instance_name, 'Name': self._get_tag_value(vol.get('Tags'), 'Name'), 'ID': vol['VolumeId'], 'Size': f"{vol['Size']} GiB"})

            disk_summary.sort(key=lambda x: x['Instance Name'])
            Display.format_output_table(disk_summary)

        except ClientError as e:
            self.display.display(f"An AWS service error occurred: {e}", level='INFO')
            sys.exit(1)

    def get_instances_by_owner(self, show_network_info, show_disk_info):
        """Retrieves data for EC2 instances by orchestrating helper methods."""
        instances_data = []
        try:
            response = self.ec2.describe_instances(Filters=[{'Name': 'tag:owner', 'Values': [self.owner]}])
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_name = self._get_tag_value(instance.get('Tags'), 'Name')
                    autostop = self._get_tag_value(instance.get('Tags'), 'lifecycle_autostop')
                    instance_id = instance['InstanceId']

                    if show_disk_info:
                        instance_info = {'Name': instance_name, 'Disks': self._get_disk_details(instance)}
                    else:
                        private_ips = self._get_private_ips(instance)
                        public_ips = self._get_public_ips(instance)
                        instance_info = {
                            'ID': instance_id, 
                            'Name': instance_name, 
                            'Autostop': autostop,
                            'State': instance['State']['Name'], 
                            'Private IPs': ", ".join(private_ips) if private_ips else "N/A", 
                            'Public IPs': ", ".join(public_ips) if public_ips else "N/A"
                        }
                        if show_network_info:
                            instance_info.update({'AZ': instance['Placement']['AvailabilityZone'], 'VPC': self._get_vpc_details(instance), 'Network': ", ".join(self._get_subnet_details(instance))})
                            del instance_info['State']
                            del instance_info['ID']
                    instances_data.append(instance_info)
            
            instances_data.sort(key=lambda x: x['Name'])
            return instances_data
        except Exception as e:
            self.display.display(f"An error occurred while fetching instances: {e}", level='INFO')
            return []
    
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
                    subnets_data = [{'Name': self._get_tag_value(subnet.get('Tags'), 'Name'), 'ID': subnet['SubnetId']} for subnet in subnet_response['Subnets']]
                
                vpcs_data.append({'VPC Name': vpc_name, 'VPC ID': vpc_id, 'Subnets': subnets_data})
            return vpcs_data
        except Exception as e:
            self.display.display(f"An error occurred while fetching VPCs: {e}", level='INFO')
            return []

    def get_network_interfaces_by_owner(self):
        """Retrieves network interfaces for a given owner."""
        try:
            instances_response = self.ec2.describe_instances(Filters=[{'Name': 'tag:owner', 'Values': [self.owner]}])
            instance_ids = [instance['InstanceId'] for reservation in instances_response['Reservations'] for instance in reservation['Instances']]

            if not instance_ids:
                return []

            ni_response = self.ec2.describe_network_interfaces(Filters=[{'Name': 'attachment.instance-id', 'Values': instance_ids}])
            if not ni_response['NetworkInterfaces']:
                return []

            subnet_ids = {ni.get('SubnetId') for ni in ni_response['NetworkInterfaces'] if ni.get('SubnetId')}
            vpc_ids = {ni.get('VpcId') for ni in ni_response['NetworkInterfaces'] if ni.get('VpcId')}

            subnet_name_map = {subnet['SubnetId']: self._get_tag_value(subnet.get('Tags'), 'Name') for subnet in self.ec2.describe_subnets(SubnetIds=list(subnet_ids))['Subnets']} if subnet_ids else {}
            vpc_name_map = {vpc['VpcId']: self._get_tag_value(vpc.get('Tags'), 'Name') for vpc in self.ec2.describe_vpcs(VpcIds=list(vpc_ids))['Vpcs']} if vpc_ids else {}

            interfaces_data = []
            for ni in ni_response['NetworkInterfaces']:
                attachment = ni.get('Attachment', {})
                interfaces_data.append({'ID': ni['NetworkInterfaceId'], 'Subnet': subnet_name_map.get(ni.get('SubnetId', 'N/A'), ni.get('SubnetId', 'N/A')), 'VPC': vpc_name_map.get(ni.get('VpcId', 'N/A'), ni.get('VpcId', 'N/A')), 'Status': ni['Status'], 'Private IP': ni.get('PrivateIpAddress', 'N/A'), 'Public IP': ni.get('Association', {}).get('PublicIp', 'N/A'), 'Instance': attachment.get('InstanceId', 'N/A')})
            return interfaces_data
        except Exception as e:
            self.display.display(f"An error occurred while fetching network interfaces: {e}", level='INFO')
            return []

    def get_unattached_disks(self):
        """Retrieves all unattached EBS volumes, filtering by owner tag."""
        disks_data = []
        try:
            response = self.ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}, {'Name': 'tag:owner', 'Values': [self.owner]}])
            for volume in response['Volumes']:
                disks_data.append({'Name': self._get_tag_value(volume.get('Tags'), 'Name'), 'Size': f"{volume['Size']} GiB", 'Type': volume['VolumeType']})
            return disks_data
        except Exception as e:
            self.display.display(f"An error occurred while fetching unattached volumes: {e}", level='INFO')
            return []

    def attach_volumes_to_instance(self, vm_name):
        """Attaches volumes matching a pattern to a specific instance."""
        try:
            instance_response = self.ec2.describe_instances(Filters=[{'Name': 'tag:Name', 'Values': [vm_name]}, {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}])
            if not instance_response['Reservations'] or not instance_response['Reservations'][0]['Instances']:
                self.display.display(f"No instance found with name '{vm_name}'.", level='INFO')
                return
            
            instance = instance_response['Reservations'][0]['Instances'][0]
            instance_id = instance['InstanceId']
            self.display.display(f"Found instance '{vm_name}' with ID '{instance_id}'.", level='VERBOSE')

            disk_name_pattern = f"{vm_name}-disk-*"
            response = self.ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}, {'Name': 'tag:owner', 'Values': [self.owner]}, {'Name': 'tag:Name', 'Values': [disk_name_pattern]}])
            volumes_to_attach = response['Volumes']
            if not volumes_to_attach:
                self.display.display(f"No available volumes found with pattern '{disk_name_pattern}' for owner {self.owner}.", level='INFO')
                return

            self.display.display(f"Found {len(volumes_to_attach)} volumes to attach.", level='VERBOSE')
            attached_devices = [bd['DeviceName'] for bd in instance.get('BlockDeviceMappings', [])]
            device_letters = 'fghijklmnopqrstuvwxyz'
            device_index = 0
            
            for volume in volumes_to_attach:
                while True:
                    device_name = f'/dev/sd{device_letters[device_index]}'
                    if device_name not in attached_devices:
                        break
                    device_index += 1
                    if device_index >= len(device_letters):
                        self.display.display("No available device names to attach volumes.", level='INFO')
                        return

                volume_id = volume['VolumeId']
                volume_name = self._get_tag_value(volume.get('Tags'), 'Name')
                self.display.display(f"Attaching {volume_name} ({volume_id}) to {vm_name} ({instance_id}) as {device_name}...", level='VERBOSE')
                self.ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device=device_name)
                attached_devices.append(device_name)
                waiter = self.ec2.get_waiter('volume_in_use')
                waiter.wait(VolumeIds=[volume_id])
                self.display.display(f"Successfully attached {volume_id}.", level='VERBOSE')

        except Exception as e:
            self.display.display(f"An error occurred: {e}", level='INFO')

class Main:
    def __init__(self):
        self.parser = self._create_parser()

    def _create_parser(self):
        parser = argparse.ArgumentParser(description="Script to manage AWS resources.")
        parser.add_argument('-r', '--region', help=f"AWS region to use (default: {DEFAULT_REGION}).")
        parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output.")
        parser.add_argument('-d', '--debug', action='store_true', help="Enable debug output.")

        subparsers = parser.add_subparsers(dest='command', help='Sub-command help')

        instances_parser = subparsers.add_parser('instances', help='List EC2 instances with basic info.')
        instances_parser.add_argument('-o', '--owner', help="Email of the instance owner to filter by.")

        network_parser = subparsers.add_parser('network', help='List instances with detailed network info.')
        network_parser.add_argument('-o', '--owner', help="Email of the instance owner to filter by.")

        disk_parser = subparsers.add_parser('disk', help='Disk related commands.')
        disk_subparsers = disk_parser.add_subparsers(dest='disk_command', help='Disk sub-command help', required=True)

        disk_list_parser = disk_subparsers.add_parser('list', help='List all disks.')
        disk_list_parser.add_argument('-o', '--owner', help="Email of the disk owner to filter by.")

        disk_attach_parser = disk_subparsers.add_parser('attach', help='Attach volumes to an instance.')
        disk_attach_parser.add_argument('vm_name', help="Name of the VM to attach disks to.")
        disk_attach_parser.add_argument('-o', '--owner', help="Email of the disk owner to filter by.")

        create_parser = disk_subparsers.add_parser('create', help='Create disks.')
        create_parser.add_argument('pattern', help="The naming pattern for the resources (e.g., 'my-disk-').")
        create_parser.add_argument('start', type=int, help="The starting number for the sequence.")
        create_parser.add_argument('end', type=int, help="The ending number for the sequence.")
        create_parser.add_argument('--size', type=int, default=1, help="The size of each disk in GiB (default: 1).")
        create_parser.add_argument('--type', default='gp3', help="The volume type (default: gp3).")
        create_parser.add_argument('-z', '--availability-zone', default='ap-northeast-1a', help="The Availability Zone for creation.")
        create_parser.add_argument('-o', '--owner', help="Email of the disk owner to filter by.")

        delete_parser = disk_subparsers.add_parser('delete', help='Delete disks.')
        delete_parser.add_argument('pattern', help="The naming pattern or prefix.")
        delete_parser.add_argument('numbers', nargs='*', type=int, help="(Optional) Specific numbers to append to the pattern.")
        delete_parser.add_argument('-o', '--owner', help="Email of the disk owner to filter by.")

        subparsers.add_parser('vpc', help='List Scality VPCs and their subnets.')
        interface_parser = subparsers.add_parser('interface', help='List network interfaces.')
        interface_parser.add_argument('-o', '--owner', help="Email of the instance owner to filter by.")
        newdisk_parser = subparsers.add_parser('newdisk', help='List unattached disks owned by a user.')
        newdisk_parser.add_argument('-o', '--owner', help="Email of the disk owner to filter by.")
        
        return parser

    def run(self):
        args = self.parser.parse_args()
        
        level = 'SILENT'
        if args.verbose:
            level = 'VERBOSE'
        if args.debug:
            level = 'DEBUG'

        if args.command == 'disk' and args.disk_command in ['create', 'delete'] and level == 'SILENT':
            level = 'INFO'

        if args.command is None:
            args.command = 'instances'
            
        display = Display(level=level)

        aws_region = args.region or DEFAULT_REGION
        owner = getattr(args, 'owner', None) or DEFAULT_OWNER

        manager = AWSManager(region=aws_region, display=display, owner=owner)
        
        command_map = {
            'instances': self.do_instances,
            'network': self.do_network,
            'disk': self.do_disk,
            'vpc': self.do_vpc,
            'interface': self.do_interface,
            'newdisk': self.do_newdisk,
        }
        
        command_func = command_map.get(args.command)
        if command_func:
            command_func(manager, display, args)

    def do_instances(self, manager, display, args):
        display.display(f"EC2 Instances owned by {manager.owner} in region {manager.region}:", level='INFO')
        instances = manager.get_instances_by_owner(show_network_info=False, show_disk_info=False)
        if not instances:
            display.display(f"No instances found for this owner in region {manager.region}.", level='INFO')
        else:
            Display.format_output_table(instances)

    def do_network(self, manager, display, args):
        display.display(f"EC2-Instances-(Network-View) for {manager.owner} in region {manager.region}:", level='INFO')
        instances = manager.get_instances_by_owner(show_network_info=True, show_disk_info=False)
        if not instances:
            display.display(f"No instances found for this owner in region {manager.region}.", level='INFO')
        else:
            Display.format_output_table(instances)

    def do_disk(self, manager, display, args):
        if args.disk_command == 'list':
            manager.list_disks(manager.owner)
        elif args.disk_command == 'attach':
            manager.attach_volumes_to_instance(args.vm_name)
        elif args.disk_command == 'create':
            if args.start > args.end:
                display.display("Error: The start number cannot be greater than the end number.", level='INFO')
                sys.exit(1)
            manager.create_disks(args.pattern, args.start, args.end, args.size, args.type, args.availability_zone, manager.owner)
        elif args.disk_command == 'delete':
            manager.delete_disks(args.pattern, args.numbers, manager.owner)

    def do_vpc(self, manager, display, args):
        display.display(f"Searching for 'scality' VPCs in region {manager.region}:", level='VERBOSE')
        vpcs = manager.get_scality_vpcs_and_subnets()
        if not vpcs:
            display.display("No VPCs containing 'scality' were found.", level='INFO')
        else:
            for vpc_data in vpcs:
                display.display(f"- VPC: {vpc_data['VPC Name']} ({vpc_data['VPC ID']})", level='INFO')
                subnets = vpc_data['Subnets']
                if subnets and subnets[0]['Name'] == 'N/A':
                    display.display("  No subnets found.", level='INFO')
                elif subnets:
                    Display.format_output_table(subnets)

    def do_interface(self, manager, display, args):
        display.display(f"Network Interfaces for {manager.owner} in region {manager.region}:", level='VERBOSE')
        interfaces = manager.get_network_interfaces_by_owner()
        if not interfaces:
            display.display(f"No network interfaces found for this owner in region {manager.region}.", level='INFO')
        else:
            Display.format_output_table(interfaces)

    def do_newdisk(self, manager, display, args):
        display.display(f"Unattached Disks for {manager.owner} in region {manager.region}:", level='VERBOSE')
        disks = manager.get_unattached_disks()
        if not disks:
            display.display(f"No unattached disks found for this owner in region {manager.region}.", level='INFO')
        else:
            Display.format_output_table(disks)

if __name__ == "__main__":
    main_app = Main()
    main_app.run()
