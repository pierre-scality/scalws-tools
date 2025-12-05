#!/usr/bin/env python3
import argparse
import sys
import boto3
import re
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

DEFAULT_REGION = 'ap-northeast-1'
DEFAULT_OWNER = 'pierre.merle@scality.com'

class Display:
    """Handles formatting and printing data to the console."""
    def __init__(self, level='SILENT'):
        self.level = level
        self.levels = {'ERROR': 4, 'DEBUG': 3, 'VERBOSE': 2, 'INFO': 1, 'SILENT': 0}

    def display(self, message, level='INFO'):
        if level == 'QUERY':
            print(f"QUERY: {message}", end='')
            return
        
        if level == 'ERROR' or self.levels.get(self.level, 0) >= self.levels.get(level, 1):
            print(f"{level}: {message}")

    def query(self, message):
        self.display(message, level='QUERY')
        return input()

    def print_query(self, message):
        self.display(message, level='QUERY')

    def raw(self, message):
        print(message)

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
            self.display.display("Authentication Error: AWS credentials not found or incomplete. Have you set the AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and (if necessary) AWS_SESSION_TOKEN environment variables?", level='ERROR')
            sys.exit(1)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':
                self.display.display("Authentication Error: The provided AWS credentials could not be validated.", level='ERROR')
                sys.exit(1)
            else:
                self.display.display(f"An AWS service error occurred: {e}", level='ERROR')
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
            confirm = self.display.query("Do you want to proceed with creation? (y/n): ")
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

    def delete_disks(self, pattern, numbers, volume_ids_list, owner):
        """Deletes EBS volumes after confirmation."""
        disks_to_delete = []
        try:
            if volume_ids_list:
                # Describe all provided volume IDs
                response = self.ec2.describe_volumes(VolumeIds=volume_ids_list)
                all_volumes = response['Volumes']
                
                # Filter volumes that belong to the owner
                owner_volumes = [vol for vol in all_volumes if self._get_tag_value(vol.get('Tags'), 'owner') == owner]
                
                # Check for volumes not found or not owned
                found_volume_ids = {vol['VolumeId'] for vol in owner_volumes}
                not_found_or_not_owned = [vid for vid in volume_ids_list if vid not in found_volume_ids]

                if not_found_or_not_owned:
                    self.display.display(f"Error: The following Volume IDs were not found or do not belong to owner {owner}: {', '.join(not_found_or_not_owned)}", level='INFO')
                    sys.exit(1)
                
                disks_to_delete = owner_volumes
            else:
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
            confirm = self.display.query("Do you want to proceed with deletion? (y/n): ")
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
                        disks = self._get_disk_details(instance)
                        disk_str = ", ".join([f"{d['Name']} ({d['Size']}, {d['Type']})" for d in disks])
                        instance_info = {'Name': instance_name, 'Disks': disk_str}
                    else:
                        private_ips = self._get_private_ips(instance)
                        public_ips_info = self._get_public_ips(instance)
                        public_ips_list = []
                        for ip_info in public_ips_info:
                            ip_str = ip_info['ip']
                            if not ip_info['is_eip'] and ip_info.get('is_from_auto_assign_subnet', False):
                                ip_str += " auto"
                            public_ips_list.append(ip_str)

                        instance_info = {
                            'ID': instance_id, 
                            'Name': instance_name, 
                            'Autostop': autostop,
                            'State': instance['State']['Name'], 
                            'Private IPs': ", ".join(private_ips) if private_ips else "N/A", 
                            'Public IPs': ", ".join(public_ips_list) if public_ips_list else "N/A"
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

    def get_instances_by_regex(self, pattern):
        """Retrieves instances owned by the owner that match a regex pattern."""
        matching_instances = []
        try:
            response = self.ec2.describe_instances(Filters=[{'Name': 'tag:owner', 'Values': [self.owner]}])
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_name = self._get_tag_value(instance.get('Tags'), 'Name')
                    if instance_name and re.search(pattern, instance_name):
                        matching_instances.append(instance)
            return matching_instances
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
                for vol in volumes_response['Volumes']:
                    disk_info.append({'Name': self._get_tag_value(vol.get('Tags'), 'Name'), 'Size': f"{vol['Size']} GiB", 'Type': vol['VolumeType']})
        return disk_info

    def _get_private_ips(self, instance):
        """Gathers private IP addresses for a given instance."""
        private_ips = []
        if 'NetworkInterfaces' in instance:
            for interface in instance['NetworkInterfaces']:
                for ip_detail in interface.get('PrivateIpAddresses', []):
                    private_ips.append(ip_detail['PrivateIpAddress'])
        return private_ips

    def _get_public_ips(self, instance):
        """Gathers public IP addresses for a given instance and indicates if they are Elastic IPs."""
        public_ips_info = []
        if 'NetworkInterfaces' in instance:
            subnet_ids = [ni.get('SubnetId') for ni in instance.get('NetworkInterfaces', []) if ni.get('SubnetId')]
            subnet_map = {}
            if subnet_ids:
                try:
                    subnet_responses = self.ec2.describe_subnets(SubnetIds=list(set(subnet_ids)))['Subnets']
                    for subnet in subnet_responses:
                        subnet_map[subnet['SubnetId']] = subnet
                except ClientError:
                    pass

            for interface in instance['NetworkInterfaces']:
                association = interface.get('Association')
                if association and 'PublicIp' in association:
                    is_eip = 'AllocationId' in association
                    
                    is_from_auto_assign_subnet = False
                    if not is_eip:
                        subnet_id = interface.get('SubnetId')
                        if subnet_id and subnet_id in subnet_map:
                            is_from_auto_assign_subnet = subnet_map[subnet_id].get('MapPublicIpOnLaunch', False)
                    
                    public_ips_info.append({
                        'ip': association['PublicIp'], 
                        'is_eip': is_eip,
                        'is_from_auto_assign_subnet': is_from_auto_assign_subnet
                    })
        return public_ips_info

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

    def list_eips(self):
        """Lists all Elastic IPs and their association status."""
        try:
            addresses = self.ec2.describe_addresses()['Addresses']
            if not addresses:
                return []

            instance_ids = [addr['InstanceId'] for addr in addresses if 'InstanceId' in addr]
            instance_details = {}
            if instance_ids:
                instances_response = self.ec2.describe_instances(InstanceIds=instance_ids)
                for reservation in instances_response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_details[instance['InstanceId']] = {
                            'Name': self._get_tag_value(instance.get('Tags', []), 'Name'),
                            'Owner': self._get_tag_value(instance.get('Tags', []), 'owner'),
                            'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A')
                        }

            eips_data = []
            for addr in addresses:
                instance_id = addr.get('InstanceId')
                eip_name = self._get_tag_value(addr.get('Tags', []), 'Name') # Get the EIP name
                if instance_id:
                    details = instance_details.get(instance_id, {})
                    status = f"{details.get('PrivateIpAddress', 'N/A')} / {details.get('Name', 'N/A')}"
                    owner = details.get('Owner', 'N/A')
                else:
                    status = 'Free'
                    owner = 'N/A'
                
                eips_data.append({
                    'Name': eip_name, # Add EIP Name here
                    'EIP': addr['PublicIp'],
                    'AllocationId': addr['AllocationId'],
                    'Status': status,
                    'Owner': owner
                })
            return eips_data
        except ClientError as e:
            self.display.display(f"An AWS error occurred: {e}", level='INFO')
            return []

    def detach_eip(self, ip_address):
        """Detaches an Elastic IP from its instance after confirmation."""
        try:
            response = self.ec2.describe_addresses(PublicIps=[ip_address])
            if not response['Addresses']:
                self.display.display(f"Error: Elastic IP '{ip_address}' not found.", level='INFO')
                return

            addr = response['Addresses'][0]
            if 'AssociationId' not in addr:
                self.display.display(f"Error: EIP '{ip_address}' is not associated with any instance.", level='INFO')
                return

            association_id = addr['AssociationId']
            instance_id = addr.get('InstanceId', 'N/A')

            self.display.display(f"EIP '{ip_address}' will be detached from instance '{instance_id}'.", level='INFO')
            confirm = self.display.query("Do you want to proceed? (y/n): ")
            if confirm.lower() != 'y':
                self.display.display("Operation cancelled by user.", level='INFO')
                return

            self.ec2.disassociate_address(AssociationId=association_id)
            self.display.display(f"Successfully initiated detachment for EIP '{ip_address}'.", level='INFO')

        except ClientError as e:
            self.display.display(f"An AWS error occurred: {e}", level='INFO')
        except KeyboardInterrupt:
            self.display.display("\nOperation cancelled by user.", level='INFO')

    def attach_eip(self, ip_address, instance_name):
        """Attaches an Elastic IP to a specified instance."""
        try:
            # Find instance
            instance_response = self.ec2.describe_instances(Filters=[{'Name': 'tag:Name', 'Values': [instance_name]}, {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}])
            if not instance_response['Reservations'] or not instance_response['Reservations'][0]['Instances']:
                self.display.display(f"Error: No instance found with name '{instance_name}'.", level='INFO')
                return
            instance = instance_response['Reservations'][0]['Instances'][0]
            instance_id = instance['InstanceId']

            # Find EIP
            addr_response = self.ec2.describe_addresses(PublicIps=[ip_address])
            if not addr_response['Addresses']:
                self.display.display(f"Error: Elastic IP '{ip_address}' not found.", level='INFO')
                return
            addr = addr_response['Addresses'][0]
            allocation_id = addr['AllocationId']

            if addr.get('InstanceId'):
                self.display.display(f"Error: EIP '{ip_address}' is already associated with an instance.", level='INFO')
                return

            self.display.display(f"Attaching EIP '{ip_address}' to instance '{instance_name}' ({instance_id}).", level='INFO')
            confirm = self.display.query("Do you want to proceed? (y/n): ")
            if confirm.lower() != 'y':
                self.display.display("Operation cancelled by user.", level='INFO')
                return

            self.ec2.associate_address(AllocationId=allocation_id, InstanceId=instance_id)
            self.display.display("Successfully initiated attachment.", level='INFO')

        except ClientError as e:
            self.display.display(f"An AWS error occurred: {e}", level='INFO')
        except KeyboardInterrupt:
            self.display.display("\nOperation cancelled by user.", level='INFO')

    def get_unattached_disks(self):
        """Retrieves all unattached EBS volumes, filtering by owner tag."""
        disks_data = []
        try:
            response = self.ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}, {'Name': 'tag:owner', 'Values': [self.owner]}])
            for volume in response['Volumes']:
                disks_data.append({'Instance Name': 'Unattached', 'ID': volume['VolumeId'], 'Size': f"{volume['Size']} GiB"})
            return disks_data
        except Exception as e:
            self.display.display(f"An error occurred while fetching unattached volumes: {e}", level='INFO')
            return []

    def get_security_groups_for_owned_instances(self):
        """Retrieves security groups for EC2 instances owned by the user."""
        try:
            response = self.ec2.describe_instances(Filters=[{'Name': 'tag:owner', 'Values': [self.owner]}])
            sec_groups_data = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_name = self._get_tag_value(instance.get('Tags'), 'Name')
                    for sg in instance.get('SecurityGroups', []):
                        sec_groups_data.append({
                            'Instance Name': instance_name,
                            'SG Name': sg.get('GroupName'),
                            'SG ID': sg.get('GroupId')
                        })
            return sec_groups_data
        except Exception as e:
            self.display.display(f"An error occurred while fetching security groups: {e}", level='INFO')
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

class VMMgt:
    def __init__(self, manager, display):
        self.manager = manager
        self.display = display

    def _instance_action(self, expressions, action):
        all_instances = []
        instance_ids = set()

        for expression in expressions:
            instances = self.manager.get_instances_by_regex(expression)
            for instance in instances:
                if instance['InstanceId'] not in instance_ids:
                    all_instances.append(instance)
                    instance_ids.add(instance['InstanceId'])

        if not all_instances:
            self.display.display(f"No VMs found matching any of the expressions: '{' '.join(expressions)}'", level='ERROR')
            return

        instance_ids_to_action = [instance['InstanceId'] for instance in all_instances]
        instance_names = [self.manager._get_tag_value(instance.get('Tags'), 'Name') for instance in all_instances]

        try:
            self.display.print_query(f"Do you want to {action} these {len(all_instances)} vm(s)? (Enter to confirm/Ctl C to abort) \n")
            self.display.raw(" ".join(instance_names))
            input()
        except KeyboardInterrupt:
            self.display.display("\nOperation cancelled by user.", level='INFO')
            sys.exit(1)

        try:
            if action == 'terminate':
                confirm = self.display.query("do you really want to terminate? (y/n): ")
                if confirm.lower() != 'y':
                    self.display.display("Operation cancelled by user.", level='INFO')
                    return

            if action == 'start':
                self.manager.ec2.start_instances(InstanceIds=instance_ids_to_action)
            elif action == 'stop':
                self.manager.ec2.stop_instances(InstanceIds=instance_ids_to_action)
            elif action == 'terminate':
                self.manager.ec2.terminate_instances(InstanceIds=instance_ids_to_action)
            self.display.display(f"Successfully initiated {action} for {len(all_instances)} VMs.", level='INFO')
        except ClientError as e:
            self.display.display(f"An AWS error occurred: {e}", level='INFO')

    def start(self, expressions):
        self._instance_action(expressions, 'start')

    def stop(self, expressions):
        self._instance_action(expressions, 'stop')

    def terminate(self, expressions):
        self._instance_action(expressions, 'terminate')


class Main:
    def __init__(self):
        self.parser = self._create_parser()

    def _create_parser(self):
        parser = argparse.ArgumentParser(description="Script to manage AWS resources.")
        parser.add_argument('-r', '--region', help=f"AWS region to use (default: {DEFAULT_REGION}).")
        parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output.")
        parser.add_argument('-d', '--debug', action='store_true', help="Enable debug output.")

        parser.add_argument('-o', '--owner', help="Email of the owner to filter by.")
        parser.add_argument('-z', '--availability-zone', default='ap-northeast-1a', help="The Availability Zone for creation.")

        subparsers = parser.add_subparsers(dest='command', help='Sub-command help')

        instances_parser = subparsers.add_parser('instances', help='Instances related commands.')
        instances_subparsers = instances_parser.add_subparsers(dest='instances_command', help='Instances sub-command help')
        instances_list_parser = instances_subparsers.add_parser('list', help='List EC2 instances with basic info.')
        instances_disks_parser = instances_subparsers.add_parser('disks', help='List disks of a specific instance.')
        instances_disks_parser.add_argument('instance_name', help="Name of the instance.")

        network_parser = subparsers.add_parser('network', help='Network related commands.')
        network_subparsers = network_parser.add_subparsers(dest='network_command', help='Network sub-command help')
        network_list_parser = network_subparsers.add_parser('list', help='List instances with detailed network info.')
        interface_parser = network_subparsers.add_parser('interface', help='List network interfaces.')

        disk_parser = subparsers.add_parser('disk', help='Disk related commands.')
        disk_subparsers = disk_parser.add_subparsers(dest='disk_command', help='Disk sub-command help')

        disk_list_parser = disk_subparsers.add_parser('list', help='List all disks.')

        disk_attach_parser = disk_subparsers.add_parser('attach', help='Attach volumes to an instance.')
        disk_attach_parser.add_argument('vm_name', help="Name of the VM to attach disks to.")

        create_parser = disk_subparsers.add_parser('create', help='Create disks.')
        create_parser.add_argument('pattern', help="The naming pattern for the resources (e.g., 'my-disk-').")
        create_parser.add_argument('start', type=int, help="The starting number for the sequence.")
        create_parser.add_argument('end', type=int, help="The ending number for the sequence.")
        create_parser.add_argument('--size', type=int, default=1, help="The size of each disk in GiB (default: 1).")
        create_parser.add_argument('--type', default='gp3', help="The volume type (default: gp3).")
        

        delete_parser = disk_subparsers.add_parser('delete', help='Delete disks.')
        delete_group = delete_parser.add_mutually_exclusive_group(required=True)
        delete_group.add_argument('--pattern', help="The naming pattern or prefix.")
        delete_group.add_argument('--volume-id', nargs='+', help="One or more exact volume IDs to delete.")
        delete_parser.add_argument('numbers', nargs='*', type=int, help="(Optional) Specific numbers to append to the pattern.")

        vpc_parser = subparsers.add_parser('vpc', help='VPC related commands.')
        vpc_subparsers = vpc_parser.add_subparsers(dest='vpc_command', help='VPC sub-command help')
        vpc_subparsers.add_parser('list', help='List Scality VPCs and their subnets.')
        new_parser = disk_subparsers.add_parser('new', help='List unattached disks owned by a user.')

        eip_parser = subparsers.add_parser('eip', help='Elastic IP related commands.')
        eip_subparsers = eip_parser.add_subparsers(dest='eip_command', help='EIP sub-command help')
        eip_list_parser = eip_subparsers.add_parser('list', help='List all EIPs.')
        eip_attach_parser = eip_subparsers.add_parser('attach', help='Attach an EIP to an instance.')
        eip_attach_parser.add_argument('ip_address', help="The EIP address.")
        eip_attach_parser.add_argument('instance_name', help="The name of the instance.")
        eip_detach_parser = eip_subparsers.add_parser('detach', help='Detach an EIP from an instance.')
        eip_detach_parser.add_argument('ip_address', help="The IP address of the EIP to detach.")
        
        secg_parser = subparsers.add_parser('secg', help='Security Group related commands.')

        start_parser = subparsers.add_parser('start', help='Start VMs.')
        start_parser.add_argument('expressions', nargs='+', help="One or more regular expressions to match VM names.")
        stop_parser = subparsers.add_parser('stop', help='Stop VMs.')
        stop_parser.add_argument('expressions', nargs='+', help="One or more regular expressions to match VM names.")
        terminate_parser = subparsers.add_parser('terminate', help='Terminate VMs.')
        terminate_parser.add_argument('expressions', nargs='+', help="One or more regular expressions to match VM names.")

        return parser

    def run(self):
        args = self.parser.parse_args()

        if not args.command:
            args.command = 'instances'
            args.instances_command = 'list'
        
        # Default to 'list' for commands that have it and are called without a subcommand
        if args.command:
            subcommand_dest = f"{args.command}_command"
            if hasattr(args, subcommand_dest) and getattr(args, subcommand_dest) is None:
                setattr(args, subcommand_dest, 'list')
        
        level = 'SILENT'
        if args.verbose:
            level = 'VERBOSE'
        if args.debug:
            level = 'DEBUG'

        if args.command in ['disk', 'eip', 'start', 'stop', 'terminate'] and level == 'SILENT':
            level = 'INFO'

        display = Display(level=level)

        aws_region = args.region or DEFAULT_REGION
        owner = args.owner or DEFAULT_OWNER

        manager = AWSManager(region=aws_region, display=display, owner=owner)
        
        command_map = {
            'instances': self.do_instances,
            'network': self.do_network,
            'disk': self.do_disk,
            'vpc': self.do_vpc,
            'eip': self.do_eip,
            'secg': self.do_secg,
            'start': self.do_vm_action,
            'stop': self.do_vm_action,
            'terminate': self.do_vm_action,
        }
        
        command_func = command_map.get(args.command)
        if command_func:
            command_func(manager, display, args)
        
    def do_eip(self, manager, display, args):
        display.display(f"Entering do_eip for command: {args.eip_command}", level='DEBUG')
        if args.eip_command == 'list':
            eips = manager.list_eips()
            if not eips:
                display.display("No Elastic IPs found.", level='INFO')
            else:
                Display.format_output_table(eips)
        elif args.eip_command == 'attach':
            display.display(f"Args: ip_address={args.ip_address}, instance_name={args.instance_name}", level='DEBUG')
            manager.attach_eip(args.ip_address, args.instance_name)
        elif args.eip_command == 'detach':
            display.display(f"Args: ip_address={args.ip_address}", level='DEBUG')
            manager.detach_eip(args.ip_address)

    def do_secg(self, manager, display, args):
        display.display(f"Entering do_secg", level='DEBUG')
        sec_groups = manager.get_security_groups_for_owned_instances()
        if not sec_groups:
            display.display(f"No security groups found for instances owned by {manager.owner} in region {manager.region}.", level='INFO')
        else:
            Display.format_output_table(sec_groups)

    def do_vm_action(self, manager, display, args):
        display.display(f"Entering do_vm_action for command: {args.command}", level='DEBUG')
        vm_mgt = VMMgt(manager, display)
        if args.command == 'start':
            vm_mgt.start(args.expressions)
        elif args.command == 'stop':
            vm_mgt.stop(args.expressions)
        elif args.command == 'terminate':
            vm_mgt.terminate(args.expressions)

    def do_instances(self, manager, display, args):
        display.display(f"Entering do_instances for command: {args.instances_command}", level='DEBUG')
        if args.instances_command == 'list':
            instances = manager.get_instances_by_owner(show_network_info=False, show_disk_info=False)
            if not instances:
                display.display(f"No instances found for this owner in region {manager.region}.", level='INFO')
            else:
                Display.format_output_table(instances)
        elif args.instances_command == 'disks':
            self.do_instances_disks(manager, display, args)

    def do_instances_disks(self, manager, display, args):
        display.display(f"Entering do_instances_disks(instance_name={args.instance_name})", level='DEBUG')
        try:
            response = manager.ec2.describe_instances(Filters=[{'Name': 'tag:Name', 'Values': [args.instance_name]}])
            if not response['Reservations']:
                display.display(f"No instance found with name '{args.instance_name}'.", level='INFO')
                return
            instance = response['Reservations'][0]['Instances'][0]
            disks = manager._get_disk_details(instance)
            if not disks:
                display.display(f"No disks found for this instance in region {manager.region}.", level='INFO')
            else:
                Display.format_output_table(disks)
        except Exception as e:
            display.display(f"An error occurred while fetching instance disks: {e}", level='INFO')

    def do_network(self, manager, display, args):
        display.display(f"Entering do_network for command: {args.network_command}", level='DEBUG')
        if args.network_command == 'list':
            instances = manager.get_instances_by_owner(show_network_info=True, show_disk_info=False)
            if not instances:
                display.display(f"No instances found for this owner in region {manager.region}.", level='INFO')
            else:
                Display.format_output_table(instances)
        elif args.network_command == 'interface':
            interfaces = manager.get_network_interfaces_by_owner()
            if not interfaces:
                display.display(f"No network interfaces found for this owner in region {manager.region}.", level='INFO')
            else:
                Display.format_output_table(interfaces)

    def do_disk(self, manager, display, args):
        display.display(f"Entering do_disk for command: {args.disk_command}", level='DEBUG')
        if args.disk_command == 'list':
            manager.list_disks(manager.owner)
        elif args.disk_command == 'attach':
            display.display(f"Args: vm_name={args.vm_name}", level='DEBUG')
            manager.attach_volumes_to_instance(args.vm_name)
        elif args.disk_command == 'create':
            display.display(f"Args: pattern={args.pattern}, start={args.start}, end={args.end}, size={args.size}, type={args.type}", level='DEBUG')
            if args.start > args.end:
                display.display("Error: The start number cannot be greater than the end number.", level='INFO')
                sys.exit(1)
            manager.create_disks(args.pattern, args.start, args.end, args.size, args.type, args.availability_zone, manager.owner)
        elif args.disk_command == 'delete':
            display.display(f"Args: pattern={args.pattern}, numbers={args.numbers}, volume_id={args.volume_id}", level='DEBUG')
            manager.delete_disks(args.pattern, args.numbers, args.volume_id, manager.owner)
        elif args.disk_command == 'new':
            disks = manager.get_unattached_disks()
            if not disks:
                display.display(f"No unattached disks found for this owner in region {manager.region}.", level='INFO')
            else:
                Display.format_output_table(disks)
                volume_ids = [disk['ID'] for disk in disks]
                display.raw(" ".join(volume_ids))

    def do_vpc(self, manager, display, args):
        display.display(f"Entering do_vpc for command: {args.vpc_command}", level='DEBUG')
        if args.vpc_command == 'list':
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



if __name__ == "__main__":
    main_app = Main()
    main_app.run()
