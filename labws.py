#!/usr/bin/env python3
import argparse
import sys
import os
import boto3
from datetime import datetime
try:
    import paramiko
except ImportError:
    paramiko = None
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

# --- Constants ---
# --- Constants ---
ALLOWED_REGIONS = ['eu-north-1', 'us-west-2', 'ap-northeast-1', 'ap-southeast-2']
ALLOWED_TENANTS = ['ts', 'training']

# User-based Constants
USER_REGION = 'ap-northeast-1'
USER_TENANT = 'ts'
USER_OWNER = 'pierre.merle@scality.com'
USER_LAUNCH_TEMPLATE = 'pme-arte-minidisk' 
NEW_PASSWD = "150.249.201.205ONssh:notty"
USER_TIMEZONE = 'Asia/Tokyo'
USER_KEY_NAME = 'pme-aws-cloudkp'
USER_AUTOSTOP = 'nightly_ap_tokyo'

# AWS :
AWS_INSTANCE_TYPE = 't3.2xlarge'
AWS_VPC_NAME = 'scality-technical services-vpc'
AWS_SUBNET_NAME = 'scality-technical services-vpc-public-ap-northeast-1a'
AWS_SECURITY_GROUP_NAMES = ['allow-vpn-public-20230321165659057700000001']


# Default AWS Configuration
AWS_DEFAULT_CONFIG = {
    'instance_type': AWS_INSTANCE_TYPE,
    'key_name': USER_KEY_NAME,
    'security_group_names': AWS_SECURITY_GROUP_NAMES,
    'subnet_name': AWS_SUBNET_NAME,
    'vpc_name': AWS_VPC_NAME,
    'lifecycle_autostop': USER_AUTOSTOP
}

# Region Configuration (AWS-based)
# Structure: val = AWS_REGION_CONFIGS[region][tenant][key]
# Values here override the defaults in AWS_DEFAULT_CONFIG
AWS_REGION_CONFIGS = {
    'ap-northeast-1': {
        'ts': {}, # Uses all defaults
        'training': {'vpc_name': 'scality-training-vpc', 'subnet_name': 'scality-training-vpc-public-ap-northeast-1a', 'security_group_names': ['allow-vpn-public-20230321165619634600000001'],'key_name': 'artesca-lab-tokyo-training'}
    },
    'eu-north-1': {
        'ts': { 'instance_type': None, 'key_name': None, 'security_group_names': [], 'subnet_name': None, 'vpc_name': None, 'lifecycle_autostop': None },
        'training': {'vpc_name': 'scality-training-vpc', 'subnet_name': 'scality-training-vpc-public-eu-north-1a', 'security_group_names': ['allow-vpn-public-20230321165617811100000001'],'key_name': 'artesca-lab-tokyo-training'}
    },
    'us-west-2': {
        'ts': { 'instance_type': None, 'key_name': None, 'security_group_names': [], 'subnet_name': None, 'vpc_name': None, 'lifecycle_autostop': None },
        'training': { 'instance_type': None, 'key_name': None, 'security_group_names': [], 'subnet_name': None, 'vpc_name': None, 'lifecycle_autostop': None }
    },
    'ap-southeast-2': {
        'ts': { 'instance_type': None, 'key_name': None, 'security_group_names': [], 'subnet_name': None, 'vpc_name': None, 'lifecycle_autostop': None },
        'training': { 'instance_type': None, 'key_name': None, 'security_group_names': [], 'subnet_name': None, 'vpc_name': None, 'lifecycle_autostop': None }
    }
}

# --- Internal Constants ---
TEMPLATE_ROOT_VOLUME_SIZE = 50 # GB
TEMPLATE_ROOT_DEVICE_NAME = '/dev/sda1' # Common for Linux AMIs, may need changing (e.g., to /dev/xvda)

# SSH Configuration
DEFAULT_SSH_USER = 'artesca-os'
DEFAULT_SSH_PASSWORD = 'scality'
DEFAULT_RESET_PASSWORD = NEW_PASSWD
SSH_USER = 'root'
SSH_PASSWD = 'scalityadmin'


class EnvManager:
    """Manages loading and saving of environment configuration from a file."""
    def __init__(self, display, defaults, aws_region_configs, tenant=None, region=None):
        self.display = display
        self.config_file = os.path.expanduser('~/.labws.conf')
        self.defaults = defaults
        self.aws_region_configs = aws_region_configs
        self.tenant = tenant
        self.cli_region = region
        import configparser
        self.parser = configparser.ConfigParser()
        self.config = self._load_config()

    def _load_config(self):
        """Loads configuration from INI file, handling regions."""
        merged_config = self.defaults.copy()
        
        merged_config = self.defaults.copy()
        
        # 1. Determine active region (CLI arg > config file > default)
        active_region = self.cli_region if self.cli_region else USER_REGION
        
        if os.path.exists(self.config_file):
            try:
                self.parser.read(self.config_file)
                if 'default-region' in self.parser and 'region-name' in self.parser['default-region']:
                    file_region = self.parser['default-region']['region-name']
                    # Only use file region if CLI region wasn't provided
                    if not self.cli_region:
                         if file_region in ALLOWED_REGIONS:
                             active_region = file_region
                         else:
                             self.display.display(f"Warning: Region '{file_region}' in config is not in allowed list {ALLOWED_REGIONS}. Using default.", level='ERROR')
            except Exception as e:
                self.display.display(f"Error reading config file: {e}", level='ERROR')

        # Set the region in the config
        merged_config['region'] = active_region

        # 2. Update with AWS defaults and region-specific overrides
        # First, apply the global AWS defaults
        active_tenant = self.tenant or self.defaults.get('tenant') # Use CLI tenant or default (USER_TENANT)
        
        # Merge global defaults first
        for key, value in AWS_DEFAULT_CONFIG.items():
            merged_config[key] = value

        # Then apply overrides from AWS_REGION_CONFIGS if they exist
        if active_region in self.aws_region_configs:
            region_config = self.aws_region_configs[active_region]
            if active_tenant in region_config:
                tenant_overrides = region_config[active_tenant]
                for key, value in tenant_overrides.items():
                    # Only override if the value is explicitly set (not None)
                    # If you want to unset a default, you might need a specific sentinel, 
                    # but for now we assume None means "use default" or "not configured" in the override map.
                    # Given the diff request, we actually want defaults to be the baseline.
                    if value is not None:
                         merged_config[key] = value
                
                # Add tenant to config for visibility
                merged_config['tenant'] = active_tenant
                self.display.display(f"Loaded AWS config for region '{active_region}' and tenant '{active_tenant}'.", level='DEBUG')
            else:
                 self.display.display(f"Warning: Tenant '{active_tenant}' not found in AWS_REGION_CONFIGS for region '{active_region}'. Using global defaults.", level='ERROR')
        else:
             self.display.display(f"Warning: Region '{active_region}' not found in AWS_REGION_CONFIGS. Using global defaults.", level='ERROR')

        # 2. Update with values from [common] section
        if 'common' in self.parser:
            self._update_from_section(merged_config, self.parser['common'])

        # 3. Update with values from [active_region] section
        if active_region in self.parser:
            self.display.display(f"Loading configuration for region: {active_region}", level='DEBUG')
            self._update_from_section(merged_config, self.parser[active_region])

        return merged_config

    def _update_from_section(self, config_dict, section):
        """Helper to update config dict from a configparser section."""
        for key, value in section.items():
            value = value.strip().strip("'\"") # Handle quotes
            
            if key in config_dict:
                # Determine type from existing value in config_dict
                current_value = config_dict[key]
                # Special handling for lists (like security groups)
                if isinstance(current_value, list) or key == 'security_group_names':
                     config_dict[key] = [item.strip() for item in value.split(',')]
                elif isinstance(current_value, bool):
                     config_dict[key] = value.lower() in ['true', '1', 'yes']
                elif isinstance(current_value, int):
                     config_dict[key] = int(value)
                else:
                     # Default to string
                     config_dict[key] = value
                self.display.display(f"Loaded '{key}' from config.", level='DEBUG')

    def get_config(self):
        """Returns the merged configuration."""
        return self.config

    def show(self):
        """Displays the current configuration."""
        self.display.display("Current effective configuration:", level='INFO')
        self.display.display(f"Active Region: {self.config.get('region')}", level='INFO')
        
        # Determine max key length for alignment
        max_key_len = max((len(key) for key in self.config.keys()))
        
        for key, value in sorted(self.config.items()):
            self.display.raw(f"  {key:<{max_key_len}} = {value}")

    def create(self):
        """Creates the config file with INI structure."""
        if os.path.exists(self.config_file):
            self.display.display(f"WARNING: Configuration file '{self.config_file}' already exists.", level='ERROR')
            try:
                confirm = self.display.query("Do you want to overwrite it? (y/n): ")
            except KeyboardInterrupt:
                self.display.display("\nOperation cancelled by user.", level='INFO')
                sys.exit(1)

            if confirm.lower() != 'y':
                self.display.display("Operation cancelled.", level='INFO')
                return
        
        try:
            with open(self.config_file, 'w') as f:
                f.write("# Scality Artesca Lab Workshop - User Configuration File\n")
                f.write(f"# File automatically generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("[default-region]\n")
                f.write(f"region-name = {USER_REGION}\n\n")
                
                f.write("[common]\n")
                f.write(f"owner = {self.defaults['owner']}\n")
                f.write(f"new_password = {self.defaults['new_password']}\n")
                f.write(f"timezone = {self.defaults['timezone']}\n\n")

                for region in ALLOWED_REGIONS:
                    f.write(f"[{region}]\n")
                    if region in self.aws_region_configs:
                        aws_conf = self.aws_region_configs[region]
                        for k, v in aws_conf.items():
                            if v is not None:
                                if isinstance(v, list):
                                    v = ','.join(v)
                                f.write(f"{k} = {v}\n")
                            else:
                                f.write(f"# {k} = ...\n")
                    f.write("\n")

            self.display.display(f"Successfully created configuration file: '{self.config_file}'", level='INFO')
        except Exception as e:
            self.display.display(f"Failed to create configuration file: {e}", level='ERROR')


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

    def __init__(self, region, display, owner=None, config=None):
        self.region = region
        self.owner = owner
        self.display = display
        self.config = config or {}
        try:
            self.ec2 = boto3.client('ec2', region_name=self.region)
            self.ec2.describe_regions()
        except (NoCredentialsError, PartialCredentialsError):
            self.display.display("Authentication Error: AWS credentials not found or incomplete.", level='ERROR')
            sys.exit(1)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':
                self.display.display("Authentication Error: The provided AWS credentials could not be validated.", level='ERROR')
                sys.exit(1)
            else:
                self.display.display(f"An AWS service error occurred: {e}", level='ERROR')
                sys.exit(1)

    def launch_instance_from_template(self, launch_template_name, instance_name, availability_zone=None):
        """Launches an EC2 instance from a specified launch template."""
        try:
            self.display.display(f"Launching instance '{instance_name}' from template '{launch_template_name}'...", level='INFO')

            run_instances_args = {
                'LaunchTemplate': {'LaunchTemplateName': launch_template_name},
                'MinCount': 1,
                'MaxCount': 1,
            }

            # If an availability zone is specified, add it to the launch arguments.
            if availability_zone:
                run_instances_args['Placement'] = {'AvailabilityZone': availability_zone}

            response = self.ec2.run_instances(**run_instances_args)
            instance_id = response['Instances'][0]['InstanceId']
            self.display.display(f"Successfully initiated launch for instance '{instance_name}' with ID '{instance_id}'.", level='DEBUG')
            
            waiter = self.ec2.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instance_id])
            self.display.display(f"Instance '{instance_name}' ({instance_id}) is now running.", level='DEBUG')

            self._tag_root_volume(instance_id, instance_name)

            self.display.display(f"Tagging instance '{instance_name}'.", level='INFO')
            self.ec2.create_tags(
                Resources=[instance_id],
                Tags=[
                    {'Key': 'Name', 'Value': instance_name},
                    {'Key': 'owner', 'Value': self.owner},
                    {'Key': 'artesca_lab', 'Value': 'yes'}
                ]
            )
            
            return instance_id
        except ClientError as e:
            self.display.display(f"An AWS error occurred while launching instance '{instance_name}': {e}", level='ERROR')
            return None

    def launch_instance_from_spec(self, name, ami_id, instance_type, key_name, sg_ids, subnet_id):
        """Launches an EC2 instance from specified parameters."""
        try:
            self.display.display(f"Launching custom instance '{name}'...", level='INFO')
            
            block_device_mappings = [
                {
                    'DeviceName': TEMPLATE_ROOT_DEVICE_NAME,
                    'Ebs': {
                        'VolumeSize': 100,
                    },
                },
            ]

            run_instances_args = {
                'ImageId': ami_id,
                'InstanceType': instance_type,
                'MinCount': 1,
                'MaxCount': 1,
                'BlockDeviceMappings': block_device_mappings,
            }
            if key_name:
                run_instances_args['KeyName'] = key_name
            if sg_ids:
                run_instances_args['SecurityGroupIds'] = sg_ids
            if subnet_id:
                run_instances_args['SubnetId'] = subnet_id
            
            response = self.ec2.run_instances(**run_instances_args)
            instance_id = response['Instances'][0]['InstanceId']
            self.display.display(f"Successfully initiated launch for instance '{name}' with ID '{instance_id}'.", level='INFO')
            
            waiter = self.ec2.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instance_id])
            self.display.display(f"Instance '{name}' ({instance_id}) is now running.", level='INFO')

            self._tag_root_volume(instance_id, name)
            # self._create_and_attach_additional_volumes(instance_id, name)

            self.ec2.create_tags(
                Resources=[instance_id],
                Tags=[
                    {'Key': 'Name', 'Value': name},
                    {'Key': 'owner', 'Value': self.owner},
                    {'Key': 'artesca_lab', 'Value': 'yes'}
                ]
            )
            self.display.display(f"Successfully tagged instance '{name}'.", level='INFO')
            
            return instance_id
        except ClientError as e:
            self.display.display(f"An AWS error occurred while launching instance '{name}': {e}", level='ERROR')
            return None

    def create_and_assign_eip(self, instance_id, instance_name):
        """Allocates a new EIP, names it, and associates it with an instance."""
        try:
            self.display.display(f"Allocating new EIP for {instance_name}...", level='INFO')
            eip_response = self.ec2.allocate_address(Domain='vpc')
            allocation_id = eip_response['AllocationId']
            public_ip = eip_response['PublicIp']
            self.display.display(f"Successfully allocated EIP '{public_ip}'.", level='DEBUG')

            eip_name = f"{instance_name}-labeip"
            self.ec2.create_tags(
                Resources=[allocation_id],
                Tags=[{'Key': 'Name', 'Value': eip_name}]
            )
            self.display.display(f"EIP tagged as '{eip_name}'.", level='VERBOSE')

            self.display.display(f"Associating EIP '{public_ip}' with instance '{instance_id}'...", level='INFO')
            self.ec2.associate_address(AllocationId=allocation_id, InstanceId=instance_id)
            self.display.display(f"Successfully associated EIP '{public_ip}' with instance '{instance_id}'.", level='VERBOSE')
            
            return public_ip
        except ClientError as e:
            self.display.display(f"An AWS error occurred during EIP creation or assignment: {e}", level='ERROR')
            return None

    def _tag_root_volume(self, instance_id, instance_name):
        """Finds and tags the root volume of an instance."""
        try:
            self.display.display(f"Finding root volume for instance '{instance_name}' to tag it...", level='DEBUG')
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            
            if not response['Reservations'] or not response['Reservations'][0]['Instances']:
                self.display.display(f"Could not find instance details for '{instance_id}' to tag root volume.", level='ERROR')
                return

            instance = response['Reservations'][0]['Instances'][0]
            root_device_name = instance.get('RootDeviceName')
            
            if not root_device_name:
                self.display.display(f"Could not determine root device name for instance '{instance_id}'.", level='ERROR')
                return

            root_volume_id = None
            for mapping in instance.get('BlockDeviceMappings', []):
                if mapping.get('DeviceName') == root_device_name:
                    root_volume_id = mapping.get('Ebs', {}).get('VolumeId')
                    break
            
            if not root_volume_id:
                self.display.display(f"Could not find root volume ID for device '{root_device_name}'.", level='ERROR')
                return

            volume_name = f"{instance_name}-lab-root"
            self.display.display(f"Tagging volume '{root_volume_id}' with name '{volume_name}'.", level='INFO')
            self.ec2.create_tags(
                Resources=[root_volume_id],
                Tags=[{'Key': 'Name', 'Value': volume_name}]
            )
        except ClientError as e:
            self.display.display(f"An AWS error occurred while tagging the root volume: {e}", level='ERROR')

    def _create_and_attach_additional_volumes(self, instance_id, instance_name):
        """Creates, tags, and attaches a predefined set of additional volumes to an instance."""
        try:
            self.display.display(f"Creating and attaching additional volumes for instance '{instance_name}'...", level='INFO')
            
            # Get instance details to find its AZ and existing block devices
            response = self.ec2.describe_instances(InstanceIds=[instance_id])
            if not response['Reservations'] or not response['Reservations'][0]['Instances']:
                self.display.display(f"Could not find instance details for '{instance_id}'.", level='ERROR')
                return
            instance = response['Reservations'][0]['Instances'][0]
            availability_zone = instance['Placement']['AvailabilityZone']
            attached_devices = [bd['DeviceName'] for bd in instance.get('BlockDeviceMappings', [])]

            disk_configs = [
                {'count': 2, 'size': 120, 'type': 'gp3', 'name_pattern': f'{instance_name}-service-lab'},
                {'count': 12, 'size': 8, 'type': 'gps', 'name_pattern': f'{instance_name}-data-lab'}
            ]

            device_letters = 'fghijklmnopqrstuvwxyz'
            device_index = 0

            for config in disk_configs:
                for i in range(1, config['count'] + 1):
                    volume_name = f"{config['name_pattern']}-{i}"
                    
                    # Find next available device name
                    while True:
                        device_name = f'/dev/sd{device_letters[device_index]}'
                        if device_name not in attached_devices:
                            break
                        device_index += 1
                        if device_index >= len(device_letters):
                            self.display.display("Error: No available device names left to attach volumes.", level='ERROR')
                            return

                    self.display.display(f"Creating volume '{volume_name}' ({config['size']}GB, {config['type']}) in {availability_zone}...", level='VERBOSE')
                    
                    # Create the volume
                    volume = self.ec2.create_volume(
                        Size=config['size'],
                        VolumeType=config['type'],
                        AvailabilityZone=availability_zone,
                        TagSpecifications=[{'ResourceType': 'volume', 'Tags': [{'Key': 'Name', 'Value': volume_name}, {'Key': 'owner', 'Value': self.owner}]}]
                    )
                    volume_id = volume['VolumeId']
                    
                    # Wait for the volume to be available
                    waiter_available = self.ec2.get_waiter('volume_available')
                    waiter_available.wait(VolumeIds=[volume_id])
                    self.display.display(f"Volume '{volume_id}' is available. Attaching as '{device_name}'...", level='VERBOSE')

                    # Attach the volume
                    self.ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device=device_name)
                    attached_devices.append(device_name)
                    
                    # Wait for the volume to be attached
                    waiter_in_use = self.ec2.get_waiter('volume_in_use')
                    waiter_in_use.wait(VolumeIds=[volume_id])
                    self.display.display(f"Successfully attached volume '{volume_name}' to '{instance_name}'.", level='INFO')

        except ClientError as e:
            self.display.display(f"An AWS error occurred during additional volume creation/attachment: {e}", level='ERROR')
        except Exception as e:
            self.display.display(f"An unexpected error occurred during additional volume creation/attachment: {e}", level='ERROR')

    def list_instances_by_prefix_and_pattern(self, prefix, pattern, get_ssh_details=False):
        """Lists instances that match a given prefix and pattern. Optionally gets hostname and timezone via SSH."""
        try:
            self.display.display(f"Listing instances with prefix '{prefix}' and pattern '{pattern}'...", level='VERBOSE')
            
            name_filter = f"{prefix}-{pattern}-*"
            
            paginator = self.ec2.get_paginator('describe_instances')
            pages = paginator.paginate(
                Filters=[
                    {'Name': 'tag:artesca_lab', 'Values': ['yes']},
                    {'Name': 'tag:Name', 'Values': [name_filter]},
                    {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}
                ]
            )

            matching_instances = []
            for page in pages:
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instance_info = {
                            'Name': next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'N/A'),
                            'InstanceId': instance['InstanceId'],
                            'State': instance['State']['Name'],
                            'PublicIp': instance.get('PublicIpAddress', 'N/A'),
                            'PrivateIp': instance.get('PrivateIpAddress', 'N/A'),
                        }

                        if get_ssh_details:
                            instance_info['hostname'] = 'N/A'
                            instance_info['timezone'] = 'N/A'
                            if instance_info['State'] == 'running' and instance_info['PublicIp'] != 'N/A':
                                hostname, timezone = self._get_ssh_details(instance_info['PublicIp'])
                                instance_info['hostname'] = hostname
                                instance_info['timezone'] = timezone
                        
                        matching_instances.append(instance_info)
            return matching_instances
        except ClientError as e:
            self.display.display(f"An AWS error occurred while listing instances: {e}", level='ERROR')
            return []

    def list_all_lab_instances(self, get_ssh_details=False):
        """Lists all instances with the 'artesca_lab=yes' tag."""
        try:
            self.display.display("Listing all instances with 'artesca_lab=yes' tag...", level='VERBOSE')

            paginator = self.ec2.get_paginator('describe_instances')
            pages = paginator.paginate(
                Filters=[
                    {'Name': 'tag:artesca_lab', 'Values': ['yes']},
                    {'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}
                ]
            )

            matching_instances = []
            for page in pages:
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        instance_info = {
                            'Name': next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), 'N/A'),
                            'InstanceId': instance['InstanceId'],
                            'State': instance['State']['Name'],
                            'PublicIp': instance.get('PublicIpAddress', 'N/A'),
                            'PrivateIp': instance.get('PrivateIpAddress', 'N/A'),
                        }

                        if get_ssh_details:
                            instance_info['hostname'] = 'N/A'
                            instance_info['timezone'] = 'N/A'
                            if instance_info['State'] == 'running' and instance_info['PublicIp'] != 'N/A':
                                hostname, timezone = self._get_ssh_details(instance_info['PublicIp'])
                                instance_info['hostname'] = hostname
                                instance_info['timezone'] = timezone

                        matching_instances.append(instance_info)
            return matching_instances
        except ClientError as e:
            self.display.display(f"An AWS error occurred while listing instances: {e}", level='ERROR')
            return []

    def _get_ssh_details(self, ip_address):
        """Connects to an instance via SSH to get hostname and timezone."""
        if not paramiko:
            return 'NO_PARAMIKO', 'NO_PARAMIKO'

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        password = self.config.get('new_password', DEFAULT_RESET_PASSWORD)
        try:
            client.connect(ip_address, username=DEFAULT_SSH_USER, password=password, port=22, timeout=3, look_for_keys=True, allow_agent=True)
            
            # Get hostname
            stdin, stdout, stderr = client.exec_command("hostname -s", timeout=5)
            hostname = stdout.read().decode('utf-8').strip() or 'EMPTY'
            
            # Get timezone
            stdin, stdout, stderr = client.exec_command("date +%Z", timeout=5)
            timezone = stdout.read().decode('utf-8').strip() or 'EMPTY'
            
            client.close()
            return hostname, timezone
        except Exception as e:
            self.display.display(f"SSH connection to {ip_address} as '{DEFAULT_SSH_USER}' failed: {e}", level='DEBUG')
            client.close()
            return 'ERROR', 'ERROR'

    def list_eips_by_prefix_and_pattern(self, prefix, pattern):
        """Lists EIPs that match a given prefix and pattern."""
        search_prefix = f"{prefix}-{pattern}-"
        self.display.display(f"Listing EIPs with name starting with '{search_prefix}'...", level='INFO')
        try:
            addresses = self.ec2.describe_addresses()['Addresses']
            
            matching_eips = []
            for addr in addresses:
                eip_name = next((tag['Value'] for tag in addr.get('Tags', []) if tag['Key'] == 'Name'), None)
                if eip_name and eip_name.startswith(search_prefix) and eip_name.endswith('-labeip'):
                    matching_eips.append({
                        'Name': eip_name,
                        'EIP': addr.get('PublicIp', 'N/A'),
                        'InstanceId': addr.get('InstanceId', 'Not Associated')
                    })
            return matching_eips
        except ClientError as e:
            self.display.display(f"An AWS error occurred while listing EIPs: {e}", level='ERROR')
            return []

    def get_instance_name_from_ip(self, public_ip):
        """Retrieves the 'Name' tag of an instance from its public IP."""
        try:
            self.display.display(f"Fetching instance details for IP '{public_ip}'...", level='INFO')
            response = self.ec2.describe_instances(
                Filters=[{'Name': 'ip-address', 'Values': [public_ip]}]
            )
            
            if not response['Reservations'] or not response['Reservations'][0]['Instances']:
                self.display.display(f"No instance found with public IP '{public_ip}'.", level='ERROR')
                return None

            instance = response['Reservations'][0]['Instances'][0]
            instance_name = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), None)
            
            if instance_name:
                self.display.display(f"Found instance '{instance_name}' for IP '{public_ip}'.", level='INFO')
                return instance_name
            else:
                self.display.display(f"Instance with IP '{public_ip}' does not have a 'Name' tag.", level='ERROR')
                return None
        except ClientError as e:
            self.display.display(f"An AWS error occurred while fetching instance details: {e}", level='ERROR')
            return None

    def get_vpc_id_by_name(self, name):
        """Finds a VPC ID by its 'Name' tag."""
        try:
            self.display.display(f"Looking for VPC with Name tag: '{name}'", level='VERBOSE')
            response = self.ec2.describe_vpcs(Filters=[{'Name': 'tag:Name', 'Values': [name]}])
            if response['Vpcs']:
                vpc_id = response['Vpcs'][0]['VpcId']
                self.display.display(f"Found VPC '{name}' with ID: {vpc_id}", level='VERBOSE')
                return vpc_id
            self.display.display(f"No VPC found with name '{name}'.", level='ERROR')
            return None
        except ClientError as e:
            self.display.display(f"An AWS error occurred while searching for VPC '{name}': {e}", level='ERROR')
            return None

    def get_subnet_id_by_name(self, name, vpc_id=None):
        """Finds a subnet ID by its 'Name' tag, optionally filtering by VPC."""
        try:
            self.display.display(f"Looking for subnet with Name tag: '{name}'", level='VERBOSE')
            filters = [{'Name': 'tag:Name', 'Values': [name]}]
            if vpc_id:
                self.display.display(f"Filtering subnet search by VPC ID: {vpc_id}", level='VERBOSE')
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
            
            response = self.ec2.describe_subnets(Filters=filters)
            if response['Subnets']:
                subnet_id = response['Subnets'][0]['SubnetId']
                self.display.display(f"Found subnet '{name}' with ID: {subnet_id}", level='VERBOSE')
                return subnet_id
            self.display.display(f"No subnet found with name '{name}' (VPC filter: {vpc_id or 'None'}).", level='ERROR')
            return None
        except ClientError as e:
            self.display.display(f"An AWS error occurred while searching for subnet '{name}': {e}", level='ERROR')
            return None

    def get_sg_ids_by_names(self, names, vpc_id=None):
        """Finds security group IDs by their 'group-name', optionally filtering by VPC."""
        if not names:
            return []
        try:
            self.display.display(f"Looking for security groups with names: {names}", level='VERBOSE')
            filters = [{'Name': 'group-name', 'Values': names}]
            if vpc_id:
                self.display.display(f"Filtering security group search by VPC ID: {vpc_id}", level='VERBOSE')
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})

            response = self.ec2.describe_security_groups(Filters=filters)
            
            found_groups = response['SecurityGroups']
            if len(found_groups) < len(names):
                found_names = [sg.get('GroupName') for sg in found_groups]
                self.display.display(f"Could not find all security groups by name. Wanted: {names}. Found: {len(found_names)} ({found_names}). (VPC filter: {vpc_id or 'None'}).", level='ERROR')
                return None

            sg_ids = [sg['GroupId'] for sg in found_groups]
            self.display.display(f"Found security groups {names} with IDs: {sg_ids}", level='VERBOSE')
            return sg_ids
        except ClientError as e:
            self.display.display(f"An AWS error occurred while searching for security groups: {e}", level='ERROR')
            return None

    def check_key_pair(self, key_name):
        """Checks if a key pair exists."""
        try:
            self.display.display(f"Checking for Key Pair: '{key_name}'", level='VERBOSE')
            response = self.ec2.describe_key_pairs(KeyNames=[key_name])
            if response['KeyPairs']:
                self.display.display(f"Found Key Pair '{key_name}' (ID: {response['KeyPairs'][0]['KeyPairId']})", level='VERBOSE')
                return True
            return False
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidKeyPair.NotFound':
                 self.display.display(f"Key Pair '{key_name}' not found.", level='ERROR')
                 return False
            self.display.display(f"An AWS error occurred while checking key pair: {e}", level='ERROR')
            return False

    def check_instance_type(self, instance_type):
        """Checks if an instance type is valid (simple check against DescribeInstanceTypes)."""
        try:
             self.display.display(f"Checking validity of Instance Type: '{instance_type}'", level='VERBOSE')
             self.ec2.describe_instance_types(InstanceTypes=[instance_type])
             self.display.display(f"Instance Type '{instance_type}' is valid.", level='VERBOSE')
             return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceType':
                 self.display.display(f"Instance Type '{instance_type}' is invalid.", level='ERROR')
                 return False
            self.display.display(f"An AWS error occurred while checking instance type: {e}", level='ERROR')
            return False

    def get_ami_id_by_name(self, name):
        """Finds an AMI ID by its 'Name' tag."""
        try:
            self.display.display(f"Looking for AMI with Name tag: '{name}'", level='VERBOSE')
            # AMIs in some regions are owned by specific account IDs for RHEL, etc.
            # This searches public images, but we might need to specify owners for some cases.
            response = self.ec2.describe_images(
                Filters=[
                    {'Name': 'name', 'Values': [name]},
                    {'Name': 'state', 'Values': ['available']}
                ],
                Owners=['self', 'amazon'] # Common owners, can be extended
            )
            if response['Images']:
                # Sort by creation date to get the most recent one if names are not unique
                images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
                ami_id = images[0]['ImageId']
                self.display.display(f"Found AMI '{name}' with ID: {ami_id}", level='VERBOSE')
                return ami_id
            
            self.display.display(f"No available AMI found with name '{name}'. Trying with a broader search...", level='VERBOSE')
            # Fallback for public images that might not be under 'self' or 'amazon'
            response = self.ec2.describe_images(
                Filters=[
                    {'Name': 'name', 'Values': [name]},
                    {'Name': 'state', 'Values': ['available']}
                ]
            )
            if response['Images']:
                images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
                ami_id = images[0]['ImageId']
                self.display.display(f"Found public AMI '{name}' with ID: {ami_id}", level='VERBOSE')
                return ami_id

            self.display.display(f"No available AMI found with name '{name}' in this region.", level='ERROR')
            return None
        except ClientError as e:
            self.display.display(f"An AWS error occurred while searching for AMI '{name}': {e}", level='ERROR')
            return None

    def list_shared_artesca_amis(self, show_all=False):
        """Lists AMIs shared with the current account that have names starting with 'artesca-'."""
        try:
            self.display.display("Listing AMIs shared with this account, named 'artesca-*'...", level='VERBOSE')
            response = self.ec2.describe_images(
                Filters=[
                    {'Name': 'name', 'Values': ['artesca-*']},
                    {'Name': 'state', 'Values': ['available']}
                ],
                ExecutableUsers=['self'] # AMIs shared with the current account
            )

            shared_amis = []
            for image in response['Images']:
                ami_name = image.get('Name', 'N/A')
                
                if not show_all:
                    if ami_name.endswith('-dev') or '-preview' in ami_name or '-rc' in ami_name:
                        continue

                shared_amis.append({
                    'Name': ami_name,
                    'ImageId': image.get('ImageId', 'N/A'),
                    'OwnerId': image.get('OwnerId', 'N/A'),
                    'CreationDate': image.get('CreationDate', 'N/A')
                })
            
            # Sort by CreationDate, newest first
            shared_amis.sort(key=lambda x: x['CreationDate'], reverse=True)
            
            return shared_amis
        except ClientError as e:
            self.display.display(f"An AWS error occurred while listing shared AMIs: {e}", level='ERROR')
            return []

    def _parse_version(self, name):
        """Parses a version string like 'artesca-4.0.2' into a comparable tuple."""
        try:
            # tailored for 'artesca-X.Y.Z' format
            if name.startswith('artesca-'):
                version_part = name.split('-', 1)[1]
                return tuple(map(int, version_part.split('.')))
        except ValueError:
            pass
        return (0, 0, 0) # Fallback for non-parseable versions

    def get_latest_artesca_ami(self):
        """Returns the latest Artesca AMI based on semantic versioning."""
        # Get all visible AMIs, filtering out dev/rc versions for stability unless we want those too?
        # Usually 'latest' implies latest stable. Let's start with stable only (default behavior of list_shared_artesca_amis).
        amis = self.list_shared_artesca_amis(show_all=False)
        
        if not amis:
            return None

        # Sort by parsed version
        latest_ami = max(amis, key=lambda x: self._parse_version(x['Name']))
        return latest_ami

    def get_artesca_ami_by_version(self, version):
        """Returns AMIs matching 'artesca-<version>', e.g., 'artesca-2.3.4'."""
        try:
            name = f"artesca-{version}"
            response = self.ec2.describe_images(
                Filters=[
                    {'Name': 'name', 'Values': [name]},
                    {'Name': 'state', 'Values': ['available']}
                ],
                ExecutableUsers=['self']
            )
            if response['Images']:
                return response['Images'][0]
            return None
        except ClientError as e:
            self.display.display(f"An AWS error occurred while searching for AMI version '{version}': {e}", level='ERROR')
            return None

    def create_launch_template(self, template_name, ami_id, instance_type, key_name, sg_ids, subnet_id, device_profile='loop'):
        """Creates a new EC2 Launch Template."""
        try:
            self.display.display(f"Creating launch template '{template_name}' with device profile '{device_profile}'...", level='INFO')

            # Determine root volume size based on device_profile
            root_volume_size = 100 if device_profile == 'loop' else TEMPLATE_ROOT_VOLUME_SIZE

            # Define Block Device Mappings, including additional volumes
            block_device_mappings = [
                {
                    'DeviceName': TEMPLATE_ROOT_DEVICE_NAME,
                    'Ebs': {
                        'VolumeSize': root_volume_size,
                    },
                },
            ]

            if device_profile == 'device':
                disk_configs = [
                    {'count': 2, 'size': 120, 'type': 'gp3'},
                    {'count': 12, 'size': 8, 'type': 'gp3'}
                ]

                import string
                device_letters = string.ascii_lowercase
                # Start from 'b' since 'a' is the root device
                device_index = 1 

                for config in disk_configs:
                    for i in range(config['count']):
                        device_name = f'/dev/sd{device_letters[device_index]}'
                        block_device_mappings.append({
                            'DeviceName': device_name,
                            'Ebs': {
                                'VolumeSize': config['size'],
                                'VolumeType': config['type'],
                            }
                        })
                        device_index += 1

            launch_template_data = {
                'ImageId': ami_id,
                'InstanceType': instance_type,
                'BlockDeviceMappings': block_device_mappings,
                'NetworkInterfaces': [
                    {
                        'DeviceIndex': 0,
                        'SubnetId': subnet_id,
                        'Groups': sg_ids,
                    }
                ],
                'TagSpecifications': [
                    {
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'Name', 'Value': template_name},
                            {'Key': 'owner', 'Value': self.owner},
                            {'Key': 'artesca_lab', 'Value': 'yes'},
                            {'Key': 'lifecycle_autostop', 'Value': self.config.get('lifecycle_autostop', 'nightly_ap_tokyo')},
                            {'Key': 'lifecycle_autostart', 'Value': 'no'}
                        ]
                    }
                ]
            }

            if key_name:
                launch_template_data['KeyName'] = key_name

            response = self.ec2.create_launch_template(
                LaunchTemplateName=template_name,
                LaunchTemplateData=launch_template_data,
                TagSpecifications=[
                    {
                        'ResourceType': 'launch-template',
                        'Tags': [
                            {'Key': 'owner', 'Value': self.owner},
                            {'Key': 'artelab-template', 'Value': 'yes'}
                        ]
                    }
                ]
            )
            
            template = response['LaunchTemplate']
            self.display.display(f"Successfully created launch template '{template['LaunchTemplateName']}' (ID: {template['LaunchTemplateId']}).", level='INFO')
            return template
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidLaunchTemplateName.AlreadyExistsException':
                self.display.display(f"Error: A launch template with the name '{template_name}' already exists.", level='ERROR')
            else:
                self.display.display(f"An AWS error occurred while creating the launch template: {e}", level='ERROR')
            return None

    def list_launch_templates(self):
        """Lists launch templates owned by the user, sorted by creation date."""
        try:
            self.display.display(f"Listing launch templates created by '{self.owner}'...", level='INFO')
            paginator = self.ec2.get_paginator('describe_launch_templates')
            pages = paginator.paginate()

            owned_templates_raw = []
            for page in pages:
                for template in page['LaunchTemplates']:
                    created_by_arn = template.get('CreatedBy', '')
                    # Extract owner email (e.g., from 'arn:aws:iam::ACCOUNT:user/EMAIL')
                    owner_email = created_by_arn.split('/')[-1]
                    if owner_email == self.owner:
                        owned_templates_raw.append(template)

            # Sort templates by creation time, newest first
            owned_templates_raw.sort(key=lambda t: t['CreateTime'], reverse=True)

            templates = []
            for template in owned_templates_raw:
                created_by_arn = template.get('CreatedBy', 'N/A')
                if '/' in created_by_arn:
                    owner_display = created_by_arn.split('/')[-1]
                else:
                    owner_display = created_by_arn

                templates.append({
                    'Name': template['LaunchTemplateName'],
                    'Owner': owner_display,
                    'Created': template['CreateTime'].strftime('%Y-%m-%d %H:%M:%S'),
                })
            return templates
        except ClientError as e:
            self.display.display(f"An AWS error occurred while listing launch templates: {e}", level='ERROR')
            return []

    def delete_launch_template(self, template_name):
        """Deletes a specified launch template."""
        try:
            self.display.display(f"Deleting launch template '{template_name}'...", level='INFO')
            self.ec2.delete_launch_template(LaunchTemplateName=template_name)
            self.display.display(f"Successfully deleted launch template '{template_name}'.", level='INFO')
            return True
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidLaunchTemplateName.NotFoundException':
                self.display.display(f"Launch template '{template_name}' not found.", level='INFO')
            else:
                self.display.display(f"An AWS error occurred while deleting the launch template: {e}", level='ERROR')
            return False

    def get_launch_template(self, template_name, show_details=True):
        """Retrieves and optionally displays the details of a specific launch template."""
        try:
            if show_details:
                self.display.display(f"Showing details for launch template '{template_name}'...", level='INFO')
            response = self.ec2.describe_launch_templates(LaunchTemplateNames=[template_name])
            
            if not response['LaunchTemplates']:
                if show_details:
                    self.display.display(f"Launch template '{template_name}' not found.", level='ERROR')
                return None
            
            template = response['LaunchTemplates'][0]
            
            # If we don't need details, we can return early, but we might want the object.
            # However, retrieving versions is an extra API call.
            if not show_details:
                return template

            # Get the latest version data
            versions_response = self.ec2.describe_launch_template_versions(
                LaunchTemplateName=template_name,
                Versions=['$Latest']
            )
            template_data = versions_response['LaunchTemplateVersions'][0]['LaunchTemplateData']

            details = {
                'Name': template['LaunchTemplateName'],
                'Id': template['LaunchTemplateId'],
                'CreatedBy': template.get('CreatedBy'),
                'CreateTime': template['CreateTime'].strftime('%Y-%m-%d %H:%M:%S'),
                'DefaultVersion': template['DefaultVersionNumber'],
                'LatestVersion': template['LatestVersionNumber'],
                'Tags': template.get('Tags', 'No Tags Found')
            }
            
            self.display.raw("\n--- Template Details ---")
            for key, value in details.items():
                self.display.raw(f"{key}: {value}")

            self.display.raw("\n--- Launch Data (Latest Version) ---")
            for key, value in template_data.items():
                if key == 'TagSpecifications':
                    self.display.raw("TagSpecifications:")
                    for spec in value:
                        self.display.raw(f"  - ResourceType: {spec['ResourceType']}")
                        self.display.raw(f"    Tags: {spec['Tags']}")
                elif key == 'BlockDeviceMappings':
                    self.display.raw("BlockDeviceMappings:")
                    for bdm in value:
                        self.display.raw(f"  - DeviceName: {bdm['DeviceName']}")
                        self.display.raw(f"    Ebs: {bdm['Ebs']}")
                else:
                    self.display.raw(f"{key}: {value}")
            
            return template

        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidLaunchTemplateName.NotFoundException':
                if show_details:
                    self.display.display(f"Launch template '{template_name}' not found.", level='ERROR')
            else:
                self.display.display(f"An AWS error occurred while describing the launch template: {e}", level='ERROR')
            return None

    def get_resources_to_destroy(self, prefix, pattern):
        """Finds all resources (instances, EIPs, volumes) associated with a prefix and pattern."""
        resources = {'instances': [], 'eips': [], 'volumes': []}
        
        # 1. Find instances
        instances = self.list_instances_by_prefix_and_pattern(prefix, pattern)
        if not instances:
            return resources
        
        resources['instances'] = instances
        instance_ids = [i['InstanceId'] for i in instances]

        # 2. Find all volumes attached to these instances
        try:
            self.display.display(f"Describing instances {instance_ids} to find attached volumes...", level='VERBOSE')
            response = self.ec2.describe_instances(InstanceIds=instance_ids)
            
            volume_ids = []
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    for bdm in instance.get('BlockDeviceMappings', []):
                        if 'Ebs' in bdm and 'VolumeId' in bdm['Ebs']:
                            volume_ids.append(bdm['Ebs']['VolumeId'])
            
            if volume_ids:
                self.display.display(f"Found {len(volume_ids)} attached volumes. Describing them...", level='VERBOSE')
                vol_response = self.ec2.describe_volumes(VolumeIds=volume_ids)
                for vol in vol_response['Volumes']:
                    volume_name = next((tag['Value'] for tag in vol.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
                    resources['volumes'].append({
                        'VolumeId': vol['VolumeId'],
                        'Name': volume_name,
                        'Size': vol['Size']
                    })

        except ClientError as e:
            self.display.display(f"An AWS error occurred while finding volumes: {e}", level='ERROR')

        # 3. Find associated EIPs
        try:
            self.display.display("Searching for associated EIPs...", level='VERBOSE')
            addresses = self.ec2.describe_addresses()['Addresses']
            
            for addr in addresses:
                if addr.get('InstanceId') in instance_ids:
                    eip_name = next((tag['Value'] for tag in addr.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
                    resources['eips'].append({
                        'PublicIp': addr['PublicIp'],
                        'AllocationId': addr['AllocationId'],
                        'Name': eip_name
                    })
        except ClientError as e:
            self.display.display(f"An AWS error occurred while searching for EIPs: {e}", level='ERROR')
            
        return resources

    def destroy_lab_resources(self, resources):
        """Terminates instances, releases EIPs, and deletes volumes."""
        instance_ids = [i['InstanceId'] for i in resources.get('instances', [])]
        eips = resources.get('eips', [])
        volume_ids = [v['VolumeId'] for v in resources.get('volumes', [])]

        # 1. Terminate Instances
        if instance_ids:
            try:
                self.display.display(f"Terminating {len(instance_ids)} instance(s): {', '.join(instance_ids)}", level='INFO')
                self.ec2.terminate_instances(InstanceIds=instance_ids)
                
                waiter = self.ec2.get_waiter('instance_terminated')
                waiter.wait(InstanceIds=instance_ids)
                self.display.display("All specified instances have been successfully terminated.", level='INFO')
            except ClientError as e:
                self.display.display(f"An AWS error occurred during instance termination: {e}", level='ERROR')
                self.display.display("Please check the AWS console. Some resources may not have been deleted.", level='ERROR')
                return

        # 2. Release EIPs
        # This can be done in parallel with instance termination.
        if eips:
            for eip in eips:
                try:
                    self.display.display(f"Releasing EIP {eip['PublicIp']}...", level='INFO')
                    self.ec2.release_address(AllocationId=eip['AllocationId'])
                except ClientError as e:
                    self.display.display(f"Could not release EIP {eip['PublicIp']} (AllocationId: {eip['AllocationId']}). It may have already been released or an error occurred: {e}", level='ERROR')

        # 3. Delete Volumes
        # This should happen after instances are confirmed terminated.
        if volume_ids:
            self.display.display(f"Starting deletion of {len(volume_ids)} volume(s)...", level='INFO')
            for volume_id in volume_ids:
                try:
                    self.display.display(f"Deleting volume {volume_id}...", level='VERBOSE')
                    self.ec2.delete_volume(VolumeId=volume_id)
                except ClientError as e:
                    # It's possible for volumes to be deleted automatically with instance termination
                    # if the 'DeleteOnTermination' flag was set. We can treat 'NotFound' as a success.
                    if e.response['Error']['Code'] == 'InvalidVolume.NotFound':
                        self.display.display(f"Volume {volume_id} was not found. It may have been deleted already.", level='VERBOSE')
                    else:
                        self.display.display(f"An AWS error occurred while deleting volume {volume_id}: {e}", level='ERROR')
            
            self.display.display("All specified volumes have been processed for deletion.", level='INFO')


class TemplateManager:
    """Manages launching instances from templates."""

    def __init__(self, aws_manager, display):
        self.aws_manager = aws_manager
        self.display = display

    def launch_instances(self, count, prefix, pattern, launch_template_name, availability_zone=None, on_confirm_callback=None):
        """Launches a number of instances, names them, and assigns EIPs, checking for existing ones."""
        if count <= 0:
            self.display.display("Error: Number of machines to start must be greater than 0.", level='ERROR')
            return

        # Check for existing instances
        existing_instances = self.aws_manager.list_instances_by_prefix_and_pattern(prefix, pattern)
        existing_instance_names = {instance['Name'] for instance in existing_instances}

        # If verbose, display what was found
        if self.display.levels.get(self.display.level, 0) >= self.display.levels.get('VERBOSE', 2):
            if existing_instances:
                self.display.display("Found existing instances with the same prefix and pattern:", level='VERBOSE')
                Display.format_output_table(existing_instances)
            else:
                self.display.display("No existing instances found with the same prefix and pattern.", level='VERBOSE')

        # Determine which instances to create
        all_potential_names = [f"{prefix}-{pattern}-{i:02d}" for i in range(1, count + 1)]
        instances_to_actually_create = []
        
        for name in all_potential_names:
            if name in existing_instance_names:
                self.display.display(f"Instance '{name}' already exists, skipping creation.", level='INFO')
            else:
                instances_to_actually_create.append({'Name': name, 'hostname': name})

        if not instances_to_actually_create:
            self.display.display("All requested instances already exist. Nothing to do.", level='INFO')
            return

        machine_names = ', '.join([instance['Name'] for instance in instances_to_actually_create])
        self.display.display(f"The following machines will be created: {machine_names}", level='INFO')

        try:
            confirm = self.display.query("Do you want to proceed with creation? (y/n): ")
        except KeyboardInterrupt:
            self.display.display("\nOperation cancelled by user.", level='INFO')
            sys.exit(1)
            
        if confirm.lower() != 'y':
            self.display.display("Operation cancelled by user.", level='INFO')
            sys.exit(0)
        
        # Execute the callback (e.g. template creation) if provided
        if on_confirm_callback:
            on_confirm_callback()

        self.display.display(f"User confirmed. Preparing to launch {len(instances_to_actually_create)} instance(s).", level='INFO')

        for instance_to_create in instances_to_actually_create:
            instance_name = instance_to_create['Name']
            self.display.display(f"Processing instance: {instance_name} ", level='VERBOSE')
            
            instance_id = self.aws_manager.launch_instance_from_template(launch_template_name, instance_name, availability_zone)
            if not instance_id:
                self.display.display(f"Failed to launch instance '{instance_name}'. Aborting.", level='ERROR')
                break
            
            public_ip = self.aws_manager.create_and_assign_eip(instance_id, instance_name)
            if not public_ip:
                self.display.display(f"Failed to create or assign EIP for instance '{instance_name}'.", level='ERROR')
            
            self.display.display(f"Successfully launched instance '{instance_name}' with assigned Public IP '{public_ip}'.", level='INFO')

class Main:
    def __init__(self):
        self.parser = self._create_parser()

    def _create_parser(self):
        parser = argparse.ArgumentParser(description="Script to manage lab environments on AWS using template.\nSee individual section help for details")
        parser.add_argument('-r', '--region', help="AWS region to use.")
        parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output.")
        parser.add_argument('-d', '--debug', action='store_true', help="Enable debug output.")
        parser.add_argument('-o', '--owner', help="Email of the owner to filter by.")
        parser.add_argument('-z', '--availability-zone', help="The Availability Zone for resource creation.")
        
        parser.add_argument('--tenant', choices=ALLOWED_TENANTS, help='The tenant to use (e.g., ts, training).')
        
        subparsers = parser.add_subparsers(dest='command', help='Sub-command help')
        
        # --- Check subcommand ---
        check_parser = subparsers.add_parser('check', help='Check the validity of environment configuration and AWS resources.')
        build_parser = subparsers.add_parser('build', help="Build machines from a template or from scratch.")
        
        # Create titled groups for better help output
        build_group = build_parser.add_argument_group('Build Options')

        # Add arguments to their respective groups
        build_group.add_argument('-c', '--count', type=int, default=1, help="The number of machines to start. Defaults to 1.")
        build_group.add_argument('-x', '--prefix', help="The prefix for machine names. If not provided, it will be\ngenerated from the owner's email.")
        build_group.add_argument('-p', '--pattern', required=True, help="The pattern for machine names (required, e.g., 'vm').")
        
        build_group.add_argument('-t', '--template', help="Use an specific existing launch template by name.")

        # Auto-Template Options
        build_group.add_argument('-D', '--device', default='loop', choices=['loop', 'device'], help="[Auto-Template] Disk profile: 'loop' (demo profile, 100GB root) or 'device' (demolvm profile, 8GB root + extra disks). Default is 'loop'.")
        build_group.add_argument('-A', '--artesca', help="[Auto-Template] Specific Artesca version (e.g., '2.3.4'). If not set, uses latest.")

        # Show subcommand
        show_parser = subparsers.add_parser('show', help='Show resources.')
        show_parser.add_argument('-e', '--eip', action='store_true', help="List EIPs matching the prefix and pattern.")
        show_parser.add_argument('-x', '--prefix', help="The prefix for the machine name. If not provided, it will be generated from the owner's email.")
        show_parser.add_argument('-p', '--pattern', help="The pattern for the machine name (e.g., 'server'). Default is 'vm'.")

        # Configure subcommand
        configure_parser = subparsers.add_parser('configure', help='Configure machines based on prefix and pattern.')
        configure_parser.add_argument('-x', '--prefix', help="The prefix for the machine name. If not provided, it will be generated from the owner's email.")
        configure_parser.add_argument('-p', '--pattern', default='vm', help="The pattern for the machine name (e.g., 'server'). Default is 'vm'.")
        configure_parser.add_argument('--os', action='store_true', help="Also change the password for the 'artesca-os' user to match the new root password.")

        # Destroy subcommand
        destroy_parser = subparsers.add_parser('destroy', help='Destroy machines and associated resources.')
        destroy_parser.add_argument('-x', '--prefix', help="The prefix for the machine name. If not provided, it will be generated from the owner's email.")
        destroy_parser.add_argument('-p', '--pattern', default='vm', help="The pattern for the machine name (e.g., 'server'). Default is 'vm'.")

        # Env subcommand
        env_parser = subparsers.add_parser('env', help='Manage local environment configuration (~/.labws.conf).')
        env_parser.add_argument('action', nargs='?', default='show', choices=['show', 'create'], help="Action to perform: 'show' (default) or 'create'.")

        # AMI subcommand
        ami_parser = subparsers.add_parser('ami', help='List AMIs shared with me, filtered by name.')
        ami_parser.add_argument('--all', action='store_true', help='Show all AMIs, including preview, rc, and dev versions.')
        ami_parser.add_argument('--latest', action='store_true', help='Show only the latest stable Artesca AMI.')

        # Template subcommand
        template_parser = subparsers.add_parser('template', help='Manage launch templates.')
        template_subparsers = template_parser.add_subparsers(dest='template_command', help='Template commands')

        # template create
        create_template_parser = template_subparsers.add_parser('create', help='Create a new launch template from specifications.')
        create_template_parser.add_argument('--template-name', help='Name for the new template. If not provided, constructed from prefix and pattern.')
        create_template_parser.add_argument('-x', '--prefix', help="The prefix for the template name. If not provided, generated from owner's email.")
        create_template_parser.add_argument('-p', '--pattern', help="The pattern for the template name (required if --template-name is not set).")
        create_template_parser.add_argument('--ami-name', help="The name of the AMI. If not provided, the latest Artesca AMI will be used.")
        create_template_parser.add_argument('-D', '--device', default='loop', choices=['loop', 'device'], help="Disk profile: 'loop' (demo profile, 100GB root) or 'device' (demolvm profile, 8GB root + extra disks). Default is 'loop'.")
        create_template_parser.add_argument('--instance-type', help="The instance type.")
        create_template_parser.add_argument('--key-name', help="The key pair name.")
        create_template_parser.add_argument('--security-group-names', nargs='+', help="Security group names.")
        create_template_parser.add_argument('--subnet-name', help="The subnet name.")
        create_template_parser.add_argument('--vpc-name', help="The VPC name.")

        # template delete
        delete_template_parser = template_subparsers.add_parser('delete', help='Delete a launch template.')
        delete_template_parser.add_argument('--template-name', required=True, help='[Required] Name of the template to delete.')

        # template show
        show_template_parser = template_subparsers.add_parser('show', help='Show details of a launch template.')
        show_template_parser.add_argument('--template-name', required=True, help='[Required] Name of the template to show.')

        return parser

    def _generate_prefix_from_owner(self, owner_email):
        """Generates a prefix from the owner's email address."""
        try:
            local_part = owner_email.split('@')[0]
            parts = local_part.split('.')
            if len(parts) >= 2:
                first_name, last_name = parts[0], parts[1]
                return f"{first_name[0]}{last_name[:2]}"
        except (IndexError, AttributeError):
            pass
        return 'vm' # Fallback prefix

    def run(self):
        args = self.parser.parse_args()
        if args.command == None:
          self.parser.print_help()
          sys.exit(1)
        level = 'INFO'
        if args.verbose:
            level = 'VERBOSE'
        if args.debug:
            level = 'DEBUG'

        display = Display(level=level)

        # --- Configuration Management ---
        defaults = {
            'region': USER_REGION,
            'tenant': USER_TENANT,
            'owner': USER_OWNER,
            'launch_template': USER_LAUNCH_TEMPLATE,
            'new_password': NEW_PASSWD,
            'timezone': USER_TIMEZONE
        }
        
        # Determine effective tenant from CLI or defaults
        # We pass it to EnvManager so it can load the right AWS resource IDs
        effective_tenant = args.tenant or USER_TENANT
        effective_region = args.region

        env_manager = EnvManager(display, defaults, AWS_REGION_CONFIGS, tenant=effective_tenant, region=effective_region)
        config = env_manager.get_config()
        config['args'] = args

        # Handle 'env' command first, as it doesn't need full AWS manager setup
        if args.command == 'env':
            if args.action == 'show':
                env_manager.show()
            elif args.action == 'create':
                env_manager.create()
            sys.exit(0)

        # Enable paramiko logging if verbose or debug is on
        if level in ['VERBOSE', 'DEBUG']:
            import logging
            paramiko_level = logging.DEBUG if level == 'DEBUG' else logging.INFO
            
            paramiko_logger = logging.getLogger("paramiko")
            paramiko_logger.setLevel(paramiko_level)
            
            # Prevent adding duplicate handlers
            if not paramiko_logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter('%(levelname)s:%(name)s:%(message)s')
                handler.setFormatter(formatter)
                paramiko_logger.addHandler(handler)
            
            display.display("Paramiko logging enabled.", level='DEBUG')

        aws_region = args.region or config['region']
        owner = args.owner or config['owner']
        availability_zone = args.availability_zone


        manager = AWSManager(region=aws_region, display=display, owner=owner, config=config)

        if args.command == 'check':
            display.display("=== Checking Environment Configuration ===", level='INFO')

            # --- Group 1: Client Configuration ---
            display.raw("\n[Client Configuration]")
            display.raw(f"  Region:       {config.get('region')}")
            display.raw(f"  Owner:        {config.get('owner')}")
            display.raw(f"  Timezone:     {config.get('timezone')}")
            
            pwd = config.get('new_password')
            pwd_display = "******" if pwd else "Not Set"
            display.raw(f"  New Password: {pwd_display}")
            
            launch_template = config.get('launch_template')
            display.raw(f"  Launch Template Name: {launch_template}")
            
            display.raw(f"  Configure SSH User:   {SSH_USER}")
            display.raw(f"  Show SSH User:        {DEFAULT_SSH_USER}")


            # --- Group 2: AWS Resources ---
            display.raw("\n[AWS Resources]")
            
            # VPC
            vpc_name = config.get('vpc_name')
            vpc_id = manager.get_vpc_id_by_name(vpc_name)
            if vpc_id:
                display.raw(f"  [OK] VPC: {vpc_name} ({vpc_id})")
            else:
                display.raw(f"  [FAIL] VPC: {vpc_name} (Not Found)")

            # Subnet
            subnet_name = config.get('subnet_name')
            subnet_id = manager.get_subnet_id_by_name(subnet_name, vpc_id=vpc_id)
            if subnet_id:
                display.raw(f"  [OK] Subnet: {subnet_name} ({subnet_id})")
            else:
                display.raw(f"  [FAIL] Subnet: {subnet_name} (Not Found)")

            # Security Groups
            sg_names = config.get('security_group_names', [])
            sg_ids = manager.get_sg_ids_by_names(sg_names, vpc_id=vpc_id)
            if sg_ids:
                display.raw(f"  [OK] Security Groups: {', '.join(sg_names)} ({', '.join(sg_ids)})")
            else:
                display.raw(f"  [FAIL] Security Groups: {', '.join(sg_names)} (One or more not found)")

            # Key Pair
            key_name = config.get('key_name')
            if manager.check_key_pair(key_name):
                 display.raw(f"  [OK] Key Pair: {key_name}")
            else:
                 display.raw(f"  [FAIL] Key Pair: {key_name} (Not Found)")

            # Instance Type
            instance_type = config.get('instance_type')
            if manager.check_instance_type(instance_type):
                 display.raw(f"  [OK] Instance Type: {instance_type}")
            else:
                 display.raw(f"  [FAIL] Instance Type: {instance_type} (Invalid)")

            # Lifecycle Autostop
            lifecycle = config.get('lifecycle_autostop')
            display.raw(f"  [INFO] Lifecycle Autostop Tag: {lifecycle}")

            sys.exit(0)

        if args.command == 'build':
            prefix = args.prefix or self._generate_prefix_from_owner(owner)
            
            # Decide template to use
            on_confirm_callback = None
            if args.template:
                template_name = args.template
                display.display(f"Using existing launch template: '{template_name}'", level='INFO')
            else:
                # Auto-Template Logic
                template_name = f"{prefix}-{args.pattern}-template"
                display.display(f"Using auto template name '{template_name}'", level='INFO')
                
                # Check if template already exists
                existing_template = manager.get_launch_template(template_name, show_details=False)
                if existing_template:
                    display.display(f"Error: Launch template '{template_name}' already exists.", level='ERROR')
                    display.display("Please use -t to use it, or destroy resources (-p <pattern>) to remove it.", level='ERROR')
                    sys.exit(1)

                # Determine AMI
                ami_id = None
                if args.artesca:
                    display.display(f"Searching for Artesca AMI version '{args.artesca}'...", level='INFO')
                    ami = manager.get_artesca_ami_by_version(args.artesca)
                    if ami:
                        ami_id = ami['ImageId']
                        display.display(f"Found AMI: {ami.get('Name')} ({ami_id})", level='INFO')
                    else:
                        display.display(f"Error: Could not find AMI for version '{args.artesca}'.", level='ERROR')
                        sys.exit(1)
                else:
                    display.display("Fetching latest Artesca AMI...", level='VERBOSE')
                    latest_ami = manager.get_latest_artesca_ami()
                    if latest_ami:
                        ami_id = latest_ami['ImageId']
                        display.display(f"Using latest AMI: {latest_ami['Name']} ({ami_id})", level='INFO')
                    else:
                        display.display("Error: Could not find any Artesca AMIs.", level='ERROR')
                        sys.exit(1)

                # Resolve network resources
                vpc_name = config['vpc_name']
                subnet_name = config['subnet_name']
                sg_names = config['security_group_names']

                vpc_id = manager.get_vpc_id_by_name(vpc_name)
                if not vpc_id:
                     display.display(f"Could not resolve VPC '{vpc_name}'.", level='ERROR')
                     sys.exit(1)

                subnet_id = manager.get_subnet_id_by_name(subnet_name, vpc_id=vpc_id)
                sg_ids = manager.get_sg_ids_by_names(sg_names, vpc_id=vpc_id)

                if not all([ami_id, subnet_id, sg_ids]):
                    display.display("Error: Could not resolve all required resources (AMI, Subnet, Security Groups).", level='ERROR')
                    sys.exit(1)

                # Define a callback to create the template only after confirmation
                def create_template_callback():
                     manager.create_launch_template(
                        template_name=template_name,
                        ami_id=ami_id,
                        instance_type=config['instance_type'],
                        key_name=config['key_name'],
                        sg_ids=sg_ids,
                        subnet_id=subnet_id,
                        device_profile=args.device
                    )
                on_confirm_callback = create_template_callback

            # Proceed with build using the template (existing or to be created)
            display.display(f"Starting build process using template: '{template_name}'", level='INFO')
            template_manager = TemplateManager(aws_manager=manager, display=display)
            template_manager.launch_instances(args.count, prefix, args.pattern, template_name, availability_zone=availability_zone, on_confirm_callback=on_confirm_callback)
        
        elif args.command == 'show':
            # If no prefix, pattern or eip flag is given, show all lab instances.
            if not args.eip and not args.prefix and not args.pattern:
                instances = manager.list_all_lab_instances(get_ssh_details=True)
                if instances:
                    Display.format_output_table(instances)
                else:
                    display.display("No instances with 'artesca_lab=yes' tag found.", level='INFO')
            else:
                prefix = args.prefix or self._generate_prefix_from_owner(owner)
                pattern = args.pattern or 'vm'

                if args.eip:
                    eips = manager.list_eips_by_prefix_and_pattern(prefix, pattern)
                    if eips:
                        Display.format_output_table(eips)
                    else:
                        display.display(f"No EIPs found with prefix '{prefix}' and pattern '{pattern}'.", level='INFO')
                else: # Default action is to show instances
                    instances = manager.list_instances_by_prefix_and_pattern(prefix, pattern, get_ssh_details=True)
                    if instances:
                        Display.format_output_table(instances)
                    else:
                        display.display(f"No instances found with prefix '{prefix}' and pattern '{pattern}'.", level='INFO')
            sys.exit(0)

        elif args.command == 'configure':
            prefix = args.prefix or self._generate_prefix_from_owner(owner)
            pattern = args.pattern
            
            display.display(f"Finding instances with prefix '{prefix}' and pattern '{pattern}' to configure...", level='VERBOSE')
            instances_to_configure = manager.list_instances_by_prefix_and_pattern(prefix, pattern)
            
            if not instances_to_configure:
                display.display("No matching instances found to configure.", level='INFO')
                sys.exit(0)

            display.display("The following instances will be configured:", level='INFO')
            Display.format_output_table([{'Name': i['Name'], 'PublicIp': i['PublicIp']} for i in instances_to_configure if i.get('PublicIp') != 'N/A'])

            try:
                confirm = display.query("Do you want to proceed with configuration? (y/n): ")
            except KeyboardInterrupt:
                display.display("\nOperation cancelled by user.", level='INFO')
                sys.exit(1)
                
            if confirm.lower() != 'y':
                display.display("Operation cancelled by user.", level='INFO')
                sys.exit(0)

            for instance in instances_to_configure:
                ip = instance.get('PublicIp')
                name = instance.get('Name')
                state = instance.get('State') # Get the state

                if state != 'running': # Check if the state is not running
                    display.display(f"ERROR: Machine '{name}' is not running (current state: {state}). Skipping configuration.", level='ERROR')
                    continue
                
                if not ip or ip == 'N/A':
                    display.display(f"Skipping instance '{name}' because it has no public IP.", level='INFO')
                    continue
                
                private_ip = instance.get('PrivateIp')
                
                display.display(f"--- Configuring instance: {name} ({ip}) ---", level='INFO')
                self._configure_instance(ip, private_ip, name, display, config)

        elif args.command == 'destroy':
            prefix = args.prefix or self._generate_prefix_from_owner(owner)
            pattern = args.pattern or 'vm'
            
            display.display(f"Finding resources to destroy for prefix '{prefix}' and pattern '{pattern}'...", level='INFO')
            resources_to_destroy = manager.get_resources_to_destroy(prefix, pattern)
            
            instances = resources_to_destroy.get('instances', [])
            eips = resources_to_destroy.get('eips', [])
            volumes = resources_to_destroy.get('volumes', [])

            # Check for auto-created template
            template_name = f"{prefix}-{pattern}-template"
            template_to_destroy = manager.get_launch_template(template_name, show_details=False)

            if not instances and not eips and not volumes and not template_to_destroy:
                display.display("No resources found to destroy.", level='INFO')
                sys.exit(0)

            display.display("The following resources will be permanently deleted:", level='INFO')
            if instances:
                display.display("\n--- Instances to Terminate ---", level='INFO')
                Display.format_output_table([{'ID': i['InstanceId'], 'Name': i['Name']} for i in instances])
            if eips:
                display.display("\n--- EIPs to Release ---", level='INFO')
                Display.format_output_table([{'IP': eip['PublicIp'], 'Name': eip.get('Name', 'N/A')} for eip in eips])
            if volumes:
                display.display("\n--- Volumes to Delete ---", level='INFO')
                Display.format_output_table([{'ID': vol['VolumeId'], 'Name': vol.get('Name', 'N/A'), 'Size (GB)': vol['Size']} for vol in volumes])
            if template_to_destroy:
                 display.display(f"Template to delete: {template_to_destroy['LaunchTemplateName']} (ID: {template_to_destroy['LaunchTemplateId']})", level='INFO')

            try:
                confirm = display.query("\nAre you sure you want to delete all these resources? This action cannot be undone. (y/n): ")
            except KeyboardInterrupt:
                display.display("\nOperation cancelled by user.", level='INFO')
                sys.exit(1)
                
            if confirm.lower() != 'y':
                display.display("Operation cancelled by user.", level='INFO')
                sys.exit(0)
            
            display.display("User confirmed. Proceeding with resource deletion...", level='INFO')
            manager.destroy_lab_resources(resources_to_destroy)

            if template_to_destroy:
                 display.display(f"Deleting associated template '{template_name}'...", level='INFO')
                 manager.delete_launch_template(template_name)

        elif args.command == 'ami':
            if args.latest:
                latest = manager.get_latest_artesca_ami()
                if latest:
                    if display.levels.get(display.level, 0) >= display.levels.get('VERBOSE', 2):
                        display.display(f"Latest Artesca AMI: {latest['Name']} ({latest['ImageId']}) created on {latest['CreationDate']}", level='INFO')
                    else:
                        display.raw(latest['Name'])
                else:
                    display.display("No Artesca AMIs found.", level='INFO')
            else:
                amis = manager.list_shared_artesca_amis(show_all=args.all)
                if amis:
                    if display.levels.get(display.level, 0) >= display.levels.get('VERBOSE', 2):
                        Display.format_output_table(amis)
                    else:
                        # Simplify output: keep only Name and ImageId
                        simplified_amis = [{'Name': a['Name'], 'ImageId': a['ImageId']} for a in amis]
                        Display.format_output_table(simplified_amis)
                else:
                    display.display("No 'artesca-*' AMIs shared with this account were found.", level='INFO')

        elif args.command == 'template':
            if args.template_command is None: # Default to list if no subcommand is provided
                templates = manager.list_launch_templates()
                if templates:
                    Display.format_output_table(templates)
                else:
                    display.display("No matching launch templates found.", level='INFO')
            
            elif args.template_command == 'create':
                prefix = args.prefix or self._generate_prefix_from_owner(owner)
                
                if args.template_name:
                    template_name = args.template_name
                elif args.pattern:
                    template_name = f"{prefix}-{args.pattern}-template"
                else:
                    display.display("Error: You must provide either --template-name OR a pattern (-p) to generate the name.", level='ERROR')
                    sys.exit(1)

                display.display(f"Preparing to create launch template '{template_name}'...", level='INFO')

                # Resolve resource names to IDs
                vpc_name = args.vpc_name or config['vpc_name']
                subnet_name = args.subnet_name or config['subnet_name']
                sg_names = args.security_group_names or config['security_group_names']

                vpc_id = manager.get_vpc_id_by_name(vpc_name)
                if not vpc_id:
                    display.display(f"Could not resolve VPC '{vpc_name}'. Aborting.", level='ERROR')
                    sys.exit(1)

                if args.ami_name:
                    ami_id = manager.get_ami_id_by_name(args.ami_name)
                    if not ami_id:
                        display.display(f"Could not find AMI with name '{args.ami_name}'. Aborting.", level='ERROR')
                        sys.exit(1)
                else:
                    display.display("No AMI name provided. Fetching latest Artesca AMI...", level='INFO')
                    latest_ami = manager.get_latest_artesca_ami()
                    if latest_ami:
                         ami_id = latest_ami['ImageId']
                         display.display(f"Using latest AMI: {latest_ami['Name']} ({ami_id})", level='INFO')
                    else:
                         display.display("Could not find any Artesca AMIs to use as default. Aborting.", level='ERROR')
                         sys.exit(1)

                subnet_id = manager.get_subnet_id_by_name(subnet_name, vpc_id=vpc_id)
                sg_ids = manager.get_sg_ids_by_names(sg_names, vpc_id=vpc_id)

                if not all([ami_id, subnet_id, sg_ids]):
                    display.display("Could not resolve all required resources from names. Please check the arguments and the region. Aborting.", level='ERROR')
                    sys.exit(1)
                
                manager.create_launch_template(
                    template_name=template_name,
                    ami_id=ami_id,
                    instance_type=args.instance_type or config['instance_type'],
                    key_name=args.key_name or config['key_name'],
                    sg_ids=sg_ids,
                    subnet_id=subnet_id,
                    device_profile=args.device
                )

            elif args.template_command == 'delete':
                manager.delete_launch_template(args.template_name)

            elif args.template_command == 'show':
                manager.get_launch_template(args.template_name)

            else:
                display.display("Please specify a valid command for 'template': create, delete, or show.", level='INFO')
                sys.exit(1)

        else:
            self.parser.print_help()
            sys.exit(1)

    def _connect_initial_mode(self, ip_address, display, config):
        """Initial connection mode: uses root/scalityadmin, no keys, handles password change."""
        import time
        new_password = config.get('new_password', DEFAULT_RESET_PASSWORD)
        
        # Helper function for reading shell output
        def read_shell_until(shell, prompts, timeout=5, initial_buffer=""):
            if isinstance(prompts, str):
                prompts = [prompts]
            output = initial_buffer
            
            # Check initial buffer first!
            for p in prompts:
                if p.lower() in output.lower():
                    return output, True
                    
            start_time = time.time()
            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    data = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += data
                    display.display(f"[SERVER]: {data.strip()}", level='VERBOSE')
                    for p in prompts:
                        if p.lower() in output.lower():
                            return output, True
                time.sleep(0.1)
            display.display(f"DEBUG: Timeout reached. Output so far: {repr(output)}", level='DEBUG')
            return output, False

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            display.display(f"Initial Mode: Connecting to {ip_address} as '{SSH_USER}'...", level='INFO')
            # Look for keys = False, Allow Agent = False as requested
            client.connect(
                ip_address, 
                username=SSH_USER, 
                password=SSH_PASSWD, 
                port=22, 
                timeout=10, 
                look_for_keys=False, 
                allow_agent=False
            )

            shell = client.invoke_shell(term='vt100')
            time.sleep(1)
            initial_output = ""
            if shell.recv_ready():
                initial_output = shell.recv(4096).decode('utf-8', errors='ignore')
            
            # Check for password expiry or change prompt
            password_prompts = ["password has expired", "current password", "password:", "passwd:"]
            if any(p in initial_output.lower() for p in password_prompts):
                display.display("Initial Mode: Password change required.", level='INFO')
                
                # Wait for EITHER current password OR new password prompt
                next_prompts = ["current password", "current unix password", "new password:", "new password", "new unix password"]
                output, found = read_shell_until(shell, next_prompts, initial_buffer=initial_output, timeout=10)
                
                if not found:
                    display.display("Initial Mode: Could not find password change prompt. Aborting.", level='ERROR')
                    display.display("--- SERVER OUTPUT START ---", level='ERROR')
                    display.display(output, level='ERROR')
                    display.display("--- SERVER OUTPUT END ---", level='ERROR')
                    client.close()
                    return None

                # If it's a "current password" prompt, we need to send the old password first
                if any(p in output.lower() for p in ["current password", "current unix password"]):
                    display.display("Initial Mode: Prompted for current password. Sending...", level='VERBOSE')
                    shell.send(f"{SSH_PASSWD}\n")
                    # Now wait for the "new password" prompt
                    output, found = read_shell_until(shell, ["new password:", "new password", "new unix password"], timeout=10)
                    if not found:
                        display.display("Initial Mode: 'New password:' prompt not found after sending current password.", level='ERROR')
                        display.display(f"Server output: {output}", level='ERROR')
                        client.close()
                        return None
                else:
                    display.display("Initial Mode: Skipped 'Current password' prompt, already at 'New password'.", level='VERBOSE')

                # Now we are at the "New password" stage
                display.display("Initial Mode: Sending new password...", level='VERBOSE')
                shell.send(f"{new_password}\n")
                
                output, found = read_shell_until(shell, ["retype", "re-enter", "passwd:", "confirm"], timeout=10)
                if not found:
                    display.display("Initial Mode: 'Retype new password:' prompt not found. Aborting.", level='ERROR')
                    display.display(f"Server output: {output}", level='ERROR')
                    client.close()
                    return None
                    
                shell.send(f"{new_password}\n")
                time.sleep(1)
                display.display("Initial Mode: Password change successful.", level='INFO')
            else:
                display.display("Initial Mode: No password change required.", level='INFO')
            
            client.close()
            return new_password

        except paramiko.AuthenticationException:
            display.display(f"Initial Mode: Authentication failed for '{SSH_USER}'. Assuming already configured.", level='VERBOSE')
            return new_password # Assume it's already set to new_password
        except Exception as e:
            display.display(f"Initial Mode: Connection error: {e}", level='ERROR')
            return None

    def _configure_instance(self, ip_address, private_ip, instance_name, display, config):
        """Performs configuration (password, hostname, timezone) on a single instance."""
        if not paramiko:
            display.display("The 'paramiko' library is required for the 'configure' command.", level='ERROR')
            return

        # Phase 1: Initial Connection and Password Handling
        current_password = self._connect_initial_mode(ip_address, display, config)
        if not current_password:
            return

        # Phase 2: Configuration (Hostname, Timezone, /etc/hosts)
        timezone = config.get('timezone', 'Asia/Tokyo')
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            display.display(f"Phase 2: Connecting to {ip_address} as '{SSH_USER}' for configuration...", level='INFO')
            client.connect(
                ip_address, 
                username=SSH_USER, 
                password=current_password, 
                port=22, 
                timeout=10,
                look_for_keys=True,
                allow_agent=True
            )

            self._test_ssh_connection(client, display)

            # Clean up authorized_keys to allow direct root login
            display.display("modifying /root/.ssh/authorized_keys", level='INFO')
            sed_command = "sed -i 's/.*\\(ssh-ed25519\\|ssh-rsa\\|ssh-dss\\|ecdsa-sha2-nistp256\\)/\\1/' /root/.ssh/authorized_keys"
            stdin, stdout, stderr = client.exec_command(sed_command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                display.display("Successfully cleaned up /root/.ssh/authorized_keys.", level='DEBUG')
            else:
                err = stderr.read().decode('utf-8').strip()
                display.display(f"Failed to clean up authorized_keys: {err}", level='ERROR')

            # Set hostname
            display.display(f"Setting hostname to '{instance_name}'...", level='INFO')
            command = f"hostnamectl set-hostname {instance_name}"
            stdin, stdout, stderr = client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                display.display(f"Successfully set hostname to '{instance_name}'.", level='VERBOSE')
            else:
                error_output = stderr.read().decode('utf-8').strip()
                display.display(f"Failed to set hostname. Exit status: {exit_status}", level='ERROR')
                if error_output:
                    display.display(f"Error: {error_output}", level='ERROR')
            
            # Set timezone
            display.display(f"Setting timezone to '{timezone}'...", level='INFO')
            command = f"timedatectl set-timezone {timezone}"
            stdin, stdout, stderr = client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                display.display(f"Successfully set timezone to '{timezone}'.", level='VERBOSE')
            else:
                error_output = stderr.read().decode('utf-8').strip()
                display.display(f"Failed to set timezone. Exit status: {exit_status}", level='ERROR')
                if error_output:
                    display.display(f"Error: {error_output}", level='ERROR')

            # Change artesca-os password if --os flag is present
            if config.get('args') and getattr(config['args'], 'os', False):
                display.display("Changing password for user 'artesca-os'...", level='INFO')
                os_pwd_cmd = f"echo \"artesca-os:{current_password}\" | chpasswd"
                stdin, stdout, stderr = client.exec_command(os_pwd_cmd)
                exit_status = stdout.channel.recv_exit_status()
                if exit_status == 0:
                    display.display("Successfully changed password for 'artesca-os'.", level='VERBOSE')
                else:
                    err = stderr.read().decode('utf-8').strip()
                    display.display(f"Failed to change artesca-os password: {err}", level='ERROR')

            # Update /etc/hosts
            entries = []
            if private_ip and private_ip != 'N/A':
                entries.append((private_ip, instance_name))
            if ip_address and ip_address != 'N/A':
                entries.append((ip_address, f"{instance_name}-eip"))

            for ip, name in entries:
                display.display(f"Configuring /etc/hosts: {ip} {name}...", level='INFO')
                # Check if entry already exists (simple grep check)
                check_cmd = f"grep -q '{name}' /etc/hosts"
                stdin, stdout, stderr = client.exec_command(check_cmd)
                if stdout.channel.recv_exit_status() != 0:
                    # Entry not found, add it
                    # Align IP to 16 chars (standard IPv4 max len is 15)
                    entry_line = f"{ip:<16} {name}"
                    add_cmd = f"sh -c 'echo \"{entry_line}\" >> /etc/hosts'"
                    stdin, stdout, stderr = client.exec_command(add_cmd)
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        display.display(f"Successfully added '{name}' to /etc/hosts.", level='VERBOSE')
                    else:
                        error_output = stderr.read().decode('utf-8').strip()
                        display.display(f"Failed to add '{name}' to /etc/hosts. Exit: {exit_status}. Error: {error_output}", level='ERROR')
                else:
                    display.display(f"Entry for '{name}' already exists in /etc/hosts. Skipping.", level='VERBOSE')
            
            client.close()

        except paramiko.AuthenticationException:
            display.display(f"Phase 2: Authentication failed with the new password. Cannot configure hostname or timezone.", level='ERROR')
        except Exception as e:
            display.display(f"Phase 2: An error occurred during hostname or timezone configuration: {e}", level='ERROR')

    def _test_ssh_connection(self, client, display):
        """Tests SSH connection by executing 'hostname' command."""
        message = "Testing SSH connection ('hostname' command)..."
        try:
            stdin, stdout, stderr = client.exec_command("hostname", timeout=10)
            exit_status = stdout.channel.recv_exit_status() # Wait for command to finish
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()

            if exit_status == 0:
                display.display(f"{message} OK (hostname: {output})", level='INFO')
                return True
            else:
                display.display(f"{message} FAILED. Exit: {exit_status}. Stderr: {error}", level='ERROR')
                return False
        except Exception as e:
            display.display(f"{message} FAILED. Exception: {e}", level='ERROR')
            return False

if __name__ == "__main__":
    main_app = Main()
    main_app.run()
