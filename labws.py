#!/usr/bin/env python3
import argparse
import sys
import os
import boto3
try:
    import paramiko
except ImportError:
    paramiko = None
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

# --- Constants ---
DEFAULT_REGION = 'ap-northeast-1'
DEFAULT_OWNER = 'pierre.merle@scality.com'
DEFAULT_LAUNCH_TEMPLATE = 'pme-arte-minidisk' # Hardcoded Launch Template Name
DEFAULT_NEW_PASSWORD = "150.249.201.205ONssh:notty"
DEFAULT_TIMEZONE = 'Asia/Tokyo'

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
            self.display.display("Authentication Error: AWS credentials not found or incomplete.", level='ERROR')
            sys.exit(1)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':
                self.display.display("Authentication Error: The provided AWS credentials could not be validated.", level='ERROR')
                sys.exit(1)
            else:
                self.display.display(f"An AWS service error occurred: {e}", level='ERROR')
                sys.exit(1)

    def launch_instance_from_template(self, launch_template_name, instance_name):
        """Launches an EC2 instance from a specified launch template."""
        try:
            self.display.display(f"Launching instance '{instance_name}' from template '{launch_template_name}'...", level='INFO')
            response = self.ec2.run_instances(
                LaunchTemplate={'LaunchTemplateName': launch_template_name},
                MinCount=1,
                MaxCount=1
            )
            instance_id = response['Instances'][0]['InstanceId']
            self.display.display(f"Successfully initiated launch for instance '{instance_name}' with ID '{instance_id}'.", level='INFO')
            
            waiter = self.ec2.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instance_id])
            self.display.display(f"Instance '{instance_name}' ({instance_id}) is now running.", level='INFO')

            self.ec2.create_tags(
                Resources=[instance_id],
                Tags=[
                    {'Key': 'Name', 'Value': instance_name},
                    {'Key': 'owner', 'Value': self.owner},
                    {'Key': 'artesca_lab', 'Value': 'yes'}
                ]
            )
            self.display.display(f"Successfully tagged instance '{instance_name}'.", level='INFO')
            
            return instance_id
        except ClientError as e:
            self.display.display(f"An AWS error occurred while launching instance '{instance_name}': {e}", level='ERROR')
            return None

    def create_and_assign_eip(self, instance_id, instance_name):
        """Allocates a new EIP, names it, and associates it with an instance."""
        try:
            self.display.display(f"Allocating new EIP for {instance_name}...", level='INFO')
            eip_response = self.ec2.allocate_address(Domain='vpc')
            allocation_id = eip_response['AllocationId']
            public_ip = eip_response['PublicIp']
            self.display.display(f"Successfully allocated EIP '{public_ip}'.", level='INFO')

            eip_name = f"{instance_name}-labeip"
            self.ec2.create_tags(
                Resources=[allocation_id],
                Tags=[{'Key': 'Name', 'Value': eip_name}]
            )
            self.display.display(f"Successfully tagged EIP as '{eip_name}'.", level='INFO')

            self.display.display(f"Associating EIP '{public_ip}' with instance '{instance_id}'...", level='INFO')
            self.ec2.associate_address(AllocationId=allocation_id, InstanceId=instance_id)
            self.display.display(f"Successfully associated EIP '{public_ip}' with instance '{instance_id}'.", level='INFO')
            
            return public_ip
        except ClientError as e:
            self.display.display(f"An AWS error occurred during EIP creation or assignment: {e}", level='ERROR')
            return None

    def list_instances_by_prefix_and_pattern(self, prefix, pattern, get_ssh_details=False):
        """Lists instances that match a given prefix and pattern. Optionally gets hostname and timezone via SSH."""
        try:
            self.display.display(f"Listing instances with prefix '{prefix}' and pattern '{pattern}'...", level='INFO')
            
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

    def _get_ssh_details(self, ip_address):
        """Connects to an instance via SSH to get hostname and timezone."""
        if not paramiko:
            return 'NO_PARAMIKO', 'NO_PARAMIKO'

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        passwords_to_try = [DEFAULT_NEW_PASSWORD, 'scality']
        
        for password in passwords_to_try:
            try:
                client.connect(ip_address, username='artesca-os', password=password, port=22, timeout=5)
                
                # Get hostname
                stdin, stdout, stderr = client.exec_command("hostname -s", timeout=5)
                hostname = stdout.read().decode('utf-8').strip() or 'EMPTY'
                
                # Get timezone
                stdin, stdout, stderr = client.exec_command("date +%Z", timeout=5)
                timezone = stdout.read().decode('utf-8').strip() or 'EMPTY'
                
                client.close()
                return hostname, timezone
            except Exception as e:
                self.display.display(f"SSH connection to {ip_address} with one of the passwords failed: {e}", level='DEBUG')
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

class TemplateManager:
    """Manages launching instances from templates."""

    def __init__(self, aws_manager, display):
        self.aws_manager = aws_manager
        self.display = display

    def launch_instances(self, count, prefix, pattern, launch_template_name):
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

        self.display.display("The following new resources will be created:", level='INFO')
        Display.format_output_table(instances_to_actually_create)

        try:
            confirm = self.display.query("Do you want to proceed with creation? (y/n): ")
        except KeyboardInterrupt:
            self.display.display("\nOperation cancelled by user.", level='INFO')
            sys.exit(1)
            
        if confirm.lower() != 'y':
            self.display.display("Operation cancelled by user.", level='INFO')
            sys.exit(0)

        self.display.display(f"User confirmed. Preparing to launch {len(instances_to_actually_create)} instance(s).", level='INFO')

        for instance_to_create in instances_to_actually_create:
            instance_name = instance_to_create['Name']
            self.display.display(f"--- Processing instance: {instance_name} ---", level='INFO')
            
            instance_id = self.aws_manager.launch_instance_from_template(launch_template_name, instance_name)
            if not instance_id:
                self.display.display(f"Failed to launch instance '{instance_name}'. Aborting.", level='ERROR')
                break
            
            public_ip = self.aws_manager.create_and_assign_eip(instance_id, instance_name)
            if not public_ip:
                self.display.display(f"Failed to create or assign EIP for instance '{instance_name}'.", level='ERROR')
            
            self.display.display(f"Successfully launched and configured '{instance_name}' with Public IP '{public_ip}'.", level='INFO')

class Main:
    def __init__(self):
        self.parser = self._create_parser()

    def _create_parser(self):
        parser = argparse.ArgumentParser(description="Script to manage lab environments on AWS.")
        parser.add_argument('-r', '--region', help=f"AWS region to use (default: {DEFAULT_REGION}).")
        parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output.")
        parser.add_argument('-d', '--debug', action='store_true', help="Enable debug output.")
        parser.add_argument('-o', '--owner', help="Email of the owner to filter by.")
        
        subparsers = parser.add_subparsers(dest='command', help='Sub-command help')

        # Build subcommand
        descript="To build lab use build opption with -c for number of machine and then prefix and pattern.\nThe machines will be named <prefix>-<pattern>-<count>. prefix is build from user email by default"
        destript=descript+"\n configure will do basic system config like change hostname and add EIP"
        build_parser = subparsers.add_parser('build', help="Build machines.")
        build_parser.add_argument('-c', '--count', type=int, required=True, help="The number of machines to start.")
        build_parser.add_argument('-x', '--prefix', help="The prefix for the machine name. If not provided, it will be generated from the owner's email.")
        build_parser.add_argument('-p', '--pattern', default='vm', help="The pattern for the machine name (e.g., 'server'). Default is 'vm'.")

        # Show subcommand
        show_parser = subparsers.add_parser('show', help='Show resources.')
        show_parser.add_argument('-e', '--eip', action='store_true', help="List EIPs matching the prefix and pattern.")
        show_parser.add_argument('-x', '--prefix', help="The prefix for the machine name. If not provided, it will be generated from the owner's email.")
        show_parser.add_argument('-p', '--pattern', default='vm', help="The pattern for the machine name (e.g., 'server'). Default is 'vm'.")

        # Configure subcommand
        configure_parser = subparsers.add_parser('configure', help='Configure machines based on prefix and pattern.')
        configure_parser.add_argument('-x', '--prefix', help="The prefix for the machine name. If not provided, it will be generated from the owner's email.")
        configure_parser.add_argument('-p', '--pattern', default='vm', help="The pattern for the machine name (e.g., 'server'). Default is 'vm'.")

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
        
        level = 'INFO'
        if args.verbose:
            level = 'VERBOSE'
        if args.debug:
            level = 'DEBUG'

        display = Display(level=level)

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

        aws_region = args.region or DEFAULT_REGION
        owner = args.owner or DEFAULT_OWNER
        launch_template = DEFAULT_LAUNCH_TEMPLATE

        manager = AWSManager(region=aws_region, display=display, owner=owner)

        if args.command == 'build':
            prefix = args.prefix or self._generate_prefix_from_owner(owner)
            pattern = args.pattern
            template_manager = TemplateManager(aws_manager=manager, display=display)
            template_manager.launch_instances(args.count, prefix, pattern, launch_template)
        
        elif args.command == 'show':
            prefix = args.prefix or self._generate_prefix_from_owner(owner)
            pattern = args.pattern
            
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
            
            display.display(f"Finding instances with prefix '{prefix}' and pattern '{pattern}' to configure...", level='INFO')
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
                
                if not ip or ip == 'N/A':
                    display.display(f"Skipping instance '{name}' because it has no public IP.", level='INFO')
                    continue
                
                display.display(f"--- Configuring instance: {name} ({ip}) ---", level='INFO')
                self._configure_instance(ip, name, display)

        else:
            self.parser.print_help()
            sys.exit(1)

    def _configure_instance(self, ip_address, instance_name, display):
        """Performs configuration (password, hostname, timezone) on a single instance."""
        if not paramiko:
            display.display("The 'paramiko' library is required for the 'configure' command.", level='ERROR')
            display.display("Please install it by running: pip install paramiko", level='ERROR')
            return

        import time

        def read_shell_until(shell, prompt, timeout=5):
            """Reads from a paramiko shell until a prompt is found or timeout occurs."""
            output = ""
            start_time = time.time()
            while time.time() - start_time < timeout:
                if shell.recv_ready():
                    output += shell.recv(1024).decode('utf-8', errors='ignore')
                    if prompt in output:
                        return output, True
                time.sleep(0.1)
            display.display(f"Timeout waiting for prompt: '{prompt}'", level='DEBUG')
            display.display(f"Full shell output:\n{output}", level='DEBUG')
            return output, False

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        current_password = None

        try:
            display.display(f"Attempting to connect to {ip_address} with initial password 'scality'...", level='INFO')
            client.connect(ip_address, username='artesca-os', password='scality', port=22, timeout=10)
            
            shell = client.invoke_shell(term='vt100')
            output, found = read_shell_until(shell, "Current password:")
            
            if not found:
                display.display("No password change prompt. Assuming 'scality' is the correct, non-expired password.", level='INFO')
                current_password = 'scality'
            else:
                display.display("Password change required. Proceeding with interactive change...", level='INFO')
                shell.send("scality\n")
                output, found = read_shell_until(shell, "New password:")
                if not found:
                    display.display("Did not receive 'New password:' prompt. Aborting configuration for this instance.", level='ERROR')
                    client.close()
                    return

                shell.send(f"{DEFAULT_NEW_PASSWORD}\n")
                output, found = read_shell_until(shell, "Retype new password:")
                if not found:
                    display.display("Did not receive 'Retype new password:' prompt. Aborting configuration for this instance.", level='ERROR')
                    client.close()
                    return
                    
                shell.send(f"{DEFAULT_NEW_PASSWORD}\n")
                time.sleep(1) # Give server time to process
                
                display.display("Password change sequence completed. Assuming password is now the new default.", level='INFO')
                current_password = DEFAULT_NEW_PASSWORD
            
            client.close()

        except paramiko.AuthenticationException:
            display.display("Authentication failed with 'scality'. Assuming password has already been changed.", level='VERBOSE')
            current_password = DEFAULT_NEW_PASSWORD
            client.close()
        except Exception as e:
            display.display(f"An unexpected error occurred during initial connection attempt: {e}", level='ERROR')
            return

        if current_password:
            client = paramiko.SSHClient() # Re-initialize client for the second connection
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                display.display(f"Connecting to {ip_address} to configure hostname and timezone...", level='INFO')
                client.connect(ip_address, username='artesca-os', password=current_password, port=22, timeout=10)

                self._test_ssh_connection(client, display)

                # Set hostname
                display.display(f"Setting hostname to '{instance_name}'...", level='INFO')
                command = f"echo '{current_password}' | sudo -S hostnamectl set-hostname {instance_name}"
                stdin, stdout, stderr = client.exec_command(command)
                exit_status = stdout.channel.recv_exit_status()
                if exit_status == 0:
                    display.display(f"Successfully set hostname to '{instance_name}'.", level='INFO')
                else:
                    error_output = stderr.read().decode('utf-8').strip()
                    display.display(f"Failed to set hostname. Exit status: {exit_status}", level='ERROR')
                    if error_output:
                        display.display(f"Error: {error_output}", level='ERROR')
                
                # Set timezone
                display.display(f"Setting timezone to '{DEFAULT_TIMEZONE}'...", level='INFO')
                command = f"echo '{current_password}' | sudo -S timedatectl set-timezone {DEFAULT_TIMEZONE}"
                stdin, stdout, stderr = client.exec_command(command)
                exit_status = stdout.channel.recv_exit_status()
                if exit_status == 0:
                    display.display(f"Successfully set timezone to '{DEFAULT_TIMEZONE}'.", level='INFO')
                else:
                    error_output = stderr.read().decode('utf-8').strip()
                    display.display(f"Failed to set timezone. Exit status: {exit_status}", level='ERROR')
                    if error_output:
                        display.display(f"Error: {error_output}", level='ERROR')
                
                client.close()

            except paramiko.AuthenticationException:
                display.display(f"Authentication failed with the new password. Cannot configure hostname or timezone.", level='ERROR')
            except Exception as e:
                display.display(f"An error occurred during hostname or timezone configuration: {e}", level='ERROR')

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
