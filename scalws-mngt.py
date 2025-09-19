#!/usr/bin/env python3
import argparse
import boto3
import sys
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

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

class AWSResourceManager:
    """Manages creation and deletion of AWS resources."""

    def __init__(self, region):
        self.region = region
        try:
            self.ec2 = boto3.client('ec2', region_name=self.region)
            # A simple, low-cost API call to check credentials early
            self.ec2.describe_regions()
        except (NoCredentialsError, PartialCredentialsError):
            print("Authentication Error: AWS credentials not found or incomplete.")
            sys.exit(1)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':
                print("Authentication Error: The provided AWS credentials could not be validated.")
                sys.exit(1)
            else:
                print(f"An AWS service error occurred: {e}")
                sys.exit(1)

    def _get_tag_value(self, tags, key):
        """Helper function to extract a tag value from a list of tags."""
        if tags:
            for tag in tags:
                if tag['Key'] == key:
                    return tag['Value']
        return None

    def create_disks(self, pattern, start, end, size, vol_type, availability_zone, owner):
        """Creates EBS volumes after checking for existing ones and asking for confirmation."""
        target_names = [f"{pattern}{i}" for i in range(start, end + 1)]

        try:
            response = self.ec2.describe_volumes(Filters=[{'Name': 'tag:owner', 'Values': [owner]}])
            existing_names = {self._get_tag_value(vol.get('Tags'), 'Name') for vol in response['Volumes']}
        except ClientError as e:
            print(f"An AWS service error occurred: {e}")
            sys.exit(1)

        conflicts = [name for name in target_names if name in existing_names]
        if conflicts:
            print(f"\nError: The following disks already exist for owner {owner}:")
            for name in conflicts:
                print(f"- {name}")
            print("No disks will be created.")
            sys.exit(1)

        print("\nThe following resources will be created:")
        disks_to_create = []
        for name in target_names:
            disks_to_create.append({
                'Name': name, 'Size': f"{size} GiB", 'Type': vol_type,
                'Owner': owner, 'Region': self.region, 'AZ': availability_zone
            })
        formatter = OutputFormatter()
        formatter.format_output_table(disks_to_create)
        
        try:
            confirm = input("\nDo you want to proceed with creation? (y/n): ")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(1)
            
        if confirm.lower() != 'y':
            print("Operation cancelled by user.")
            sys.exit(0)

        print("\nUser confirmed. Proceeding with disk creation...")
        for name in target_names:
            try:
                print(f"Creating disk '{name}'...")
                self.ec2.create_volume(
                    Size=size, VolumeType=vol_type, AvailabilityZone=availability_zone,
                    TagSpecifications=[{'ResourceType': 'volume', 'Tags': [{'Key': 'Name', 'Value': name}, {'Key': 'owner', 'Value': owner}]}]
                )
                print(f"Successfully initiated creation for disk '{name}'.")
            except ClientError as e:
                print(f"An AWS error occurred while creating disk '{name}': {e}")
                print("Stopping due to error.")
                sys.exit(1)
        
        print(f"\nSuccessfully initiated creation for {len(target_names)} disks.")

    def delete_disks(self, pattern, numbers, owner):
        """Deletes EBS volumes after confirmation."""
        disks_to_delete = []
        
        try:
            paginator = self.ec2.get_paginator('describe_volumes')
            pages = paginator.paginate(Filters=[{'Name': 'tag:owner', 'Values': [owner]}])
            
            all_volumes = [vol for page in pages for vol in page['Volumes']]

            if not numbers:
                for vol in all_volumes:
                    name = self._get_tag_value(vol.get('Tags'), 'Name')
                    if name and name.startswith(pattern):
                        disks_to_delete.append(vol)
            else:
                target_names = {f"{pattern}{n}" for n in numbers}
                for vol in all_volumes:
                    name = self._get_tag_value(vol.get('Tags'), 'Name')
                    if name in target_names:
                        disks_to_delete.append(vol)
        except ClientError as e:
            print(f"An AWS service error occurred: {e}")
            sys.exit(1)

        if not disks_to_delete:
            print("No matching disks found to delete.")
            return

        print("\nThe following disks will be DELETED:")
        delete_summary = [{
            'ID': vol['VolumeId'], 'Name': self._get_tag_value(vol.get('Tags'), 'Name'),
            'Size': f"{vol['Size']} GiB", 'State': vol['State'], 'AZ': vol['AvailabilityZone']
        } for vol in disks_to_delete]
        
        formatter = OutputFormatter()
        formatter.format_output_table(delete_summary)

        try:
            confirm = input("\nDo you want to proceed with deletion? (y/n): ")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            sys.exit(1)
        
        if confirm.lower() != 'y':
            print("Operation cancelled by user.")
            sys.exit(0)

        print("\nUser confirmed. Proceeding with disk deletion...")
        for vol in disks_to_delete:
            vol_id = vol['VolumeId']
            vol_name = self._get_tag_value(vol.get('Tags'), 'Name')
            try:
                print(f"Deleting disk '{vol_name}' ({vol_id})...")
                self.ec2.delete_volume(VolumeId=vol_id)
                print(f"Successfully initiated deletion for disk '{vol_name}'.")
            except ClientError as e:
                if e.response['Error']['Code'] == 'VolumeInUse':
                    print(f"Error: Disk '{vol_name}' ({vol_id}) is currently in use and cannot be deleted.")
                else:
                    print(f"An AWS error occurred while deleting disk '{vol_name}': {e}")
                print("Stopping due to error.")
                sys.exit(1)
        
        print(f"\nSuccessfully initiated deletion for {len(disks_to_delete)} disks.")

    def list_disks(self, owner):
        """Lists all EBS volumes for a given owner, sorted by instance name."""
        print(f"Listing disks for owner: {owner} in region: {self.region}")
        try:
            paginator = self.ec2.get_paginator('describe_volumes')
            pages = paginator.paginate(Filters=[{'Name': 'tag:owner', 'Values': [owner]}])
            all_volumes = [vol for page in pages for vol in page['Volumes']]

            if not all_volumes:
                print("No disks found for this owner.")
                return

            # Gather instance IDs from attached volumes
            instance_ids = [vol['Attachments'][0]['InstanceId'] for vol in all_volumes if vol.get('Attachments')]
            instance_name_map = {}
            if instance_ids:
                instance_response = self.ec2.describe_instances(InstanceIds=instance_ids)
                for reservation in instance_response['Reservations']:
                    for instance in reservation['Instances']:
                        instance_name_map[instance['InstanceId']] = self._get_tag_value(instance.get('Tags'), 'Name') or 'N/A'

            # Prepare data for display
            disk_summary = []
            for vol in all_volumes:
                instance_name = 'Unattached'
                if vol.get('Attachments'):
                    instance_id = vol['Attachments'][0]['InstanceId']
                    instance_name = instance_name_map.get(instance_id, instance_id) # Default to ID if name not found
                
                disk_summary.append({
                    'Instance Name': instance_name,
                    'Name': self._get_tag_value(vol.get('Tags'), 'Name'),
                    'ID': vol['VolumeId'],
                    'Size': f"{vol['Size']} GiB",
                })

            # Sort by Instance Name
            disk_summary.sort(key=lambda x: x['Instance Name'])

            formatter = OutputFormatter()
            formatter.format_output_table(disk_summary)

        except ClientError as e:
            print(f"An AWS service error occurred: {e}")
            sys.exit(1)

def main():
    """Main function to parse arguments and run the script."""
    parser = argparse.ArgumentParser(description="Script to manage AWS resources in bulk.")
    parser.add_argument('-r', '--region', default='ap-northeast-1', help="AWS region to use.")
    parser.add_argument('-o', '--owner', default='pierre.merle@scality.com', help="Email of the resource owner.")

    subparsers = parser.add_subparsers(dest='action', help='The action to perform: create or delete.', required=True)

    # Create parser
    create_parser = subparsers.add_parser('create', help='Create resources.')
    create_parser.add_argument('resource', choices=['disk'], help="The type of resource to create.")
    create_parser.add_argument('pattern', help="The naming pattern for the resources (e.g., 'my-disk-').")
    create_parser.add_argument('start', type=int, help="The starting number for the sequence.")
    create_parser.add_argument('end', type=int, help="The ending number for the sequence.")
    create_parser.add_argument('--size', type=int, default=1, help="The size of each disk in GiB (default: 1).")
    create_parser.add_argument('--type', default='gp3', help="The volume type (default: gp3).")
    create_parser.add_argument('-z', '--availability-zone', default='ap-northeast-1a', help="The Availability Zone for creation.")

    # Delete parser
    delete_parser = subparsers.add_parser('delete', help='Delete resources.')
    delete_parser.add_argument('resource', choices=['disk'], help="The type of resource to delete.")
    delete_parser.add_argument('pattern', help="The naming pattern or prefix.")
    delete_parser.add_argument('numbers', nargs='*', type=int, help="(Optional) Specific numbers to append to the pattern.")

    # List parser
    list_parser = subparsers.add_parser('list', help='List resources.')
    list_parser.add_argument('resource', choices=['disk'], help='The type of resource to list.')

    args = parser.parse_args()
    manager = AWSResourceManager(region=args.region)

    if args.action == 'create':
        if args.resource == 'disk':
            if args.start > args.end:
                print("Error: The start number cannot be greater than the end number.")
                sys.exit(1)
            manager.create_disks(args.pattern, args.start, args.end, args.size, args.type, args.availability_zone, args.owner)
    elif args.action == 'delete':
        if args.resource == 'disk':
            manager.delete_disks(args.pattern, args.numbers, args.owner)
    elif args.action == 'list':
        if args.resource == 'disk':
            manager.list_disks(args.owner)

if __name__ == "__main__":
    main()