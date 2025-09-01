#!/usr/bin/env python3
import boto3
import argparse

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
    def __init__(self, region):
        self.region = region
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
                return f"{vpc_name} ({vpc_id})"
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
                        subnets_info.append(f"{subnet_name} ({subnet_id})")
                    else:
                        subnets_info.append(f"N/A ({subnet_id})")
                else:
                    subnets_info.append('N/A')
        return subnets_info

    def get_instances_by_owner(self, owner_email, show_network_info, show_disk_info):
        """Retrieves data for EC2 instances by orchestrating helper methods."""
        instances_data = []
        try:
            response = self.ec2.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if self._get_tag_value(instance.get('Tags'), 'owner') != owner_email:
                        continue

                    instance_name = self._get_tag_value(instance.get('Tags'), 'Name')
                    instance_id = instance['InstanceId']

                    if show_disk_info:
                        instance_info = {
                            'ID': instance_id,
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
                                'Network': " | ".join(self._get_subnet_details(instance))
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

def main():
    """Main function to parse arguments and run the script."""
    parser = argparse.ArgumentParser(description="Script to list AWS EC2 resources.")
    parser.add_argument('-r', '--region', help="AWS region to use (default: ap-northeast-1).")
    parser.add_argument('-o', '--owner', help="Email of the instance owner to filter by.")
    parser.add_argument('-n', '--network', action='store_true', help="Displays detailed network information (AZ, VPC, Subnets).")
    parser.add_argument('-v', '--vpc', action='store_true', help="Searches for and displays VPCs containing 'scality' and their subnets.")
    parser.add_argument('-d', '--disk', action='store_true', help="Displays disk information (size and type).")
    args = parser.parse_args()

    aws_region = args.region if args.region else 'ap-northeast-1'
    target_owner = args.owner if args.owner else 'pierre.merle@scality.com'

    manager = AWSManager(region=aws_region)
    formatter = OutputFormatter()

    print(f"EC2 Instances owned by {target_owner} in region {aws_region}:")
    instances = manager.get_instances_by_owner(target_owner, args.network, args.disk)
    if not instances:
        print(f"No instances found for this owner in region {aws_region}.")
    else:
        formatter.format_output_table(instances)

    if args.vpc:
        print(f"\nSearching for 'scality' VPCs in region {aws_region}:")
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

if __name__ == "__main__":
    main()
