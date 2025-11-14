# scalws-tools

`scalws` is a command-line tool for interacting with AWS services, tailored for Scality use cases.

## Installation

1.  Make sure you have Python 3 and `boto3` installed (`pip install boto3`).
2.  Clone this repository.
3.  Navigate to the project directory.
4.  Make the script executable: `chmod +x scalws.py`

## Configuration

- **AWS Credentials**: The script requires AWS credentials to be configured in your environment (e.g., via `~/.aws/credentials` or environment variables).
- **Default Owner**: The default owner for resources is `pierre.merle@scality.com`. You can override this with the `-o` or `--owner` flag.
- **Default Region**: The default region is `ap-northeast-1`. You can override this with the `-r` or `--region` flag.

## Usage

The `scalws` tool uses subcommands to group related operations.

### General Options

- `-r, --region`: Specify the AWS region.
- `-o, --owner`: Specify the owner's email.
- `-v, --verbose`: Enable verbose output.
- `-d, --debug`: Enable debug output.

### Instances (`instances`)

- `instances list` (default command): List EC2 instances with basic info.
- `instances disks <instance_name>`: List disks attached to a specific instance.

### VM Management (`start`, `stop`, `terminate`)

- `start <expression>`: Starts all VMs matching the regular expression.
- `stop <expression>`: Stops all VMs matching the regular expression.
- `terminate <expression>`: Terminates all VMs matching the regular expression.

Example:
```bash
./scalws.py start "my-vm-.*"
```

### Disk Management (`disk`)

- `disk list`: List all EBS volumes.
- `disk create <pattern> <start> <end> [--size <GiB>] [--type <type>]`: Create EBS volumes.
- `disk delete --pattern <pattern> [numbers...]` or `disk delete --volume-id <volume-id>`: Delete EBS volumes.
- `disk attach <vm_name>`: Attach available volumes to an instance.
- `disk new`: List unattached disks.

### Network Management (`network`)

- `network list`: List instances with detailed network info.
- `network interface`: List network interfaces.

### VPC Management (`vpc`)

- `vpc list`: List Scality VPCs and their subnets.

### Elastic IP Management (`eip`)

- `eip list`: List all EIPs.
- `eip attach <ip_address> <instance_name>`: Attach an EIP to an instance.
- `eip detach <ip_address>`: Detach an EIP from an instance.

### Security Group Management (`secg`)

- `secg`: List security groups for owned instances.

## Autocompletion

To enable bash autocompletion, source the `scalws_completion.bash` file in your `.bashrc` or `.bash_profile`:

```bash
echo "source $(pwd)/scalws_completion.bash" >> ~/.bashrc
```
