# scalws-tools

There are 2 tools to manage AWS machines. 

`scalws` is a command-line tool for interacting with AWS services :
-  Simplify start/stop of group of machines by using pattern matching 
-  Get various informations on network/vpc/eip difficult to get all together in the UI 
-  Create/Attach/Detach/Delete bunch of disks of an instance (typically to test disk addition)

`labws` is an helper to create and configure artesca labs. 
-   Launch a bunch of machine is one command
-   Configure passwd and set up hostname/timezone 
-   Show lab configuration 


## Configuration

- **AWS Credentials**: The script requires AWS credentials using environement keys you get from onelogin
- **Default Owner**: The default owner for resources is `pierre.merle@scality.com`. You can override this with the `-o` or `--owner` flag.
- **Default Region**: The default region is `ap-northeast-1`. You can override this with the `-r` or `--region` flag.

## Usage - SCALWS

The `scalws` tool uses subcommands to group related operations. There are two main types of actions: VM management and resource management.

### General Options

- `-r, --region`: Specify the AWS region.
- `-o, --owner`: Specify the owner's email.
- `-v, --verbose`: Enable verbose output.
- `-d, --debug`: Enable debug output.
- `-z, --availability-zone`: The Availability Zone for resource creation.

### VM Management

These commands allow you to manage the lifecycle of your VMs.

- `start <expression>`: Starts all VMs matching the string
- `stop <expression>`: Stops all VMs matching the string
- `terminate <expression>`: Terminates all VMs matching string

The regex is matching the full string against all vm. You can use several strings.

Example:
```bash
./scalws.py start 943 arte
QUERY: Do you want to start these 5 vm(s)? (Enter to confirm/Ctl C to abort) 
pme_943_supervisor pme_943_store-3 pme_943_store-1 pme_943_store-2 pme_943_client pme-arte-demo1

```

It will match all VM belonging to the owner and propose to start them. Just hit enter to run the action. Same for Stop. For Terminate there will be confirmations.
The pattern matching only works for stop/start/terminate.

### Resource Management

These commands allow you to manage various AWS resources.

#### Instances (`instances`)

- `instances list` (default command): List EC2 instances with basic info.
- `instances disks <instance_name>`: List disks attached to a specific instance.

#### Disk Management (`disk`)

- `disk list`: List all EBS volumes.
- `disk create <pattern> <start> <end> [--size <GiB>] [--type <type>]`: Create EBS volumes.
- `disk delete --pattern <pattern> [numbers...]` or `disk delete --volume-id <volume-id>`: Delete EBS volumes.
- `disk attach <vm_name>`: Attach available volumes to an instance.
- `disk new`: List unattached disks.

Example: Create 12 disks and attach them to 'my-vm'.
```bash
./scalws.py disk create my-vm-disk- 1 12 --size 100 --type gp3
./scalws.py disk attach my-vm
```

#### Network Management (`network`)

- `network list`: List instances with detailed network info.
- `network interface`: List network interfaces.

#### VPC Management (`vpc`)

- `vpc list`: List Scality VPCs and their subnets.

#### Elastic IP Management (`eip`)

- `eip list`: List all EIPs.
- `eip attach <ip_address> <instance_name>`: Attach an EIP to an instance.
- `eip detach <ip_address>`: Detach an EIP from an instance.

Unlike other commands eip list all eip with owner. You can then attach a free ip to your instance

#### Security Group Management (`secg`)

- `secg`: List security groups for owned instances.

## Installation

1.  Make sure you have Python 3 and `boto3` installed (`pip install boto3`).
2.  Clone this repository.
3.  Navigate to the project directory.
4.  Make the script executable: `chmod +x scalws.py`


## Autocompletion

To enable bash autocompletion, source the `scalws_completion.bash` file in your `.bashrc` or `.bash_profile`:

```bash
echo "source $(pwd)/scalws_completion.bash" >> ~/.bashrc
```

## Usage - LABWS

### `labws.py`

This script is used to manage lab environments, specifically for creating, showing, and configuring EC2 instances from a template.

#### Subcommands

##### `build`

Creates and configures a specified number of EC2 instances. It checks for existing instances with the same name and will not create duplicates.

*   **Usage:** `./labws.py build -c <count> [-x <prefix>] [-p <pattern>]`
*   **Arguments:**
    *   `-c, --count`: (Required) The number of machines to create.
    *   `-x, --prefix`: The prefix for the instance names. If not provided, a prefix is generated from the owner's email (e.g., 'pme').
    *   `-p, --pattern`: The pattern for the instance names. Defaults to 'vm'.
*   **Example:** `./labws.py build -c 2 -x pme -p lab` will create two instances named `pme-lab-01` and `pme-lab-02`.

##### `show`

Displays information about existing lab resources. By default, it shows instances and their status, including hostname and timezone information retrieved via SSH.
Without argument it will show machines created via this tool (owned by same owner)

*   **Usage:** `./labws.py show [-x <prefix>] [-p <pattern>] [-e]`
*   **Arguments:**
    *   `-x, --prefix`: The prefix to filter by.
    *   `-p, --pattern`: The pattern to filter by. Defaults to 'vm'.
    *   `-e, --eip`: If specified, lists Elastic IPs instead of instances.
*   **Example:** `./labws.py show -x pme -p lab` will show instances matching the prefix 'pme' and pattern 'lab'.

##### `configure`

Configures one or more existing instances based on their prefix and pattern. This command performs the following actions on each matching instance:
1.  Handles the initial forced password change for the `artesca-os` user.
2.  Sets the instance hostname to match its `Name` tag.
3.  Sets the timezone to the default value.

*   **Usage:** `./labws.py configure [-x <prefix>] [-p <pattern>]`
*   **Arguments:**
    *   `-x, --prefix`: The prefix of the instances to configure.
    *   `-p, --pattern`: The pattern of the instances to configure. Defaults to 'vm'.
*   **Example:** `./labws.py configure -x pme -p lab` will run the configuration process on all instances matching the prefix 'pme' and pattern 'lab'.
