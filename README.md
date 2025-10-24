# scalws-tools

`scalws` is a command-line tool for interacting with Scaleway services.

## Installation

1.  Make sure you have Python 3 installed.
2.  Clone this repository: `git clone https://github.com/your-username/scalws-tools.git`
3.  Navigate to the project directory: `cd scalws-tools`
4.  Make the script executable: `chmod +x scalws.py`

## Usage

The `scalws` tool uses subcommands to group related operations.

### VM Management

These commands allow you to manage your VMs.

- `start <expression>`: Starts all VMs matching the regular expression.
- `stop <expression>`: Stops all VMs matching the regular expression.
- `terminate <expression>`: Terminates all VMs matching the regular expression.

Example:
```bash
./scalws.py start "my-vm-.*"
```

### Network

The `network` subcommand is used for network-related operations.

#### Add a network

To add a new network, use the `add` subcommand:

```bash
./scalws.py network add <network-name>
```

### VPC

The `vpc` subcommand is used for VPC-related operations.

#### Add a VPC

To add a new VPC, use the `add` subcommand:

```bash
./scalws.py vpc add <vpc-name>
```

#### Delete a VPC

To delete a VPC, use the `delete` subcommand:

```bash
./scalws.py vpc delete <vpc-name>
```

## Autocompletion

To enable bash autocompletion, source the `scalws_completion.bash` file in your `.bashrc` or `.bash_profile`:

```bash
echo "source $(pwd)/scalws_completion.bash" >> ~/.bashrc
```