### `labws.py`

This script is used to manage lab environments for Artesca on scality AWS.
The machines name will be <prefix>-<pattern>-<number> (see build below) and you can create multiple machines with -c option
The prefix is based on your email firsname 1 letter + lastname 2 letter. If you want to change you can use -x but in this case you'll need -x for all this lab operations.
The pattern is mandatory and will be used as exact pattern
The number will be 2 digit based on the count (option -c defaut 1) option
The AMI will use the latest artesca one. 
You need to setup your own environement with email/region etc ... ( 

The base usage is : 
./labws.py build -p labtrain -c 3  

It will create a template and then 3 machines named fla-labtrain-01 (fla for first.last). 
You do not need -c for other options. 

Next step is configure machine (with root to leave artesca-os untouched for training) with this command 
./labws.py configure -p labtrain 

It will change hostname/timezone etc ...  

When you are done with the lab you can destroy all machines with 
./labws.py destroy -p labtrain 

#### First start

When you run the script the fix time make sure you run the env subcommand to create you local environement file.
`./labws.py env create`


#### Subcommands

##### `build`

Creates and configures a specified number of EC2 instances. It checks for existing instances with the same name and will not create duplicates.

*   **Usage:** `./labws.py build -c <count> [-x <prefix>] [-p <pattern>] [-t template]`
*   **Arguments:**
    *   `-a, --count`: (Required) The number of machines to create.
    *   `-c, --count`: (Required) The number of machines to create.
    *   `-x, --prefix`: The prefix for the instance names. If not provided, a prefix is generated from the owner's email (e.g., 'pme').
    *   `-p, --pattern`: The pattern for the instance names. Defaults to 'vm'.
    *   `-t, --template`: The name of the launch template to use. If not specified, uses `pme-arte-minidisk` (or configured default). If no name is given (`-t`), uses the configured default.
*   **Example:** `./labws.py build -c 2 -x pme -p lab` will create two instances named `pme-lab-01` and `pme-lab-02` using the default template.

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


##### `env`

Manages local environment configuration (`~/.labws.conf`), allowing you to override default values like owner, region, instance type, and passwords.

*   **Usage:**
    *   `./labws.py env show`: Shows current configuration (hardcoded defaults + config file).
    *   `./labws.py env create`: Creates a default configuration file if it doesn't exist.

##### `ami`

Lists AMIs shared with your account, specifically those starting with `artesca-`. Useful for finding the `ami-id` needed for creating templates.

*   **Usage:** `./labws.py ami [--all]`
*   **Arguments:**
    *   `--all`: Show all versions, including dev, preview, and rc builds. By default, these are hidden.

##### `template`

Manages AWS Launch Templates.

*   **Usage:**
    *   `./labws.py template [show]`: Lists your launch templates (default action).
    *   `./labws.py template show --template-name <name>`: detailed view of a template.
    *   `./labws.py template delete --template-name <name>`: deletes a template.
    *   `./labws.py template create --ami-name <ami-name> [options]`: creates a new template.
*   **Create Arguments:**
    *   `--template-name`: Name for the new template.
    *   `--ami-name`: (Required) Name of the base AMI.
    *   `--devtype`: Disk configuration. `lofs` (default, 100GB root, no extra disks) or `device` (50GB root + standard extra disks).
    *   Other standard options: `--instance-type`, `--key-name`, `--vpc-name`, `--subnet-name`, `--security-group-names`.

##### `destroy`

Destroys instances and all associated resources (EIPs, Volumes) matching a prefix and pattern.

*   **Usage:** `./labws.py destroy [-x <prefix>] [-p <pattern>]`
*   **Example:** `./labws.py destroy -x pme -p lab` will terminate instances `pme-lab-*`, release their EIPs, and delete their attached volumes.
