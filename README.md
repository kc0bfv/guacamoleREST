# GuacamoleREST

This tool administers an Apache Guacamole server via the not-officially-documented REST API.  The REST API documentation used is found here https://github.com/ridvanaltun/guacamole-rest-api-documentation

## Requirements

Python3

## Usage

Create a command file like `cmd.example`.  Run `guacREST.py` with your command file as the argument.

## Ansible Usage

This is really intended for use with Ansible.  You can create a command file with the template tool, then copy it and the script over to your target and run it.  The commands are such that if you run the tool multiple times with the same command file it will not create duplicate configuration entries.  Ones that already exist are left alone.
