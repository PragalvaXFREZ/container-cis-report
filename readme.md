#Docker Container CIS Audit Tool

## Audit Parameters:
-Checks if container runs as root
-Checks for SSH server presence
-Validates firewall (INPUT policy DROP)
-Verifies base image (eg. Alpine, Ubuntu)
-Checks for read-only filesystem
-Generates a detailed terminal + final report (.html)

## Requirements:
-Python 3
-Docker Engine
-Python Docker SDK

## How to run?

pip install docker

python cis_checker.py
