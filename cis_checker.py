import docker
import os  
from datetime import datetime  

def check_container(container_id):
    client = docker.from_env()

    try:
        container = client.containers.get(container_id)
        print(f"\nChecking security for container: {container_id}...\n")
        
        results = []

        # 1. Check if running as root
        check_root = container.exec_run("id -u").output.decode().strip()
        if check_root == "0":
            results.append({
                "check_id": "1.1.1",
                "description": "Running as root",
                "current_value": "root",
                "expected_value": "Non-root user",
                "status": "FAIL",
                "suggestion": "Avoid running containers as root",
                "rating": 2
            })
        else:
            results.append({
                "check_id": "1.1.1",
                "description": "Running as root",
                "current_value": "Non-root user",
                "expected_value": "Non-root user",
                "status": "PASS",
                "suggestion": "",
                "rating": 10
            })

        # 2. Check if SSH is installed
        check_ssh = container.exec_run("which sshd").exit_code
        if check_ssh == 0:
            results.append({
                "check_id": "1.2.1",
                "description": "SSH Server installed",
                "current_value": "Installed",
                "expected_value": "Not Installed",
                "status": "FAIL",
                "suggestion": "Remove SSH server from the container",
                "rating": 3
            })
        else:
            results.append({
                "check_id": "1.2.1",
                "description": "SSH Server installed",
                "current_value": "Not Installed",
                "expected_value": "Not Installed",
                "status": "PASS",
                "suggestion": "",
                "rating": 10
            })

        # 3. Check firewall rules
        check_firewall = container.exec_run("iptables -L | grep -q 'Chain INPUT (policy DROP)'").exit_code
        if check_firewall == 0:
            results.append({
                "check_id": "2.2.1",
                "description": "Firewall rules",
                "current_value": "INPUT policy DROP",
                "expected_value": "INPUT policy DROP",
                "status": "PASS",
                "suggestion": "",
                "rating": 10
            })
        else:
            results.append({
                "check_id": "2.2.1",
                "description": "Firewall rules",
                "current_value": "Policy not set to DROP",
                "expected_value": "INPUT policy DROP",
                "status": "FAIL",
                "suggestion": "Set INPUT policy to DROP",
                "rating": 5
            })

        # 4. Base image check
        base_image = container.image.attrs['RepoTags'][0]
        if base_image.lower() in ["alpine", "ubuntu"]:
            results.append({
                "check_id": "3.1.1",
                "description": "Base Image",
                "current_value": base_image,
                "expected_value": "Secure Image (e.g., Alpine, Ubuntu)",
                "status": "PASS",
                "suggestion": "",
                "rating": 8
            })
        else:
            results.append({
                "check_id": "3.1.1",
                "description": "Base Image",
                "current_value": base_image,
                "expected_value": "Secure Image (e.g., Alpine, Ubuntu)",
                "status": "FAIL",
                "suggestion": "Use a more secure base image",
                "rating": 4
            })

        # 5. Read-only filesystem check
        check_read_only = container.exec_run("mount | grep -q 'ro,'").exit_code
        if check_read_only == 0:
            results.append({
                "check_id": "3.2.1",
                "description": "Read-Only Filesystem",
                "current_value": "Enabled",
                "expected_value": "Enabled",
                "status": "PASS",
                "suggestion": "",
                "rating": 10
            })
        else:
            results.append({
                "check_id": "3.2.1",
                "description": "Read-Only Filesystem",
                "current_value": "Disabled",
                "expected_value": "Enabled",
                "status": "FAIL",
                "suggestion": "Enable read-only filesystem",
                "rating": 3
            })

        # Terminal Output
        print("===== CIS HARDENING REPORT =====\n")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"CIS Container Hardening Report\nGenerated: {timestamp}")
        print("=" * 60)

        for result in results:
            print(f"Check ID: {result['check_id']}")
            print(f"Description: {result['description']}")
            print(f"Current Value: {result['current_value']}")
            print(f"Expected Value: {result['expected_value']}")
            print(f"Status: {result['status']}")
            print(f"Rating: {result['rating']}/10")
            if result['suggestion']:
                print(f"Suggestion: {result['suggestion']}")
            print("-" * 60)

        # Save HTML Report
        script_dir = os.path.dirname(os.path.realpath(__file__))
        html_path = os.path.join(script_dir, f"{container_id}Audit.html")

        with open(html_path, "w") as f:
            f.write(f"<html><head><title>CIS Report for {container_id}</title>")
            f.write("<style>body{font-family:sans-serif;} .fail{color:red;} .pass{color:green;}</style>")
            f.write("</head><body>")
            f.write(f"<h2>CIS Container Hardening Report</h2>")
            f.write(f"<p><strong>Generated:</strong> {timestamp}</p><hr>")
            
            for result in results:
                f.write(f"<h3>Check ID: {result['check_id']}</h3>")
                f.write(f"<p><strong>Description:</strong> {result['description']}<br>")
                f.write(f"<strong>Current Value:</strong> {result['current_value']}<br>")
                f.write(f"<strong>Expected Value:</strong> {result['expected_value']}<br>")
                f.write(f"<strong>Status:</strong> <span class='{result['status'].lower()}'>{result['status']}</span><br>")
                f.write(f"<strong>Rating:</strong> {result['rating']}/10<br>")
                if result['suggestion']:
                    f.write(f"<strong>Suggestion:</strong> {result['suggestion']}<br>")
                f.write("</p><hr>")

            f.write("</body></html>")

        print(f"\n✅ HTML report saved to {html_path}")

    except docker.errors.NotFound:
        print(f"❌ Error: Container '{container_id}' not found.")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    container_id = input("Enter Docker Container ID: ")
    check_container(container_id)
