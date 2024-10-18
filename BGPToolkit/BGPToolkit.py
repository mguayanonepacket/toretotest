import os
import time
from typing import Any, List
from ncclient import manager
import napalm
import re
from napalm import get_network_driver


def check_existing_sessions(router: Any, asn: int, host: str, user: str) -> None:
    """Check existing BGP sessions for the given ASN and print details."""
    bgp_config = router.get_bgp_config()
    peer = []

    for bgp_group in bgp_config:
        if bgp_config[bgp_group]["remote_as"] == asn:
            peer.append(bgp_group)

    for peer_group in peer:
        import_policy = bgp_config[peer_group]["import_policy"].split()
        export_policy = bgp_config[peer_group]["export_policy"].split()

        if "DENY" in export_policy[0] and "DENY" not in import_policy[0]:
            print(f"** Leading DENY exists in the export policy for {peer_group}")
        elif "DENY" not in export_policy[0] and "DENY" in import_policy[0]:
            print(f"** Leading DENY exists in the import policy for {peer_group}")
        else:
            print(f"** Leading DENY exists in both import and export Policy for {peer_group}")


def generate_graceful_commands(router: Any, asn: int, host: str, user: str) -> List[str]:
    """Generate BGP graceful shutdown commands."""
    graceful_commands = []
    peer = []
    bgp_config = router.get_bgp_config()

    for bgp_group in bgp_config:
        if bgp_config[bgp_group]["remote_as"] == asn:
            peer.append(bgp_group)

    for peer_group in peer:
        import_policy = bgp_config[peer_group]["import_policy"].split()
        export_policy = bgp_config[peer_group]["export_policy"].split()

        if "DENY" not in export_policy[0] and "DENY" not in import_policy[0]:
            graceful_commands.append(f"set protocols bgp group {peer_group} graceful-shutdown sender")
    return graceful_commands


def generate_drain_commands(router: Any, asn: int, host: str, user: str) -> List[str]:
    """Generate BGP drain commands."""
    drain_commands = []
    peer = []
    bgp_config = router.get_bgp_config()

    for bgp_group in bgp_config:
        if bgp_config[bgp_group]["remote_as"] == asn:
            peer.append(bgp_group)

    for peer_group in peer:
        import_policy = bgp_config[peer_group]["import_policy"].split()
        export_policy = bgp_config[peer_group]["export_policy"].split()
        if "DENY" not in export_policy[0] and "DENY" not in import_policy[0]:
            drain_commands.append(f"insert protocols bgp group {peer_group} export DENY before {export_policy[0]}")
            drain_commands.append(f"insert protocols bgp group {peer_group} import DENY before {import_policy[0]}")
    return drain_commands


def check_graceful_shutdown(router: Any, peer_group: str) -> bool:
    """Check if graceful-shutdown is configured for a specific peer group."""
    try:
        # Run the command to check for graceful-shutdown
        output_dict = router.cli(
            [f"show configuration protocols bgp group {peer_group} | display set | match graceful-shutdown"]
        )

        # Debugging: Print the command output
        output = output_dict.get(
            f"show configuration protocols bgp group {peer_group} | display set | match graceful-shutdown", ""
        )

        # Check if 'graceful-shutdown' exists in the output
        if "graceful-shutdown" in output:
            print(f"** graceful-shutdown found in {peer_group} configuration.")
            return True
        else:
            print(f"** graceful-shutdown not found in {peer_group} configuration.")
    except Exception as e:
        print(f"Error checking graceful-shutdown for {peer_group}: {e}")

    return False


def generate_normalize_commands(router: Any, asn: int, host: str, user: str) -> List[str]:
    """Generate BGP normalization commands."""
    normalize_commands = []
    peer = []

    # Get BGP configuration
    bgp_config = router.get_bgp_config()
    for bgp_group in bgp_config:
        if bgp_config[bgp_group].get("remote_as") == asn:
            peer.append(bgp_group)

    for peer_group in peer:
        # Check for and delete existing DENY policies
        if "DENY" in bgp_config[peer_group].get("export_policy", ""):
            normalize_commands.append(f"delete protocols bgp group {peer_group} export DENY")
        if "DENY" in bgp_config[peer_group].get("import_policy", ""):
            normalize_commands.append(f"delete protocols bgp group {peer_group} import DENY")

        # Check for graceful-shutdown and prepare delete command if exists
        if check_graceful_shutdown(router, peer_group):
            normalize_commands.append(f"delete protocols bgp group {peer_group} graceful-shutdown")

    return normalize_commands


def confirm_commit(router: Any, host: str) -> bool:
    """Confirm and apply configuration changes."""
    print()
    print("This is what you're about to commit")
    while True:
        commit = input("Do you want to continue (yes/no): ").lower().strip()
        if commit in ("y", "yes"):
            print(f"Committing on {host}")
            router.commit_config()
            return True
        elif commit in ("n", "no"):
            print(f"Commit on {host} aborted")
            return False
        else:
            print("You must answer yes or no")
            continue


def apply_commands(router: Any, commands: List[str], host: str) -> bool:
    """Apply configuration commands to the router."""
    print()
    print("Generated Commands:")
    for command in commands:
        print(command)

    try:
        with open("candidate_config.txt", "w") as file:
            for command in commands:
                file.write(command + "\n")
    except IOError as e:
        print(f"Error writing to file: {e}")
        return False

    try:
        router.load_merge_candidate(filename="candidate_config.txt")
    except Exception as e:
        print(f"Error loading candidate configuration: {e}")
        if "statement not found" in str(e):
            return confirm_commit(router, host)
        else:
            return False

    try:
        compare_output = router.compare_config()
        print()
        print("Changes to be applied:")
        print(compare_output)
    except Exception as e:
        print(f"Error comparing configurations: {e}")
        return False

    return confirm_commit(router, host)


def get_peer_ip(router: Any, asn: int) -> List[str]:
    """Retrieve the peer IP addresses for the given ASN."""
    try:
        bgp_neighbors = router.get_bgp_neighbors()
        peers = bgp_neighbors["global"]["peers"]
        peer_ips = []

        for peer_ip, peer_data in peers.items():
            if peer_data.get("remote_as") == asn:
                peer_ips.append(peer_ip)

        if not peer_ips:
            raise KeyError(f"No peers found with ASN {asn}")

        return peer_ips
    except Exception as e:
        print(f"Error retrieving peer IPs: {e}")
        raise


def check_preference(router: Any, peer_ips: List[str]) -> None:
    """Check and print BGP preference details for given peer IPs."""
    for peer_ip in peer_ips:
        print("*" * 70)
        try:
            output_dict = router.cli([f"show bgp neighbor {peer_ip} | match pref"])

            output = output_dict.get(f"show bgp neighbor {peer_ip} | match pref")

            if output and isinstance(output, str):
                lines = output.split("\n")
                sorted_lines = sorted(lines)
                sorted_output = "\n".join(sorted_lines)

                print(f"show bgp neighbor {peer_ip} | match pref")
                print(sorted_output)
            else:
                print("No output received or invalid output format")
        except Exception as e:
            print(f"Error executing command: {e}")


def check_bgp_summary(router: Any, peer_ips: List[str]) -> None:
    """Check and print BGP summary details for given peer IPs."""
    for peer_ip in peer_ips:
        print("*" * 70)
        try:
            output_dict = router.cli([f"show bgp summary | match {peer_ip}"])

            output = output_dict.get(f"show bgp summary | match {peer_ip}")

            if output and isinstance(output, str):
                lines = output.split("\n")
                sorted_lines = sorted(lines)
                sorted_output = "\n".join(sorted_lines)

                print(f"show bgp summary | match {peer_ip}")
                print(sorted_output)
            else:
                print("No output received or invalid output format")
        except Exception as e:
            print(f"Error executing command: {e}")


def get_bgp_neighbors(router: Any, asn: int, host: str, user: str) -> dict:
    """Fetch BGP neighbors for a specific ASN."""
    driver = get_network_driver("junos")
    device = driver(host, user, "")
    device.open()
    neighbors = device.get_bgp_neighbors()
    device.close()
    return neighbors


def main() -> None:
    """Main function to execute the script."""
    print("*" * 70)

    while True:
        host = input("Enter the router hostname: ").strip()
        if host:
            break
        print("Please enter a valid router name.")

    #user = os.getenv("USER")
    user = 'mguayanone'
    op_args = {"use_keys": True, "allow_agent": True}
    driver = get_network_driver("junos")
    print(f"el usuario es {user}")
    try:
        with driver(host, user, "", optional_args=op_args) as router:
            router.open()
            if not router.is_alive():
                print("Router connection failed. Please check the hostname and try again.")
                return
            print()
            command_result = router.cli(["show configuration protocols bgp | match transit"])
            output = command_result["show configuration protocols bgp | match transit"]
            matches = re.findall(r"TRANSIT:\s*(\S+)\s*-\s*AS(\d+)", output)
            unique_asns = set()
            for match in matches:
                asn, transit_name = match[1], match[0]
                unique_asns.add((asn, transit_name))
            if unique_asns:
                print("AS Numbers found in BGP transit configurations:")
                for idx, (asn, transit_name) in enumerate(unique_asns, 1):
                    print(f"{idx}) {asn}  -- {transit_name}")
                print()

                while True:
                    try:
                        choice = int(input(f"Enter the number corresponding to the peer ASN (1-{len(unique_asns)}): "))
                        if 1 <= choice <= len(unique_asns):
                            asn, transit_name = list(unique_asns)[choice - 1]

                            asn = int(asn)

                            print(f"You selected: {asn}  -- {transit_name}")
                            break
                        else:
                            print(f"Invalid input. Please enter a number between 1 and {len(unique_asns)}.")
                    except ValueError:
                        print("Invalid input. Please enter a valid number.")
            else:
                print("No AS Numbers found in BGP transit configurations.")

                return

            print()
            print("1- Drain traffic")
            print("2- Normalize traffic")
            print("3- Emergency Drain traffic (without applying graceful-shutdown)")
            print()

            while True:
                choice = input("Choose one option from the list above (1/2/3): ").strip()
                if choice not in ["1", "2", "3"]:
                    print("Invalid option. Please choose either 1, 2, or 3.")
                else:
                    break

            if choice == "1":

                print()

                print("###### Getting the BGP session info ######")
                peer_ip = get_peer_ip(router, asn)
                if peer_ip:
                    check_preference(router, peer_ip)
                print("*" * 70)
                graceful_commands = generate_graceful_commands(router, asn, host, user)
                if apply_commands(router, graceful_commands, host):
                    print()
                    print("###### Executing drain commands ######")

                    print("*" * 70)

                    drain_commands = generate_drain_commands(router, asn, host, user)
                    apply_commands(router, drain_commands, host)
                    print()
                    while True:

                        print()
                        print("*" * 70)
                        verify = input("Type 'y' to perform verification and 'n' to skip: ").lower().strip()
                        if verify == "y":
                            peer_ip = get_peer_ip(router, asn)
                            if peer_ip:
                                check_preference(router, peer_ip)
                            else:
                                print("Peer IP not found.")
                        elif verify == "n":
                            print("Verification skipped")
                            break
                        else:
                            print("Invalid input. Please type 'y' to perform verification or 'n' to skip.")

            elif choice == "2":
                print()
                print("###### Checking BGP neighbor status ######")
                peer_ip = get_peer_ip(router, asn)
                check_bgp_summary(router, peer_ip)
                print()
                print("##### Starting normalization process ######")
                print("*" * 70)
                print()
                check_existing_sessions(router, asn, host, user)
                normalize_commands = generate_normalize_commands(router, asn, host, user)
                apply_commands(router, normalize_commands, host)
                print()
                while True:
                    print()
                    print("*" * 70)
                    verify = input("Type 'y' to perform verification and 'n' to skip: ").lower().strip()
                    if verify == "y":
                        peer_ip = get_peer_ip(router, asn)
                        if peer_ip:
                            check_preference(router, peer_ip)
                        else:
                            print("Peer IP not found.")
                    elif verify == "n":
                        print("Verification skipped")
                        break
                    else:
                        print("Invalid input. Please type 'y' to perform verification or 'n' to skip.")

            elif choice == "3":
                print()
                print("###### Getting the BGP session info ######")
                peer_ip = get_peer_ip(router, asn)
                if peer_ip:
                    check_preference(router, peer_ip)
                print()
                print("###### Executing drain commands ######")
                print("*" * 70)
                drain_commands = generate_drain_commands(router, asn, host, user)
                apply_commands(router, drain_commands, host)
                print()
                while True:
                    print()
                    print("*" * 70)
                    verify = input("Type 'y' to perform verification and 'n' to skip: ").lower().strip()
                    if verify == "y":
                        peer_ip = get_peer_ip(router, asn)
                        if peer_ip:
                            check_preference(router, peer_ip)
                        else:
                            print("Peer IP not found.")
                    elif verify == "n":
                        print("Verification skipped")
                        break
                    else:
                        print("Invalid input. Please type 'y' to perform verification or 'n' to skip.")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        print("Exiting script.")


if __name__ == "__main__":
    main()
