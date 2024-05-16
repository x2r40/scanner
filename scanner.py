import os
import subprocess
from pathlib import Path
import logging

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def make_directory(directory):
    Path(directory).mkdir(parents=True, exist_ok=True)

def make_file(file_path):
    Path(file_path).touch(exist_ok=True)

def run_shell_command(command):
    try:
        subprocess.run(command, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed with exit code {e.returncode}")

def write_lines_to_file(lines, file_path):
    with open(file_path, 'w') as file:
        file.writelines(lines)

def read_lines_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def main():
    setup_logging()
    url = input("Enter URL: ")

    make_directory(url)
    make_directory(Path(url, "recon"))

    directories = [
        "recon/scans",
        "recon/httprobe",
        "recon/potential_takeovers",
        "recon/wayback",
        "recon/wayback/params",
        "recon/wayback/extensions"
    ]

    for directory in directories:
        make_directory(Path(url, directory))

    files = [
        "recon/httprobe/alive.txt",
        "recon/final.txt",
        "recon/potential_takeovers/potential_takeovers.txt",
        "recon/wayback/wayback_output.txt",
        "recon/wayback/params/wayback_params.txt",
        "recon/wayback/extensions/js.txt",
        "recon/wayback/extensions/jsp.txt",
        "recon/wayback/extensions/json.txt",
        "recon/wayback/extensions/php.txt",
        "recon/wayback/extensions/aspx.txt",
    ]

    for file in files:
        make_file(Path(url, file))

    logging.info("Harvesting subdomains with assetfinder...")
    assetfinder_command = ["assetfinder", url]
    run_shell_command(assetfinder_command + [f">{Path(url, 'recon/assets.txt')}"])

    assets = read_lines_from_file(Path(url, "recon/assets.txt"))
    final_file_path = Path(url, "recon/final.txt")
    write_lines_to_file(filter(lambda x: url in x, assets), final_file_path)

    os.remove(Path(url, "recon/assets.txt"))

    logging.info("Probing for alive domains...")
    httprobe_command = f"cat {final_file_path} | sort -u | httprobe -s -p https:443 | sed 's/https\\?:\\/\\///' | tr -d ':443' > {Path(url, 'recon/httprobe/alive.txt')}"
    run_shell_command(httprobe_command)

    logging.info("Checking for possible subdomain takeover...")
    subjack_command = [
        "subjack", "-w", str(final_file_path), "-t", "100", "-timeout", "30", "-ssl", 
        "-c", "~/go/src/github.com/haccer/subjack/fingerprints.json", "-v", "3", 
        "-o", str(Path(url, "recon/potential_takeovers/potential_takeovers.txt"))
    ]
    run_shell_command(subjack_command)

    logging.info("Scanning for open ports...")
    nmap_command = ["nmap", "-iL", str(Path(url, "recon/httprobe/alive.txt")), "-T4", "-oA", str(Path(url, "recon/scans/scanned.txt"))]
    run_shell_command(nmap_command)

    logging.info("Scraping wayback data...")
    waybackurls_command = f"cat {final_file_path} | waybackurls >> {Path(url, 'recon/wayback/wayback_output.txt')}"
    run_shell_command(waybackurls_command)

    sort_command = f"sort -u {Path(url, 'recon/wayback/wayback_output.txt')}"
    run_shell_command(sort_command)

    logging.info("Pulling and compiling all possible params found in wayback data...")
    grep_command = f"cat {Path(url, 'recon/wayback/wayback_output.txt')} | grep '\\?*=' | cut -d '=' -f 1 | sort -u >> {Path(url, 'recon/wayback/params/wayback_params.txt')}"
    run_shell_command(grep_command)

    params_file = Path(url, "recon/wayback/params/wayback_params.txt")
    for line in read_lines_from_file(params_file):
        print(line.strip() + '=')

    logging.info("Pulling and compiling js/php/aspx/jsp/json files from wayback output...")
    wayback_output_file = Path(url, "recon/wayback/wayback_output.txt")
    for line in read_lines_from_file(wayback_output_file):
        ext = line.split('.')[-1].strip()
        if ext in ["js", "jsp", "json", "php", "aspx"]:
            extension_file_path = Path(url, f"recon/wayback/extensions/{ext}.txt")
            with open(extension_file_path, 'a') as extension_file:
                extension_file.write(line + '\n')

    logging.info("Cleanup...")
    for ext in ["js", "jsp", "json", "php", "aspx"]:
        temp_file = Path(url, f"recon/wayback/extensions/{ext}1.txt")
        if temp_file.exists():
            temp_file.unlink()

if __name__ == "__main__":
    main()
