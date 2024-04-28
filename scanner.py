import os
import subprocess

def make_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def make_file(file_path):
    if not os.path.exists(file_path):
        open(file_path, 'a').close()

def run_shell_command(command):
    subprocess.run(command, shell=True)

def write_lines_to_file(lines, file_path):
    with open(file_path, 'w') as file:
        file.writelines(lines)

def read_lines_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def main():
    url = input("Enter URL: ")

    make_directory(url)
    make_directory(os.path.join(url, "recon"))

    directories = [
        "recon/scans",
        "recon/httprobe",
        "recon/potential_takeovers",
        "recon/wayback",
        "recon/wayback/params",
        "recon/wayback/extensions"
    ]

    for directory in directories:
        make_directory(os.path.join(url, directory))

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
        make_file(os.path.join(url, file))

    print("[+] Harvesting subdomains with assetfinder...")
    assetfinder_command = f"assetfinder {url} > {url}/recon/assets.txt"
    run_shell_command(assetfinder_command)

    assets = read_lines_from_file(os.path.join(url, "recon/assets.txt"))
    final_file_path = os.path.join(url, "recon/final.txt")
    write_lines_to_file(filter(lambda x: url in x, assets), final_file_path)

    os.remove(os.path.join(url, "recon/assets.txt"))

    print("[+] Probing for alive domains...")
    httprobe_command = f"cat {final_file_path} | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' > {url}/recon/httprobe/alive.txt"
    run_shell_command(httprobe_command)

    print("[+] Checking for possible subdomain takeover...")
    subjack_command = f"subjack -w {final_file_path} -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o {url}/recon/potential_takeovers/potential_takeovers.txt"
    run_shell_command(subjack_command)

    print("[+] Scanning for open ports...")
    nmap_command = f"nmap -iL {url}/recon/httprobe/alive.txt -T4 -oA {url}/recon/scans/scanned.txt"
    run_shell_command(nmap_command)

    print("[+] Scraping wayback data...")
    waybackurls_command = f"cat {final_file_path} | waybackurls >> {url}/recon/wayback/wayback_output.txt"
    run_shell_command(waybackurls_command)

    sort_command = f"sort -u {url}/recon/wayback/wayback_output.txt"
    run_shell_command(sort_command)

    print("[+] Pulling and compiling all possible params found in wayback data...")
    grep_command = f"cat {url}/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> {url}/recon/wayback/params/wayback_params.txt"
    run_shell_command(grep_command)
    for line in read_lines_from_file(os.path.join(url, "recon/wayback/params/wayback_params.txt")):
        print(line.strip() + '=')

    print("[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output...")
    for line in read_lines_from_file(os.path.join(url, "recon/wayback/wayback_output.txt")):
        ext = line.split('.')[-1]
        if ext in ["js", "jsp", "json", "php", "aspx"]:
            extension_file_path = os.path.join(url, f"recon/wayback/extensions/{ext}.txt")
            with open(extension_file_path, 'a') as extension_file:
                extension_file.write(line + '\n')

    print("[+] Cleanup...")
    for ext in ["js", "jsp", "json", "php", "aspx"]:
        os.remove(os.path.join(url, f"recon/wayback/extensions/{ext}1.txt"))

if __name__ == "__main__":
    main()
