#!/bin/bash
for ipa in 98.13{6..9}.{0..255}.{0..255}; do
wget -t 1 -T 5 http://${ipa}/phpinfo.php; done&

(Example: download phpinfo file (if found) from Yahoo! IP range
(98.136.0.0–98.139.255.255)

# Download phpinfo files from an IP range
