#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography"]
# ///
"""
Encrypt a secret message and output a self-contained HTML file.

Usage:
    uv run encrypt.py --password "mypassword" --secret "This is my secret" > secret.html

Output: Complete HTML file with embedded encrypted secret
"""

import argparse
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants (must match HTML template)
SALT_SIZE = 32  # bytes
BLOCK_SIZE = 16  # bytes (IV size for AES-GCM)
KEY_SIZE = 32  # bytes (AES-256)
ITERATIONS = 5000000

HTML_TEMPLATE = """<!DOCTYPE html>
<!--
Portable Secret - Self-contained encrypted message viewer
Uses Web Cryptography API (PBKDF2 + AES-GCM)
-->
<html>

<head>
    <meta charset="UTF-8" />
    <meta name="robots" content="none">
    <style>
        body {
            background-color: floralwhite;
            font-size: large;
            margin: 50px;
            font-family: system-ui, sans-serif;
        }

        div {
            margin: 10px 0;
        }

        pre {
            padding: 15px;
            white-space: pre-wrap;
            word-break: break-word;
        }

        button {
            font-size: large;
            padding: 12px 20px;
            cursor: pointer;
        }

        input.password_input {
            font-size: large;
            padding: 12px 20px;
            font-family: monospace;
        }

        .decrypted {
            background-color: palegreen;
            border: 2px dotted forestgreen;
        }

        #errormsg {
            margin-left: 10px;
        }

        details {
            margin-top: 30px;
            color: #666;
        }

        .hidden-message {
            background-color: #ffcccc;
            border: 2px dotted #cc0000;
        }

        #copy-btn {
            font-size: medium;
            padding: 8px 16px;
            cursor: pointer;
            margin-left: 10px;
        }

        #timer-display {
            margin-left: 15px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
    <script>
        const SECRET = {{SECRET_JSON}};

        const saltSize = 32;   // bytes
        const blockSize = 16;  // bytes (AES block / IV size)
        const keySize = 32;    // bytes
        const hideTimeout = 20000; // ms - auto-hide after 20 seconds
        let hideTimer = null;
        let countdownInterval = null;
        let decryptedText = null;

        async function init() {
            document.getElementById("salt").value = SECRET.salt;
            document.getElementById("iv").value = SECRET.iv;
            document.getElementById("cipher").innerHTML = SECRET.cipher;
            document.getElementById("password").addEventListener("keydown", (event) => {
                if (event.key === "Enter") decrypt();
            });
            document.getElementById("password").focus();

            // Hide message when browser loses focus
            document.addEventListener("visibilitychange", () => {
                if (document.hidden && decryptedText !== null) {
                    hideMessage("Hidden: browser tab switched");
                }
            });
            window.addEventListener("blur", () => {
                if (decryptedText !== null) {
                    hideMessage("Hidden: window lost focus");
                }
            });
        }

        async function decrypt() {
            try {
                setMessage("⏳ Generating key from password...");

                const salt = hexStringToBytes(SECRET.salt);
                if (salt.length !== saltSize) throw new Error(`Unexpected salt size: ${salt.length}`);

                const iv = hexStringToBytes(SECRET.iv);
                if (iv.length !== blockSize) throw new Error(`Unexpected IV size: ${iv.length}`);

                const password = new TextEncoder().encode(document.getElementById("password").value);
                if (password.length === 0) throw new Error("Empty password");

                const passwordKey = await window.crypto.subtle.importKey(
                    "raw", password,
                    { name: "PBKDF2" },
                    false, ["deriveKey"]
                );

                const key = await window.crypto.subtle.deriveKey(
                    {
                        name: "PBKDF2",
                        salt: salt,
                        iterations: SECRET.iterations,
                        hash: "SHA-512",
                    },
                    passwordKey,
                    { name: "AES-GCM", length: keySize * 8 },
                    false, ["decrypt"]
                );

                setMessage("⏳ Decrypting...");

                const cipher = hexStringToBytes(SECRET.cipher);
                const decryptedBuffer = await window.crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: iv },
                    key, cipher
                );

                const decrypted = removePadding(new Uint8Array(decryptedBuffer));
                const plainText = new TextDecoder().decode(decrypted);

                document.getElementById("target_text").innerText = plainText;
                document.getElementById("text_output_div").hidden = false;
                decryptedText = plainText;
                setMessage("✅ Decrypted successfully");
                startHideTimer();

            } catch (err) {
                setMessage(`❌ Decryption failed: ${err.message || err}`);
            }
        }

        function hexStringToBytes(input) {
            const bytes = [];
            for (let c = 0; c < input.length; c += 2) {
                bytes.push(parseInt(input.substr(c, 2), 16));
            }
            return Uint8Array.from(bytes);
        }

        function removePadding(input) {
            const padAmount = input[input.length - 1];
            return input.slice(0, input.length - padAmount);
        }

        function setMessage(msg) {
            document.getElementById("errormsg").innerHTML = msg;
        }

        function startHideTimer() {
            clearTimers();
            let secondsLeft = hideTimeout / 1000;
            updateTimerDisplay(secondsLeft);
            
            countdownInterval = setInterval(() => {
                secondsLeft--;
                updateTimerDisplay(secondsLeft);
            }, 1000);
            
            hideTimer = setTimeout(() => {
                hideMessage("Hidden: auto-timeout (20s)");
            }, hideTimeout);
        }

        function clearTimers() {
            if (hideTimer) {
                clearTimeout(hideTimer);
                hideTimer = null;
            }
            if (countdownInterval) {
                clearInterval(countdownInterval);
                countdownInterval = null;
            }
        }

        function updateTimerDisplay(seconds) {
            const display = document.getElementById("timer-display");
            if (display) {
                display.innerText = `Auto-hide in ${seconds}s`;
            }
        }

        function hideMessage(reason) {
            clearTimers();
            decryptedText = null;
            document.getElementById("target_text").innerText = "";
            document.getElementById("text_output_div").hidden = true;
            document.getElementById("timer-display").innerText = "";
            document.getElementById("password").value = "";
            setMessage("🔒 " + (reason || "Message hidden for security"));
        }

        async function copyToClipboard() {
            if (decryptedText === null) {
                setMessage("❌ No decrypted message to copy");
                return;
            }
            try {
                await navigator.clipboard.writeText(decryptedText);
                setMessage("📋 Copied to clipboard!");
            } catch (err) {
                setMessage(`❌ Copy failed: ${err.message || err}`);
            }
        }
    </script>
</head>

<body onload="init()">
    <h1>🔐 Encrypted Secret</h1>
    <p>Enter the password to decrypt the hidden message.</p>

    <div>
        <input type="password" id="password" placeholder="Enter password" class="password_input" required
               autocomplete="off" data-1p-ignore data-lpignore="true" data-form-type="other">
    </div>

    <div>
        <button type="button" onclick="decrypt()">Decrypt</button>
        <span id="errormsg"></span>
    </div>

    <div id="text_output_div" hidden>
        <h3>Decrypted Message: <button type="button" id="copy-btn" onclick="copyToClipboard()">📋 Copy</button><span id="timer-display"></span></h3>
        <pre id="target_text" class="decrypted"></pre>
    </div>

    <details>
        <summary>Technical Details</summary>
        <p>Encryption: PBKDF2 (SHA-512) + AES-256-GCM</p>
        <div>Salt: <input type="text" id="salt" size="66" readonly></div>
        <div>IV: <input type="text" id="iv" size="34" readonly></div>
        <div>Ciphertext:<br><textarea rows="4" cols="80" id="cipher" readonly></textarea></div>
    </details>
</body>

</html>
"""


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Apply PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def encrypt(password: str, plaintext: str) -> dict:
    """Encrypt plaintext with password using PBKDF2 + AES-GCM."""

    # Generate random salt and IV
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(BLOCK_SIZE)

    # Derive key using PBKDF2 with SHA-512
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))

    # Pad plaintext (PKCS#7)
    plaintext_bytes = plaintext.encode("utf-8")
    padded = pkcs7_pad(plaintext_bytes, BLOCK_SIZE)

    # Encrypt with AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, padded, None)

    return {
        "salt": salt.hex(),
        "iv": iv.hex(),
        "cipher": ciphertext.hex(),
        "iterations": ITERATIONS,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt a secret message and output a self-contained HTML file."
    )
    parser.add_argument(
        "--password", "-p", required=True, help="Password to encrypt the secret"
    )
    parser.add_argument(
        "--secret", "-s", required=True, help="Secret message to encrypt"
    )
    args = parser.parse_args()

    result = encrypt(args.password, args.secret)
    html = HTML_TEMPLATE.replace("{{SECRET_JSON}}", json.dumps(result))
    print(html)


if __name__ == "__main__":
    main()
