"""
Julian Client - Secure File Transfer System v4.0.0
==================================================

A production-ready, security-hardened file transfer client with:
- JSON-based protocol (prevents command injection)
- TLS 1.3 encryption (NO certificate pinning - use Safety Numbers instead)
- Pairing authentication with code-based login
- Service discovery (auto-detect servers)
- Strong device fingerprinting (UUID + Machine ID)
- Advanced file validation (path traversal, overwrite protection)
- Message validation (type checking, structure verification)
- Resume transfers (continue interrupted downloads)
- File management (delete, rename, search)
- Safety Numbers (server identity verification)
- Optional credentials encryption (AES-128)
- Interactive REPL interface
- Quick CLI commands

Security Features:
------------------
1. Path Traversal Protection: Prevents ../ attacks
2. File Overwrite Protection: Sequential numbering for existing files
3. File Size Validation: Prevents disk exhaustion
4. Disk Space Check: Verifies available space before download
5. JSON Type Validation: Prevents crashes from malformed messages
6. TLS 1.3 Encryption: All communications encrypted
7. Device Fingerprinting: UUID + Machine ID for strong identity
8. Input Sanitization: All inputs validated before use
9. Safety Numbers: Verify server identity (anti-spoofing)
10. Optional Credentials Encryption: AES-128 with master password
11. Timeouts: Prevent hanging on network issues
12. Retries: Automatic retry on connection failures
13. Lock File: Prevent multiple instances

Note: Certificate Pinning has been removed for easier development/testing.
      Use Safety Numbers for server verification instead.

Design Patterns Applied:
------------------------
- Strategy: FileValidator, MessageValidator (validation strategies)
- Factory: ServiceDiscovery (server discovery)
- Singleton: DeviceIdentity (one identity per device)

Author: Julian Project
License: MIT
Version: 4.0.0
"""

import socket
import hashlib
import os
import logging
import platform
import ssl
import json
import argparse
import sys
import uuid
import time
import getpass
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass


# ============================================================================
# OPTIONAL: Credentials Encryption
# ============================================================================
# Try to import cryptography package for optional encryption
# If not available, credentials are stored with file permissions only

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ============================================================================
# CONFIGURATION
# ============================================================================
# Centralized configuration for easy customization

CONFIG = {
    "client": {
        "config_dir": ".julian",
        "credentials_file": "credentials.json",
        "device_id_file": "device_id.json",
        "certs_dir": "certs",
        "log_file": "client_logs.txt",
        "download_prefix": "downloaded_",
        "partial_suffix": ".partial",  # For resume transfers
        "max_file_size_mb": 0,  # 0 = unlimited
        "transfer_timeout": 30,  # seconds per chunk
        "connect_timeout": 10,  # seconds for connection
        "max_retries": 3,  # retry attempts
        "retry_delay": 2,  # seconds between retries
    },
    "discovery": {
        "broadcast_port": 37020,
        "timeout": 5,  # seconds to wait for discovery
    },
    "security": {
        "code_length": 8,
        "encrypt_credentials": False,  # Optional encryption
    },
}


# ============================================================================
# SECURITY: File Validator
# ============================================================================

class FileValidator:
    """
    Validates file operations to prevent security vulnerabilities.
    
    Security Measures:
    ------------------
    1. Path Traversal Protection: Prevents ../ attacks
    2. Filename Sanitization: Removes dangerous characters
    3. Safe Path Construction: Ensures files stay in designated folder
    4. File Size Validation: Prevents disk exhaustion
    5. Disk Space Check: Verifies available space
    6. Overwrite Protection: Sequential numbering for existing files
    """
    
    @staticmethod
    def validate_download_filename(filename: str, download_dir: str = ".") -> str:
        """
        Validate and sanitize filename for download.
        
        Security Strategy:
        ------------------
        1. Extract only the filename (removes all path components)
        2. Check for dangerous patterns
        3. Verify length is reasonable
        4. Ensure final path is within download directory
        
        Args:
            filename: Original filename from server
            download_dir: Directory where file will be saved
        
        Returns:
            Safe filename if valid
        
        Raises:
            ValueError: If filename is invalid or contains path traversal
        
        Example:
            validate_download_filename("../../../etc/passwd") → ValueError
            validate_download_filename("photo.jpg") → "photo.jpg"
        """
        # Step 1: Extract only the filename (removes all path components)
        safe_name = os.path.basename(filename)
        
        # Step 2: Check if basename extraction removed everything
        if not safe_name:
            raise ValueError("Invalid filename: empty after sanitization")
        
        # Step 3: Check for dangerous patterns
        dangerous_patterns = ['..', '/', '\\', '\x00']
        for pattern in dangerous_patterns:
            if pattern in safe_name:
                raise ValueError(f"Invalid filename: contains '{pattern}'")
        
        # Step 4: Check length
        if len(safe_name) > 255:
            raise ValueError("Filename too long (max 255 characters)")
        
        # Step 5: Verify final path is within download directory
        download_path = Path(download_dir).resolve()
        final_path = (download_path / safe_name).resolve()
        
        if not str(final_path).startswith(str(download_path)):
            raise ValueError("Path traversal detected")
        
        return safe_name
    
    @staticmethod
    def validate_upload_filename(filename: str) -> str:
        """Validate filename for upload."""
        return FileValidator.validate_download_filename(filename)
    
    @staticmethod
    def get_safe_save_path(filename: str, directory: str = ".", 
                           prefix: str = "downloaded_") -> str:
        """
        Get a safe path for saving file, avoiding overwrites.
        
        Strategy:
        ---------
        If file exists, add sequential number:
        file.pdf → file(1).pdf → file(2).pdf
        """
        safe_name = FileValidator.validate_download_filename(filename, directory)
        name_with_prefix = f"{prefix}{safe_name}"
        base_path = Path(directory) / name_with_prefix
        
        if not base_path.exists():
            return str(base_path)
        
        # File exists, add sequential number
        stem = base_path.stem
        suffix = base_path.suffix
        counter = 1
        
        while True:
            new_name = f"{prefix}{stem}({counter}){suffix}"
            new_path = Path(directory) / new_name
            
            if not new_path.exists():
                return str(new_path)
            
            counter += 1
            
            if counter > 1000:
                raise ValueError("Too many files with similar names")
    
    @staticmethod
    def validate_file_size(size: int, max_size_mb: int = 0) -> bool:
        """Validate file size is reasonable."""
        if size <= 0:
            return False
        
        if max_size_mb > 0:
            max_bytes = max_size_mb * 1024 * 1024
            if size > max_bytes:
                return False
        
        # Sanity check: reject absurdly large files (> 100GB)
        if size > 100 * 1024 * 1024 * 1024:
            return False
        
        return True
    
    @staticmethod
    def check_disk_space(required_bytes: int, path: str = ".") -> bool:
        """Check if enough disk space is available."""
        try:
            stat = os.statvfs(path)
            available_bytes = stat.f_bavail * stat.f_frsize
            required_with_buffer = int(required_bytes * 1.1)
            return available_bytes >= required_with_buffer
        except Exception:
            # Windows doesn't support statvfs, assume OK
            return True


# ============================================================================
# SECURITY: Message Validator
# ============================================================================

class MessageValidator:
    """
    Validates JSON messages from server.
    
    Purpose:
    --------
    Prevent crashes and security issues from malformed messages.
    """
    
    @staticmethod
    def validate_message(message: dict, required_fields: dict) -> bool:
        """Validate message has required fields with correct types."""
        if not isinstance(message, dict):
            return False
        
        for field, expected_type in required_fields.items():
            if field not in message:
                return False
            
            value = message[field]
            if not isinstance(value, expected_type):
                return False
            
            if expected_type == int and value < 0:
                return False
            
            if expected_type == str and len(value) == 0:
                return False
        
        return True
    
    @staticmethod
    def validate_file_meta(message: dict) -> bool:
        """Validate FILE_META message structure."""
        return MessageValidator.validate_message(message, {
            'filename': str,
            'size': int,
            'sha256': str
        })
    
    @staticmethod
    def validate_resume_meta(message: dict) -> bool:
        """Validate RESUME_META message structure."""
        return MessageValidator.validate_message(message, {
            'filename': str,
            'size': int,
            'offset': int,
            'remaining': int,
            'sha256': str
        })
    
    @staticmethod
    def validate_file_list(message: dict) -> bool:
        """Validate FILE_LIST message structure."""
        if not MessageValidator.validate_message(message, {'files': list}):
            return False
        
        for file_entry in message['files']:
            if not isinstance(file_entry, dict):
                return False
            if 'name' not in file_entry or 'size' not in file_entry:
                return False
            if not isinstance(file_entry['name'], str):
                return False
            if not isinstance(file_entry['size'], int):
                return False
        
        return True
    
    @staticmethod
    def validate_search_results(message: dict) -> bool:
        """Validate SEARCH_RESULTS message structure."""
        if not MessageValidator.validate_message(message, {
            'pattern': str,
            'count': int,
            'files': list
        }):
            return False
        
        for file_entry in message['files']:
            if not isinstance(file_entry, dict):
                return False
            if 'name' not in file_entry or 'size' not in file_entry:
                return False
        
        return True
    
    @staticmethod
    def validate_user_list(message: dict) -> bool:
        """Validate USER_LIST message structure."""
        if not MessageValidator.validate_message(message, {'users': list}):
            return False
        
        for user_entry in message['users']:
            if not isinstance(user_entry, dict):
                return False
            required = ['username', 'ip', 'state']
            for field in required:
                if field not in user_entry:
                    return False
        
        return True
    
    @staticmethod
    def validate_stats(message: dict) -> bool:
        """Validate STATS message structure."""
        return MessageValidator.validate_message(message, {
            'username': str,
            'uploaded': int,
            'downloaded': int,
            'files_sent': int,
            'files_received': int
        })


# ============================================================================
# DEVICE IDENTITY (Strong Fingerprinting)
# ============================================================================

class DeviceIdentity:
    """
    Generates and manages unique device identity.
    
    Inspired by Syncthing's Device ID system.
    Uses multiple factors for strong fingerprinting.
    """
    
    def __init__(self, config_dir: Path = None):
        config_dir = config_dir or Path.home() / CONFIG["client"]["config_dir"]
        config_dir.mkdir(parents=True, exist_ok=True)
        self.identity_file = config_dir / CONFIG["client"]["device_id_file"]
        self.identity = self._load_or_create_identity()
    
    def _load_or_create_identity(self) -> dict:
        """Load existing identity or create new one."""
        if self.identity_file.exists():
            try:
                with open(self.identity_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        
        identity = {
            "device_uuid": str(uuid.uuid4()),
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "machine_id": self._get_machine_id(),
        }
        
        with open(self.identity_file, 'w') as f:
            json.dump(identity, f, indent=2)
        
        try:
            os.chmod(self.identity_file, 0o600)
        except Exception:
            pass
        
        return identity
    
    def _get_machine_id(self) -> str:
        """Get unique machine ID from OS."""
        # Linux: /etc/machine-id
        if Path('/etc/machine-id').exists():
            try:
                with open('/etc/machine-id', 'r') as f:
                    return f.read().strip()
            except Exception:
                pass
        
        # macOS: IOPlatformUUID
        if platform.system() == "Darwin":
            try:
                import subprocess
                result = subprocess.run(
                    ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
                    capture_output=True, text=True, timeout=2
                )
                for line in result.stdout.split('\n'):
                    if 'IOPlatformUUID' in line:
                        return line.split('=')[1].strip().strip('"')
            except Exception:
                pass
        
        # Windows: MachineGuid
        if platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Cryptography"
                )
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
                winreg.CloseKey(key)
                return value
            except Exception:
                pass
        
        # Fallback: Generate random UUID
        return str(uuid.uuid4())
    
    def get_fingerprint(self) -> str:
        """Generate device fingerprint from multiple factors."""
        factors = [
            self.identity["device_uuid"],
            self.identity["machine_id"],
        ]
        combined = "|".join(factors)
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def get_device_id(self) -> str:
        """Get human-readable device ID."""
        fingerprint = self.get_fingerprint()
        chunks = [fingerprint[i:i+7].upper() for i in range(0, 56, 7)]
        return "-".join(chunks)


# ============================================================================
# CREDENTIALS ENCRYPTION (Optional)
# ============================================================================

class CredentialsEncryption:
    """
    Optional encryption for stored credentials.
    
    Security:
    ---------
    - Uses Fernet (AES-128-CBC) for encryption
    - Master password → PBKDF2 → 32-byte key
    - Salt stored with encrypted data
    - 480,000 iterations for key derivation
    
    Note:
    -----
    Requires `cryptography` package: pip install cryptography
    """
    
    @staticmethod
    def is_available() -> bool:
        """Check if encryption is available."""
        return CRYPTO_AVAILABLE
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    @staticmethod
    def encrypt(data: str, password: str) -> str:
        """Encrypt data with password."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography package not installed")
        
        salt = os.urandom(16)
        key = CredentialsEncryption.derive_key(password, salt)
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        
        combined = salt + encrypted
        return base64.b64encode(combined).decode()
    
    @staticmethod
    def decrypt(encrypted_data: str, password: str) -> str:
        """Decrypt data with password."""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography package not installed")
        
        combined = base64.b64decode(encrypted_data.encode())
        salt = combined[:16]
        encrypted = combined[16:]
        
        key = CredentialsEncryption.derive_key(password, salt)
        f = Fernet(key)
        return f.decrypt(encrypted).decode()


# ============================================================================
# CREDENTIAL MANAGER
# ============================================================================

class CredentialManager:
    """
    Manages saved pairing info with optional encryption.
    
    Security Levels:
    ----------------
    1. No encryption (default): File permissions 0o600
    2. With encryption: AES-128 + master password
    """
    
    def __init__(self, config_dir: Path = None):
        config_dir = config_dir or Path.home() / CONFIG["client"]["config_dir"]
        config_dir.mkdir(parents=True, exist_ok=True)
        self.credentials_file = config_dir / CONFIG["client"]["credentials_file"]
        self.encrypt = CONFIG["security"]["encrypt_credentials"]
    
    def save_pairing(self, server_ip: str, port: int, username: str,
                      device_fingerprint: str) -> None:
        """Save pairing info with optional encryption."""
        credentials = {
            'server_ip': server_ip,
            'port': port,
            'username': username,
            'device_fingerprint': device_fingerprint,
            'encrypted': False
        }
        
        json_data = json.dumps(credentials, indent=2)
        
        if self.encrypt:
            if not CRYPTO_AVAILABLE:
                print("⚠️  cryptography package not installed. Saving unencrypted.")
                self.encrypt = False
            else:
                print("\n🔐 Credential Encryption Enabled")
                master_password = getpass.getpass("🔑 Enter master password: ")
                confirm = getpass.getpass("🔑 Confirm master password: ")
                
                if master_password != confirm:
                    print("❌ Passwords don't match!")
                    return
                
                if len(master_password) < 8:
                    print("❌ Password must be at least 8 characters!")
                    return
                
                encrypted_data = CredentialsEncryption.encrypt(json_data, master_password)
                credentials = {
                    'encrypted': True,
                    'credentials_data': encrypted_data
                }
                json_data = json.dumps(credentials, indent=2)
        
        with open(self.credentials_file, 'w') as f:
            f.write(json_data)
        
        try:
            os.chmod(self.credentials_file, 0o600)
        except Exception:
            pass
    
    def load_pairing(self) -> Optional[dict]:
        """Load pairing info with decryption if needed."""
        if not self.credentials_file.exists():
            return None
        
        try:
            with open(self.credentials_file, 'r') as f:
                content = f.read()
            
            data = json.loads(content)
            
            if data.get('encrypted', False):
                if not CRYPTO_AVAILABLE:
                    print("❌ cryptography package required")
                    return None
                
                master_password = getpass.getpass("🔑 Enter master password: ")
                
                try:
                    encrypted_data = data.get('credentials_data', '')
                    decrypted = CredentialsEncryption.decrypt(encrypted_data, master_password)
                    return json.loads(decrypted)
                except Exception:
                    print("❌ Wrong password or corrupted data")
                    return None
            else:
                return {
                    'server_ip': data['server_ip'],
                    'port': data['port'],
                    'username': data['username'],
                    'device_fingerprint': data['device_fingerprint']
                }
        
        except Exception as e:
            print(f"❌ Error loading credentials: {e}")
            return None
    
    def clear_pairing(self) -> None:
        """Remove saved pairing."""
        if self.credentials_file.exists():
            self.credentials_file.unlink()
            print("✅ Pairing cleared.")
        else:
            print("⚠️  No saved pairing found")


# ============================================================================
# RESUME TRANSFER MANAGER
# ============================================================================

class ResumeManager:
    """
    Manages partial downloads/uploads for resume capability.
    
    How It Works:
    -------------
    1. During transfer, creates .partial file
    2. Stores metadata in .partial.meta (JSON)
    3. On resume, reads metadata and continues from offset
    4. On completion, renames .partial to final filename
    """
    
    def __init__(self, directory: str = "."):
        self.directory = directory
    
    def get_partial_path(self, filename: str) -> str:
        """Get path for partial file."""
        return os.path.join(
            self.directory, 
            f"{filename}{CONFIG['client']['partial_suffix']}"
        )
    
    def get_meta_path(self, filename: str) -> str:
        """Get path for metadata file."""
        return os.path.join(
            self.directory,
            f"{filename}{CONFIG['client']['partial_suffix']}.meta"
        )
    
    def save_metadata(self, filename: str, total_size: int, sha256: str,
                       bytes_transferred: int) -> None:
        """Save transfer metadata."""
        meta = {
            'filename': filename,
            'total_size': total_size,
            'sha256': sha256,
            'bytes_transferred': bytes_transferred,
            'last_updated': time.time()
        }
        
        meta_path = self.get_meta_path(filename)
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)
    
    def load_metadata(self, filename: str) -> Optional[dict]:
        """Load transfer metadata."""
        meta_path = self.get_meta_path(filename)
        
        if not os.path.exists(meta_path):
            return None
        
        try:
            with open(meta_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    
    def cleanup(self, filename: str) -> None:
        """Remove partial and metadata files after successful transfer."""
        partial_path = self.get_partial_path(filename)
        meta_path = self.get_meta_path(filename)
        
        for path in [partial_path, meta_path]:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
    
    def list_partials(self) -> List[dict]:
        """List all partial downloads in directory."""
        partials = []
        suffix = CONFIG['client']['partial_suffix']
        
        try:
            for filename in os.listdir(self.directory):
                if filename.endswith(suffix) and not filename.endswith(f"{suffix}.meta"):
                    original_name = filename[:-len(suffix)]
                    meta = self.load_metadata(original_name)
                    
                    partial_path = os.path.join(self.directory, filename)
                    actual_size = os.path.getsize(partial_path)
                    
                    total_size = meta['total_size'] if meta else actual_size
                    
                    partials.append({
                        'filename': original_name,
                        'partial_path': partial_path,
                        'actual_size': actual_size,
                        'total_size': total_size,
                        'sha256': meta['sha256'] if meta else None,
                        'progress': (actual_size / total_size * 100) if total_size > 0 else 0
                    })
        except Exception:
            pass
        
        return partials


# ============================================================================
# SAFETY NUMBERS (Server Verification)
# ============================================================================

class SafetyNumbers:
    """
    Verifies server identity using Safety Numbers.
    
    Inspired by Signal's Safety Numbers.
    
    How It Works:
    -------------
    1. Client requests SERVER_FINGERPRINT from server
    2. Server computes SHA256 of its certificate
    3. Converts to 5 groups of 5 digits
    4. User compares with numbers shown on server console
    5. If match → server is authentic
    """
    
    @staticmethod
    def verify(client_socket, expected_numbers: str = None) -> bool:
        """
        Verify server identity using Safety Numbers.
        
        Args:
            client_socket: Connected socket
            expected_numbers: If provided, compare directly
        
        Returns:
            True if verified, False otherwise
        """
        try:
            JsonProtocol.send_message(client_socket, {
                "type": "SERVER_FINGERPRINT"
            })
            
            response = JsonProtocol.recv_message(client_socket)
            
            if not response or response.get('type') != 'SERVER_FINGERPRINT':
                print("❌ Could not get server fingerprint")
                return False
            
            safety_numbers = response.get('safety_numbers', '')
            fingerprint = response.get('fingerprint', '')
            
            print("\n" + "=" * 60)
            print("🛡️ SERVER VERIFICATION (Safety Numbers)")
            print("=" * 60)
            print(f"\n📱 Server Safety Numbers: {safety_numbers}")
            print(f"🔏 Fingerprint: {fingerprint}...")
            print("\n💡 Compare these numbers with what's shown on the server console.")
            print("💡 If they match, the server is authentic.")
            print("=" * 60)
            
            if expected_numbers:
                return safety_numbers == expected_numbers
            else:
                user_input = input("\n🔍 Do the numbers match? (yes/no): ").strip().lower()
                return user_input in ['yes', 'y']
        
        except Exception as e:
            print(f"❌ Verification error: {e}")
            return False


# ============================================================================
# LOCK FILE (Prevent Multiple Instances)
# ============================================================================

class LockFile:
    """
    Prevents multiple instances from running simultaneously.
    
    How It Works:
    -------------
    1. Creates a lock file in config directory
    2. If lock file exists, another instance is running
    3. Lock file is removed on clean exit
    """
    
    def __init__(self, config_dir: Path):
        self.lock_file = config_dir / "client.lock"
    
    def acquire(self) -> bool:
        """Try to acquire lock."""
        if self.lock_file.exists():
            try:
                with open(self.lock_file, 'r') as f:
                    old_pid = int(f.read().strip())
                
                # Check if process is still alive
                os.kill(old_pid, 0)
                return False
            except (ProcessLookupError, ValueError, OSError):
                # Process doesn't exist → stale lock file
                try:
                    self.lock_file.unlink()
                except Exception:
                    pass
        
        # Create lock file with our PID
        with open(self.lock_file, 'w') as f:
            f.write(str(os.getpid()))
        
        return True
    
    def release(self) -> None:
        """Release the lock."""
        try:
            if self.lock_file.exists():
                self.lock_file.unlink()
        except Exception:
            pass


# ============================================================================
# SERVICE DISCOVERY (Auto-detect Servers)
# ============================================================================

class ServiceDiscovery:
    """Discover Julian servers on the local network via UDP broadcast."""
    
    def __init__(self, timeout: int = None):
        self.timeout = timeout or CONFIG["discovery"]["timeout"]
        self.broadcast_port = CONFIG["discovery"]["broadcast_port"]
    
    def discover(self) -> List[dict]:
        """Listen for server broadcasts and return list of discovered servers."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('', self.broadcast_port))
        except Exception as e:
            print(f"⚠️  Could not bind to discovery port: {e}")
            return []
        
        sock.settimeout(self.timeout)
        
        servers = []
        seen_ips = set()
        
        print(f"🔍 Discovering Julian servers (timeout: {self.timeout}s)...")
        
        try:
            while True:
                data, addr = sock.recvfrom(1024)
                
                if addr[0] in seen_ips:
                    continue
                
                try:
                    server_info = json.loads(data.decode('utf-8'))
                    
                    if server_info.get('service') == 'julian':
                        seen_ips.add(addr[0])
                        servers.append({
                            'ip': addr[0],
                            'port': server_info.get('port'),
                            'version': server_info.get('version'),
                            'requires_auth': server_info.get('requires_auth'),
                            'tls': server_info.get('tls')
                        })
                except json.JSONDecodeError:
                    continue
        
        except socket.timeout:
            pass
        finally:
            sock.close()
        
        return servers


# ============================================================================
# JSON PROTOCOL (Secure Communication)
# ============================================================================

class JsonProtocol:
    """
    JSON-based protocol with length prefix.
    
    Security Benefits:
    ------------------
    1. Prevents command injection (no string parsing)
    2. Prevents data corruption (structured format)
    3. Length prefix prevents buffer overflow
    4. JSON validation ensures data integrity
    """
    
    @staticmethod
    def send_message(sock: socket.socket, data: dict) -> None:
        """Send JSON message with length prefix."""
        message = json.dumps(data)
        encoded = message.encode('utf-8')
        length = len(encoded).to_bytes(4, 'big')
        sock.send(length + encoded)
    
    @staticmethod
    def recv_message(sock: socket.socket, timeout: int = None) -> Optional[dict]:
        """Receive JSON message with length prefix."""
        if timeout:
            sock.settimeout(timeout)
        
        try:
            length_bytes = sock.recv(4)
            if len(length_bytes) < 4:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Sanity check (prevent memory exhaustion)
            if length > 10 * 1024 * 1024:
                return None
            
            message_bytes = sock.recv(length)
            if len(message_bytes) < length:
                return None
            
            return json.loads(message_bytes.decode('utf-8'))
        except Exception:
            return None
        finally:
            if timeout:
                sock.settimeout(None)


# ============================================================================
# FILE TRANSFER UTILITIES
# ============================================================================

class FileTransferUtils:
    """Utility class for file transfer operations."""
    
    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        """Calculate SHA256 hash of a file for integrity verification."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def show_progress(current: int, total: int, prefix: str = "") -> None:
        """Display a progress bar for file transfers."""
        if total == 0:
            return
        
        percent = int(100 * current / total)
        filled = int(50 * current / total)
        bar = '█' * filled + '-' * (50 - filled)
        
        print(f'\r{prefix} |{bar}| {percent}% ({current}/{total} bytes)', 
              end='', flush=True)
        
        if current >= total:
            print()
    
    @staticmethod
    def format_size(size: int) -> str:
        """Format file size to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    @staticmethod
    def get_system_info() -> tuple:
        """Collect system information for device fingerprinting."""
        os_info = platform.system()
        distribution = ""
        device_type = "Desktop"
        
        if os_info == "Linux":
            try:
                if os.path.exists('/etc/os-release'):
                    with open('/etc/os-release') as f:
                        for line in f:
                            if line.startswith('PRETTY_NAME='):
                                distribution = line.split('=')[1].strip().strip('"')
                                break
                elif os.path.exists('/system/build.prop'):
                    os_info = "Android"
                    device_type = "Mobile (Android)"
                    try:
                        with open('/system/build.prop') as f:
                            for line in f:
                                if line.startswith('ro.build.display.id='):
                                    distribution = line.split('=')[1].strip()
                                    break
                    except Exception:
                        distribution = "Android"
                else:
                    distribution = platform.platform()
            except Exception:
                distribution = "Unknown Linux"
        
        elif os_info == "Darwin":
            distribution = f"macOS {platform.mac_ver()[0]}"
            device_type = "Mac"
        
        elif os_info == "Windows":
            distribution = platform.platform()
            device_type = "Windows PC"
        
        if 'com.termux' in os.environ.get('PREFIX', ''):
            os_info = "Android (Termux)"
            device_type = "Mobile (Termux)"
            distribution = "Termux"
        
        return os_info, distribution, device_type


# ============================================================================
# FILE BROWSER (Interactive Mode)
# ============================================================================

class FileBrowser:
    """Interactive file browser for navigating directories."""
    
    def __init__(self):
        self.current_path = os.getcwd()
    
    def display_directory(self) -> None:
        """Display current directory contents."""
        print(f"\n📁 Current: {self.current_path}")
        print("=" * 60)
        
        try:
            items = os.listdir(self.current_path)
        except PermissionError:
            print("❌ Permission denied!")
            return
        
        dirs = sorted([i for i in items if os.path.isdir(os.path.join(self.current_path, i))])
        files = sorted([i for i in items if os.path.isfile(os.path.join(self.current_path, i))])
        
        print("\n📂 Directories:")
        if dirs:
            for i, d in enumerate(dirs, 1):
                print(f"  [{i}] 📁 {d}")
        else:
            print("  (None)")
        
        print("\n📄 Files:")
        if files:
            for i, f in enumerate(files, len(dirs) + 1):
                size = os.path.getsize(os.path.join(self.current_path, f))
                print(f"  [{i}] 📄 {f} ({FileTransferUtils.format_size(size)})")
        else:
            print("  (None)")
        
        print("\n[0] ⬆️  Parent directory")
        print("[q] Quit browser")
        print("=" * 60)
    
    def navigate(self) -> Optional[str]:
        """Interactive navigation loop. Returns selected file path."""
        while True:
            self.display_directory()
            choice = input("\n👉 Select (number/path/0/q): ").strip()
            
            if choice.lower() == 'q':
                return None
            
            if choice == '0':
                parent = os.path.dirname(self.current_path)
                if parent == self.current_path:
                    print("⚠️  Already at root!")
                else:
                    self.current_path = parent
                continue
            
            if os.path.exists(choice):
                if os.path.isfile(choice):
                    return choice
                elif os.path.isdir(choice):
                    self.current_path = os.path.abspath(choice)
                continue
            
            try:
                num = int(choice)
                items = os.listdir(self.current_path)
                dirs = sorted([i for i in items if os.path.isdir(os.path.join(self.current_path, i))])
                files = sorted([i for i in items if os.path.isfile(os.path.join(self.current_path, i))])
                all_items = dirs + files
                
                if 1 <= num <= len(all_items):
                    selected = all_items[num - 1]
                    full_path = os.path.join(self.current_path, selected)
                    if os.path.isdir(full_path):
                        self.current_path = full_path
                    else:
                        return full_path
                else:
                    print("❌ Invalid number!")
            except ValueError:
                print("❌ Invalid input!")


# ============================================================================
# SECURE CLIENT (Core Connection Logic)
# ============================================================================

class SecureClient:
    """
    Main client class with:
    - JSON-based protocol
    - TLS 1.3 encryption (no certificate pinning)
    - Strong device fingerprinting
    - Pairing authentication
    - Code-based login
    - Advanced file validation
    - Resume transfers
    - File management (delete, rename, search)
    - Safety Numbers verification
    """
    
    def __init__(self, server_ip: str, server_port: int, config_dir: Path = None):
        """
        Initialize secure client.
        
        Args:
            server_ip: Server IP address
            server_port: Server port
            config_dir: Configuration directory
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.is_connected = False
        self.username = None
        
        # Config directory
        self.config_dir = config_dir or Path.home() / CONFIG["client"]["config_dir"]
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Device identity
        self.device_identity = DeviceIdentity(self.config_dir)
        self.resume_manager = ResumeManager(".")
        
        # Collect system information
        self.os_info, self.distribution, self.device_type = FileTransferUtils.get_system_info()
        
        # Setup logging
        log_file = self.config_dir / CONFIG["client"]["log_file"]
        logging.basicConfig(
            filename=str(log_file),
            filemode='a',
            format='%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            level=logging.INFO
        )
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Create SSL context for TLS 1.3 encryption.
        
        Note: Certificate pinning has been removed for easier development.
        Use Safety Numbers for server verification instead.
        """
        # Create custom SSL context (not default, to avoid strict validation)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Accept self-signed certificates
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Use TLS 1.2+ (TLS 1.3 if available)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        return context
    
    def _connect_socket(self) -> bool:
        """
        Establish TLS connection with retries.
        
        Retry Strategy:
        ---------------
        - Try up to max_retries times
        - Wait retry_delay seconds between attempts
        - Log each failed attempt
        """
        max_retries = CONFIG["client"]["max_retries"]
        retry_delay = CONFIG["client"]["retry_delay"]
        connect_timeout = CONFIG["client"]["connect_timeout"]
        
        for attempt in range(1, max_retries + 1):
            try:
                context = self._create_ssl_context()
                
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(connect_timeout)
                
                self.socket = context.wrap_socket(
                    self.socket, server_hostname=self.server_ip
                )
                self.socket.connect((self.server_ip, self.server_port))
                
                # Restore no-timeout for normal operations
                self.socket.settimeout(None)
                
                return True
            
            except Exception as e:
                if attempt < max_retries:
                    print(f"⚠️  Connection attempt {attempt}/{max_retries} failed: {e}")
                    print(f"⏳ Retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                else:
                    print(f"❌ Connection failed after {max_retries} attempts: {e}")
                    return False
    
    def setup(self, username: str) -> bool:
        """
        First-time pairing flow.
        
        IMPORTANT: The pairing code is displayed on the SERVER console,
        NOT on the client. The user must get the code from the server admin.
        
        Steps:
        ------
        1. Send PAIR_REQUEST with device info
        2. Server generates code and displays to admin
        3. User gets code from admin
        4. Send PAIR_CONFIRM with code
        5. Server verifies and registers device
        """
        if not self._connect_socket():
            return False
        
        try:
            # Step 1: Send pair request
            device_info = f"{self.os_info}||{self.distribution}||{self.device_type}"
            device_fingerprint = self.device_identity.get_fingerprint()
            
            JsonProtocol.send_message(self.socket, {
                "type": "PAIR_REQUEST",
                "username": username,
                "device_info": device_info,
                "device_fingerprint": device_fingerprint
            })
            
            # Step 2: Receive acknowledgment (code is NOT sent to client)
            response = JsonProtocol.recv_message(self.socket)
            if not response or response.get('type') != 'PAIR_CODE':
                print(f"❌ Unexpected response: {response}")
                return False
            
            # Step 3: Ask user to get code from server admin
            print("\n" + "=" * 60)
            print("🔑 PAIRING REQUIRED")
            print("=" * 60)
            print(f"The server has generated a pairing code.")
            print(f"👉 Look at the SERVER console to see the code.")
            print(f"👉 Ask the server admin for the code.")
            print("=" * 60)
            
            entered_code = input("\n🔑 Enter the pairing code from server admin: ").strip()
            
            # Step 4: Send confirmation
            JsonProtocol.send_message(self.socket, {
                "type": "PAIR_CONFIRM",
                "code": entered_code
            })
            
            # Step 5: Receive confirmation
            response = JsonProtocol.recv_message(self.socket)
            if not response or response.get('type') != 'PAIRED_OK':
                error_msg = response.get('message', 'Unknown error') if response else 'Pairing failed'
                print(f"❌ Pairing failed: {error_msg}")
                return False
            
            self.username = username
            self.is_connected = True
            
            print("\n✅ Pairing successful!")
            print(f"💡 Your device is now registered with the server.")
            print(f"💡 Next time, ask admin for a code to connect.")
            return True
        
        except Exception as e:
            print(f"❌ Setup error: {e}")
            return False
    
    def connect_with_code(self, username: str, code: str) -> bool:
        """
        Connect with admin-provided code (every time).
        
        Steps:
        ------
        1. Send CODE_LOGIN with username, code, and device fingerprint
        2. Server verifies code and device
        3. If valid, enter command loop
        """
        if not self._connect_socket():
            return False
        
        try:
            device_fingerprint = self.device_identity.get_fingerprint()
            
            JsonProtocol.send_message(self.socket, {
                "type": "CODE_LOGIN",
                "username": username,
                "code": code,
                "device_fingerprint": device_fingerprint
            })
            
            # Receive response
            response = JsonProtocol.recv_message(self.socket)
            
            if response and response.get('type') == 'LOGIN_OK':
                self.username = response.get('username')
                self.is_connected = True
                return True
            else:
                error_msg = response.get('message', 'Unknown error') if response else 'Connection failed'
                print(f"❌ Login failed: {error_msg}")
                return False
        
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False
    
    def verify_server(self) -> bool:
        """Verify server identity using Safety Numbers."""
        return SafetyNumbers.verify(self.socket)
    
    def send_command(self, data: dict) -> Optional[dict]:
        """Send a command to the server and receive response."""
        try:
            JsonProtocol.send_message(self.socket, data)
            return JsonProtocol.recv_message(self.socket)
        except Exception as e:
            print(f"\n❌ Error: {e}")
            return None
    
    def send_file(self, file_path: str) -> bool:
        """Upload file with timeout protection."""
        if not os.path.isfile(file_path):
            print(f"❌ File not found: {file_path}")
            return False
        
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_sha256 = FileTransferUtils.calculate_sha256(file_path)
        
        print(f"\n📤 Sending: {file_name} ({FileTransferUtils.format_size(file_size)})")
        
        JsonProtocol.send_message(self.socket, {
            "type": "UPLOAD",
            "filename": file_name,
            "size": file_size,
            "sha256": file_sha256
        })
        
        transfer_timeout = CONFIG["client"]["transfer_timeout"]
        sent_size = 0
        self.socket.settimeout(transfer_timeout)
        
        try:
            with open(file_path, 'rb') as f:
                while sent_size < file_size:
                    try:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        self.socket.send(chunk)
                        sent_size += len(chunk)
                        FileTransferUtils.show_progress(sent_size, file_size, "Sending")
                    except socket.timeout:
                        print(f"\n⚠️  Transfer timeout")
                        return False
            
            self.socket.settimeout(None)
            
            response = JsonProtocol.recv_message(self.socket)
            if response and response.get('type') == 'FILE_OK':
                print(f"\n✅ File sent successfully!")
                return True
            else:
                print(f"\n⚠️ Transfer failed!")
                return False
        
        except Exception as e:
            print(f"\n❌ Error: {e}")
            return False
        finally:
            self.socket.settimeout(None)
    
    def download_file(self, file_name: str, resume: bool = True) -> bool:
        """
        Download file with resume support.
        
        Security Measures:
        ------------------
        1. Filename validation (path traversal protection)
        2. File size validation
        3. Disk space check
        4. Message type validation
        5. No file overwrite
        6. Resume capability
        """
        try:
            # Validate filename
            safe_name = FileValidator.validate_download_filename(file_name)
            
            # Check for existing partial download
            partial_path = self.resume_manager.get_partial_path(safe_name)
            meta = self.resume_manager.load_metadata(safe_name) if resume else None
            
            if resume and meta and os.path.exists(partial_path):
                # Resume download
                offset = os.path.getsize(partial_path)
                print(f"\n🔄 Resuming download from {FileTransferUtils.format_size(offset)}")
                
                JsonProtocol.send_message(self.socket, {
                    "type": "RESUME_DOWNLOAD",
                    "filename": safe_name,
                    "offset": offset
                })
                
                metadata = JsonProtocol.recv_message(self.socket)
                
                if not metadata or metadata.get('type') != 'RESUME_META':
                    print("⚠️ Resume failed, starting fresh download")
                    return self._download_fresh(safe_name)
                
                if not MessageValidator.validate_resume_meta(metadata):
                    print("❌ Invalid resume metadata")
                    return self._download_fresh(safe_name)
                
                file_size = metadata['size']
                remaining = metadata['remaining']
                file_sha256 = metadata['sha256']
                
                JsonProtocol.send_message(self.socket, {"type": "READY"})
                
                print(f"📥 Downloading remaining: {FileTransferUtils.format_size(remaining)}")
                
                transfer_timeout = CONFIG["client"]["transfer_timeout"]
                self.socket.settimeout(transfer_timeout)
                
                received_size = 0
                try:
                    with open(partial_path, 'ab') as f:
                        while received_size < remaining:
                            try:
                                chunk_size = min(4096, remaining - received_size)
                                data = self.socket.recv(chunk_size)
                                if not data:
                                    break
                                f.write(data)
                                received_size += len(data)
                                FileTransferUtils.show_progress(
                                    offset + received_size, file_size, "Downloading"
                                )
                            except socket.timeout:
                                print(f"\n⚠️  Transfer timeout. Progress saved for resume.")
                                self.resume_manager.save_metadata(
                                    safe_name, file_size, file_sha256, offset + received_size
                                )
                                return False
                
                finally:
                    self.socket.settimeout(None)
                
                # Verify integrity
                if FileTransferUtils.calculate_sha256(partial_path) == file_sha256:
                    final_path = f"{CONFIG['client']['download_prefix']}{safe_name}"
                    os.rename(partial_path, final_path)
                    self.resume_manager.cleanup(safe_name)
                    print(f"\n✅ Downloaded: {final_path}")
                    return True
                else:
                    print(f"\n⚠️ File corrupted!")
                    return False
            
            else:
                return self._download_fresh(safe_name)
        
        except ValueError as e:
            print(f"❌ Validation error: {e}")
            return False
        except Exception as e:
            print(f"❌ Download error: {e}")
            return False
    
    def _download_fresh(self, file_name: str) -> bool:
        """Fresh download without resume."""
        JsonProtocol.send_message(self.socket, {
            "type": "DOWNLOAD",
            "filename": file_name
        })
        
        metadata = JsonProtocol.recv_message(self.socket)
        
        if not MessageValidator.validate_file_meta(metadata):
            print("❌ Invalid file metadata from server")
            return False
        
        file_name = metadata['filename']
        file_size = metadata['size']
        file_sha256 = metadata['sha256']
        
        if not FileValidator.validate_file_size(file_size):
            print(f"❌ Invalid file size: {file_size}")
            return False
        
        if not FileValidator.check_disk_space(file_size):
            print(f"❌ Not enough disk space")
            return False
        
        save_path = FileValidator.get_safe_save_path(
            file_name, directory=".",
            prefix=CONFIG['client']['download_prefix']
        )
        
        # Use partial file for resume capability
        partial_path = self.resume_manager.get_partial_path(file_name)
        
        JsonProtocol.send_message(self.socket, {"type": "READY"})
        
        print(f"\n📥 Downloading: {file_name} ({FileTransferUtils.format_size(file_size)})")
        print(f"💾 Saving to: {save_path}")
        
        transfer_timeout = CONFIG["client"]["transfer_timeout"]
        self.socket.settimeout(transfer_timeout)
        
        received_size = 0
        try:
            with open(partial_path, 'wb') as f:
                while received_size < file_size:
                    try:
                        chunk_size = min(4096, file_size - received_size)
                        data = self.socket.recv(chunk_size)
                        if not data:
                            break
                        f.write(data)
                        received_size += len(data)
                        FileTransferUtils.show_progress(received_size, file_size, "Downloading")
                        
                        # Save metadata periodically (every 1MB)
                        if received_size % (1024 * 1024) < 4096:
                            self.resume_manager.save_metadata(
                                file_name, file_size, file_sha256, received_size
                            )
                    except socket.timeout:
                        print(f"\n⚠️  Transfer timeout. Progress saved for resume.")
                        self.resume_manager.save_metadata(
                            file_name, file_size, file_sha256, received_size
                        )
                        return False
            
            self.socket.settimeout(None)
            
            # Verify integrity
            if FileTransferUtils.calculate_sha256(partial_path) == file_sha256:
                # Rename to final name
                os.rename(partial_path, save_path)
                self.resume_manager.cleanup(file_name)
                print(f"\n✅ Downloaded: {save_path}")
                return True
            else:
                print(f"\n⚠️ File corrupted!")
                try:
                    os.remove(partial_path)
                except Exception:
                    pass
                return False
        
        except Exception as e:
            print(f"❌ Download error: {e}")
            return False
        finally:
            self.socket.settimeout(None)
    
    # ========================================================================
    # File Management Commands
    # ========================================================================
    
    def delete_file(self, file_name: str) -> bool:
        """Delete a file from the server."""
        JsonProtocol.send_message(self.socket, {
            "type": "DELETE",
            "filename": file_name
        })
        
        response = JsonProtocol.recv_message(self.socket)
        
        if response and response.get('type') == 'DELETE_OK':
            print(f"✅ Deleted: {file_name}")
            return True
        else:
            error = response.get('message', 'Unknown error') if response else 'Connection failed'
            print(f"❌ Delete failed: {error}")
            return False
    
    def rename_file(self, old_name: str, new_name: str) -> bool:
        """Rename a file on the server."""
        JsonProtocol.send_message(self.socket, {
            "type": "RENAME",
            "old_name": old_name,
            "new_name": new_name
        })
        
        response = JsonProtocol.recv_message(self.socket)
        
        if response and response.get('type') == 'RENAME_OK':
            print(f"✅ Renamed: {old_name} → {new_name}")
            return True
        else:
            error = response.get('message', 'Unknown error') if response else 'Connection failed'
            print(f"❌ Rename failed: {error}")
            return False
    
    def search_files(self, pattern: str) -> List[dict]:
        """Search for files matching pattern."""
        JsonProtocol.send_message(self.socket, {
            "type": "SEARCH",
            "pattern": pattern
        })
        
        response = JsonProtocol.recv_message(self.socket)
        
        if not response or response.get('type') != 'SEARCH_RESULTS':
            print("❌ Search failed")
            return []
        
        if not MessageValidator.validate_search_results(response):
            print("❌ Invalid search results")
            return []
        
        files = response.get('files', [])
        count = response.get('count', 0)
        
        print(f"\n🔍 Search results for '{pattern}': {count} file(s)")
        print("=" * 60)
        
        for i, file in enumerate(files, 1):
            name = file.get('name', 'unknown')
            size = file.get('size', 0)
            print(f"  [{i}] 📄 {name} ({FileTransferUtils.format_size(size)})")
        
        print("=" * 60)
        return files
    
    def list_server_files(self) -> List[dict]:
        """List files with validation."""
        response = self.send_command({"type": "LIST"})
        
        if not response or not MessageValidator.validate_file_list(response):
            print("\n📭 No files on server or invalid response")
            return []
        
        files = response.get('files', [])
        
        if not files:
            print("\n📭 No files on server")
            return []
        
        print(f"\n📋 Server Files ({len(files)}):")
        print("=" * 60)
        for i, file in enumerate(files, 1):
            name = file.get('name', 'unknown')
            size = file.get('size', 0)
            print(f"  [{i}] 📄 {name} ({FileTransferUtils.format_size(size)})")
        print("=" * 60)
        
        return files
    
    def get_users_list(self) -> None:
        """Get users list with validation."""
        response = self.send_command({"type": "USERS"})
        
        if not response or not MessageValidator.validate_user_list(response):
            print("\n📭 Could not retrieve users list")
            return
        
        users = response.get('users', [])
        
        if not users:
            print("\n📭 No users connected")
            return
        
        print(f"\n👥 Connected Users:")
        print("=" * 70)
        print(f"{'Username':<15} {'IP':<15} {'State':<15} {'Uptime':<10}")
        print("=" * 70)
        
        for user in users:
            username = user.get('username', 'unknown')
            ip = user.get('ip', 'unknown')
            state = user.get('state', 'unknown')
            uptime = user.get('uptime', 0)
            print(f"{username:<15} {ip:<15} {state:<15} {uptime}s")
        
        print("=" * 70)
    
    def get_stats(self) -> None:
        """Display personal statistics with validation."""
        response = self.send_command({"type": "STATS"})
        
        if not response or not MessageValidator.validate_stats(response):
            error_msg = response.get('message', 'Unknown error') if response else 'Connection failed'
            print(f"❌ {error_msg}")
            return
        
        print(f"\n📊 Your Statistics:")
        print("=" * 40)
        print(f"Username: {response.get('username')}")
        print(f"Total Uploaded: {FileTransferUtils.format_size(response.get('uploaded', 0))}")
        print(f"Total Downloaded: {FileTransferUtils.format_size(response.get('downloaded', 0))}")
        print(f"Files Sent: {response.get('files_sent', 0)}")
        print(f"Files Received: {response.get('files_received', 0)}")
        print("=" * 40)
    
    def close(self) -> None:
        """Close connection gracefully."""
        self.is_connected = False
        try:
            JsonProtocol.send_message(self.socket, {"type": "QUIT"})
            self.socket.close()
        except Exception:
            pass
        logging.info("Client disconnected")


# ============================================================================
# INTERACTIVE REPL
# ============================================================================

class JulianREPL:
    """
    Interactive Read-Eval-Print Loop for Julian client.
    
    Usage:
    ------
    $ ju_client
    # Opens REPL with connection info and quick commands
    """
    
    def __init__(self):
        self.client = None
        self.connected = False
        self.server_ip = None
        self.server_port = None
        self.username = None
    
    def run(self):
        """Main REPL loop."""
        print("=" * 60)
        print("🌟 Julian Client v4.0.0 - Interactive Mode")
        print("=" * 60)
        print("Type 'help' for commands, 'exit' to quit.\n")
        
        while True:
            try:
                if self.connected:
                    prompt = f"\n🔗 [{self.username}@{self.server_ip}:{self.server_port}]> "
                else:
                    prompt = "\n⚫ [disconnected]> "
                
                command = input(prompt).strip()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:]
                
                if cmd in ['exit', 'quit', 'q']:
                    if self.connected:
                        self.client.close()
                    print("👋 Goodbye!")
                    break
                
                elif cmd == 'help':
                    self._show_help()
                
                elif cmd == 'connect':
                    self._cmd_connect(args)
                
                elif cmd == 'disconnect':
                    self._cmd_disconnect()
                
                elif cmd == 'send':
                    self._cmd_send(args)
                
                elif cmd == 'download':
                    self._cmd_download(args)
                
                elif cmd == 'list':
                    self._cmd_list()
                
                elif cmd == 'search':
                    self._cmd_search(args)
                
                elif cmd == 'delete':
                    self._cmd_delete(args)
                
                elif cmd == 'rename':
                    self._cmd_rename(args)
                
                elif cmd == 'resume':
                    self._cmd_resume()
                
                elif cmd == 'users':
                    self._cmd_users()
                
                elif cmd == 'stats':
                    self._cmd_stats()
                
                elif cmd == 'verify':
                    self._cmd_verify()
                
                elif cmd == 'info':
                    self._cmd_info()
                
                else:
                    print(f"❌ Unknown command: {cmd}")
                    print("💡 Type 'help' for available commands")
            
            except KeyboardInterrupt:
                print("\n\n⚠️  Use 'exit' to quit")
            except EOFError:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def _show_help(self):
        """Show available commands."""
        print("\n" + "=" * 60)
        print("📚 Available Commands")
        print("=" * 60)
        print("\n🔌 Connection:")
        print("  connect [code]      - Connect to saved server")
        print("  disconnect          - Disconnect from server")
        print("  verify              - Verify server identity (Safety Numbers)")
        print("  info                - Show connection info")
        
        print("\n📁 File Operations:")
        print("  send <file>         - Upload file")
        print("  download <file>     - Download file (supports resume)")
        print("  list                - List server files")
        print("  search <pattern>    - Search files (*, ? wildcards)")
        print("  delete <file>       - Delete file from server")
        print("  rename <old> <new>  - Rename file on server")
        print("  resume              - List resumable partial downloads")
        
        print("\n👥 Social:")
        print("  users               - Show connected users")
        print("  stats               - Show your statistics")
        
        print("\n⚙️  Other:")
        print("  help                - Show this help")
        print("  exit                - Exit Julian")
        print("=" * 60)
    
    def _cmd_connect(self, args):
        """Connect to server."""
        if self.connected:
            print("⚠️  Already connected. Use 'disconnect' first.")
            return
        
        cred_manager = CredentialManager()
        pairing = cred_manager.load_pairing()
        
        if not pairing:
            print("❌ No saved pairing. Run 'ju_client setup' first.")
            return
        
        self.server_ip = pairing['server_ip']
        self.server_port = pairing['port']
        self.username = pairing['username']
        
        print(f"🔗 Connecting as '{self.username}' to {self.server_ip}:{self.server_port}...")
        
        if args:
            code = args[0]
        else:
            code = input("🔑 Enter code from admin: ").strip()
        
        self.client = SecureClient(self.server_ip, self.server_port)
        
        if self.client.connect_with_code(self.username, code):
            self.connected = True
            print(f"✅ Connected!")
            
            verify = input("\n🛡️ Verify server identity? (y/n): ").strip().lower()
            if verify in ['y', 'yes']:
                self.client.verify_server()
        else:
            print("❌ Connection failed")
            self.client = None
    
    def _cmd_disconnect(self):
        """Disconnect from server."""
        if not self.connected:
            print("⚠️  Not connected")
            return
        
        self.client.close()
        self.client = None
        self.connected = False
        print("🔌 Disconnected")
    
    def _cmd_send(self, args):
        """Upload file."""
        if not self._check_connected():
            return
        
        if not args:
            file_path = input("📁 File path: ").strip()
        else:
            file_path = args[0]
        
        if not os.path.isfile(file_path):
            print(f"❌ File not found: {file_path}")
            return
        
        self.client.send_file(file_path)
    
    def _cmd_download(self, args):
        """Download file."""
        if not self._check_connected():
            return
        
        if not args:
            file_name = input("📄 File name: ").strip()
        else:
            file_name = args[0]
        
        self.client.download_file(file_name, resume=True)
    
    def _cmd_list(self):
        """List server files."""
        if not self._check_connected():
            return
        
        self.client.list_server_files()
    
    def _cmd_search(self, args):
        """Search files."""
        if not self._check_connected():
            return
        
        if not args:
            pattern = input("🔍 Pattern (use * for wildcard): ").strip()
        else:
            pattern = ' '.join(args)
        
        self.client.search_files(pattern)
    
    def _cmd_delete(self, args):
        """Delete file."""
        if not self._check_connected():
            return
        
        if not args:
            file_name = input("🗑️  File to delete: ").strip()
        else:
            file_name = args[0]
        
        confirm = input(f"⚠️  Delete '{file_name}'? (y/n): ").strip().lower()
        if confirm in ['y', 'yes']:
            self.client.delete_file(file_name)
    
    def _cmd_rename(self, args):
        """Rename file."""
        if not self._check_connected():
            return
        
        if len(args) >= 2:
            old_name, new_name = args[0], args[1]
        else:
            old_name = input("📝 Old name: ").strip()
            new_name = input("📝 New name: ").strip()
        
        self.client.rename_file(old_name, new_name)
    
    def _cmd_resume(self):
        """List resumable downloads."""
        partials = self.client.resume_manager.list_partials() if self.client else ResumeManager().list_partials()
        
        if not partials:
            print("\n📭 No partial downloads found")
            return
        
        print(f"\n🔄 Partial Downloads ({len(partials)}):")
        print("=" * 70)
        for i, p in enumerate(partials, 1):
            print(f"  [{i}] 📄 {p['filename']}")
            print(f"       Progress: {p['progress']:.1f}% ({FileTransferUtils.format_size(p['actual_size'])}/{FileTransferUtils.format_size(p['total_size'])})")
        print("=" * 70)
        
        if self.connected:
            choice = input("\n👉 Resume a download? (number or 'n'): ").strip()
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(partials):
                    self.client.download_file(partials[idx]['filename'], resume=True)
    
    def _cmd_users(self):
        """Show connected users."""
        if not self._check_connected():
            return
        
        self.client.get_users_list()
    
    def _cmd_stats(self):
        """Show statistics."""
        if not self._check_connected():
            return
        
        self.client.get_stats()
    
    def _cmd_verify(self):
        """Verify server identity."""
        if not self._check_connected():
            return
        
        self.client.verify_server()
    
    def _cmd_info(self):
        """Show connection info."""
        if not self.connected:
            print("⚫ Not connected")
            return
        
        print("\n" + "=" * 60)
        print("📊 Connection Info")
        print("=" * 60)
        print(f"  Server: {self.server_ip}:{self.server_port}")
        print(f"  Username: {self.username}")
        print(f"  Device: {self.client.device_type}")
        print(f"  OS: {self.client.os_info}")
        print(f"  Distribution: {self.client.distribution}")
        print(f"  Device ID: {self.client.device_identity.get_device_id()}")
        print("=" * 60)
    
    def _check_connected(self) -> bool:
        """Check if connected."""
        if not self.connected:
            print("⚠️  Not connected. Use 'connect' first.")
            return False
        return True


# ============================================================================
# CLI COMMANDS
# ============================================================================

def cmd_setup(args):
    """First-time pairing with the server."""
    print("=" * 60)
    print("🔐 Julian Setup - First-Time Pairing")
    print("=" * 60)
    
    if args.discover:
        discovery = ServiceDiscovery()
        servers = discovery.discover()
        
        if servers:
            print(f"\n✅ Found {len(servers)} Julian server(s):")
            for i, server in enumerate(servers, 1):
                tls_status = "🔐 TLS" if server['tls'] else "⚠️  No TLS"
                print(f"  [{i}] {server['ip']}:{server['port']} ({tls_status})")
            
            choice = input("\n👉 Select server (number) or 'm' for manual: ").strip()
            
            if choice.isdigit() and 1 <= int(choice) <= len(servers):
                selected = servers[int(choice) - 1]
                server_ip = selected['ip']
                port = selected['port']
            else:
                server_ip = input("📍 Server IP: ").strip()
                port = int(input("🔌 Port: ").strip())
        else:
            print("\n⚠️  No servers found. Enter manually.")
            server_ip = input("📍 Server IP: ").strip()
            port = int(input("🔌 Port: ").strip())
    else:
        server_ip = input("📍 Server IP: ").strip()
        port = int(input("🔌 Port: ").strip())
    
    username = input("👤 Username: ").strip()
    
    client = SecureClient(server_ip, port)
    
    if client.setup(username):
        cred_manager = CredentialManager()
        cred_manager.save_pairing(
            server_ip, port, username, client.device_identity.get_fingerprint()
        )
        print("\n✅ Setup complete!")
        print("💡 Next time, run 'ju_client connect' and enter the code from admin.")
    
    client.close()


def cmd_connect(args):
    """Connect with admin-provided code."""
    cred_manager = CredentialManager()
    pairing = cred_manager.load_pairing()
    
    if not pairing:
        print("❌ No saved pairing. Run 'ju_client setup' first.")
        return
    
    print(f"🔗 Connecting as '{pairing['username']}'...")
    print(f"📍 Server: {pairing['server_ip']}:{pairing['port']}")
    
    code = input("\n🔑 Enter the code from server admin: ").strip()
    
    client = SecureClient(pairing['server_ip'], pairing['port'])
    
    if client.connect_with_code(pairing['username'], code):
        print(f"\n✅ Connected!")
        repl = JulianREPL()
        repl.client = client
        repl.connected = True
        repl.server_ip = pairing['server_ip']
        repl.server_port = pairing['port']
        repl.username = pairing['username']
        repl.run()
    else:
        print("\n❌ Connection failed.")
    
    client.close()


def _require_code_and_connect(operation_name: str, operation_func):
    """Helper to require code before operation."""
    cred_manager = CredentialManager()
    pairing = cred_manager.load_pairing()
    
    if not pairing:
        print("❌ No saved pairing. Run 'ju_client setup' first.")
        return
    
    code = input(f"🔑 Enter code for '{operation_name}': ").strip()
    
    client = SecureClient(pairing['server_ip'], pairing['port'])
    
    if client.connect_with_code(pairing['username'], code):
        operation_func(client)
    else:
        print("❌ Authentication failed.")
    
    client.close()


def cmd_send(args):
    """Quick file upload."""
    def do_send(client):
        client.send_file(args.file)
    _require_code_and_connect("send", do_send)


def cmd_download(args):
    """Quick file download."""
    def do_download(client):
        client.download_file(args.file, resume=True)
    _require_code_and_connect("download", do_download)


def cmd_list(args):
    """List server files."""
    def do_list(client):
        client.list_server_files()
    _require_code_and_connect("list", do_list)


def cmd_search(args):
    """Search files."""
    def do_search(client):
        client.search_files(args.pattern)
    _require_code_and_connect("search", do_search)


def cmd_delete(args):
    """Delete file."""
    def do_delete(client):
        confirm = input(f"⚠️  Delete '{args.file}'? (y/n): ").strip().lower()
        if confirm in ['y', 'yes']:
            client.delete_file(args.file)
    _require_code_and_connect("delete", do_delete)


def cmd_rename(args):
    """Rename file."""
    def do_rename(client):
        client.rename_file(args.old_name, args.new_name)
    _require_code_and_connect("rename", do_rename)


def cmd_resume():
    """List resumable downloads."""
    partials = ResumeManager().list_partials()
    
    if not partials:
        print("\n📭 No partial downloads found")
        return
    
    print(f"\n🔄 Partial Downloads ({len(partials)}):")
    print("=" * 70)
    for i, p in enumerate(partials, 1):
        print(f"  [{i}] 📄 {p['filename']}")
        print(f"       Progress: {p['progress']:.1f}% ({FileTransferUtils.format_size(p['actual_size'])}/{FileTransferUtils.format_size(p['total_size'])})")
    print("=" * 70)


def cmd_users(args):
    """Show connected users."""
    def do_users(client):
        client.get_users_list()
    _require_code_and_connect("users", do_users)


def cmd_stats(args):
    """Show personal statistics."""
    def do_stats(client):
        client.get_stats()
    _require_code_and_connect("stats", do_stats)


def cmd_discover(args):
    """Discover Julian servers on the network."""
    discovery = ServiceDiscovery(timeout=args.timeout)
    servers = discovery.discover()
    
    if servers:
        print(f"\n✅ Found {len(servers)} Julian server(s):")
        for i, server in enumerate(servers, 1):
            tls_status = "🔐 TLS" if server['tls'] else "⚠️  No TLS"
            print(f"  [{i}] {server['ip']}:{server['port']} ({tls_status})")
    else:
        print("\n⚠️  No Julian servers found on the network.")


def cmd_reset(args):
    """Clear saved pairing."""
    cred_manager = CredentialManager()
    cred_manager.clear_pairing()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Application entry point."""
    # Acquire lock file
    config_dir = Path.home() / CONFIG["client"]["config_dir"]
    config_dir.mkdir(parents=True, exist_ok=True)
    lock = LockFile(config_dir)
    
    if not lock.acquire():
        print("❌ Another Julian client is already running.")
        print("💡 Close the other instance or delete ~/.julian/client.lock")
        sys.exit(1)
    
    try:
        # If no arguments, launch REPL
        if len(sys.argv) == 1:
            repl = JulianREPL()
            repl.run()
            return
        
        # Otherwise, use CLI commands
        parser = argparse.ArgumentParser(
            description="Julian Client - Secure File Transfer",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  ju_client                 Launch interactive mode (REPL)
  ju_client setup           First-time pairing
  ju_client setup --discover  Auto-discover servers
  ju_client connect         Connect with code
  ju_client send <file>     Quick upload
  ju_client download <file> Quick download
  ju_client list            List server files
  ju_client search <pattern> Search files
  ju_client delete <file>   Delete file
  ju_client rename <old> <new>  Rename file
  ju_client users           Show connected users
  ju_client stats           Show statistics
  ju_client discover        Discover servers
  ju_client resume          List resumable downloads
  ju_client reset           Clear pairing
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        setup_parser = subparsers.add_parser('setup', help='First-time pairing')
        setup_parser.add_argument('--discover', action='store_true')
        
        subparsers.add_parser('connect', help='Connect with code')
        
        send_parser = subparsers.add_parser('send', help='Upload file')
        send_parser.add_argument('file')
        
        download_parser = subparsers.add_parser('download', help='Download file')
        download_parser.add_argument('file')
        
        subparsers.add_parser('list', help='List files')
        
        search_parser = subparsers.add_parser('search', help='Search files')
        search_parser.add_argument('pattern')
        
        delete_parser = subparsers.add_parser('delete', help='Delete file')
        delete_parser.add_argument('file')
        
        rename_parser = subparsers.add_parser('rename', help='Rename file')
        rename_parser.add_argument('old_name')
        rename_parser.add_argument('new_name')
        
        subparsers.add_parser('resume', help='List resumable downloads')
        subparsers.add_parser('users', help='Show users')
        subparsers.add_parser('stats', help='Show statistics')
        
        discover_parser = subparsers.add_parser('discover', help='Discover servers')
        discover_parser.add_argument('--timeout', type=int, default=5)
        
        subparsers.add_parser('reset', help='Clear pairing')
        
        args = parser.parse_args()
        
        if args.command == 'setup':
            cmd_setup(args)
        elif args.command == 'connect':
            cmd_connect(args)
        elif args.command == 'send':
            cmd_send(args)
        elif args.command == 'download':
            cmd_download(args)
        elif args.command == 'list':
            cmd_list(args)
        elif args.command == 'search':
            cmd_search(args)
        elif args.command == 'delete':
            cmd_delete(args)
        elif args.command == 'rename':
            cmd_rename(args)
        elif args.command == 'resume':
            cmd_resume()
        elif args.command == 'users':
            cmd_users(args)
        elif args.command == 'stats':
            cmd_stats(args)
        elif args.command == 'discover':
            cmd_discover(args)
        elif args.command == 'reset':
            cmd_reset(args)
        else:
            parser.print_help()
    
    finally:
        lock.release()


if __name__ == "__main__":
    main()