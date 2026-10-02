"""
Julian Client - Secure File Transfer System v4.4.0
==================================================

Production-ready, security-hardened file transfer client.

Features:
- TLS 1.3 encryption (no certificate pinning - use Safety Numbers)
- JSON protocol with length-prefix (TCP-safe)
- Pairing authentication with code-based login
- Service discovery (auto-detect servers)
- Strong device fingerprinting (UUID + Machine ID)
- Advanced file validation (path traversal, symlink, overwrite protection)
- Resume transfers (continue interrupted downloads)
- File management (delete, rename, search)
- Transfer requests (user-to-user with approval)
- Safety Numbers (server identity verification)
- Optional credentials encryption (AES-128)
- Interactive REPL interface
- Quick CLI commands
- **NEW: TUI File Browser (curses-based)**
- **NEW: JulianFiles folder (auto-downloads)**
- **NEW: Sent History tracking**
- Zero external dependencies (uses curses, built-in)

Security Hardening:
- TOCTOU protection in file operations
- Symlink attack prevention
- Resource leak prevention (try/finally)
- Infinite loop protection in resume
- Info leakage prevention in errors
- Race condition protection in credentials
- Max download size validation

Author: Julian Project
License: MIT
Version: 4.4.0
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
import threading
from pathlib import Path
from typing import Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from collections import deque

# Optional: cryptography for credentials encryption
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Optional: curses for TUI browser
try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    CURSES_AVAILABLE = False


# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    "client": {
        "config_dir": ".julian",
        "credentials_file": "credentials.json",
        "device_id_file": "device_id.json",
        "log_file": "client_logs.txt",
        "download_prefix": "downloaded_",
        "partial_suffix": ".partial",
        "browser_folder": "JulianFiles",
        "sent_history_folder": "JulianSent",
        "sent_history_file": "sent_history.json",
        "max_file_size_mb": 0,
        "max_download_size_mb": 10240,  # 10 GB
        "transfer_timeout": 30,
        "connect_timeout": 10,
        "max_retries": 3,
        "retry_delay": 2,
        "history_limit": 100,
    },
    "discovery": {
        "broadcast_port": 37020,
        "timeout": 5,
    },
    "security": {
        "code_length": 8,
        "encrypt_credentials": False,
    },
}


# ============================================================================
# FILE VALIDATOR (Security Hardened)
# ============================================================================

class FileValidator:
    """Validates file operations with security protections."""
    
    @staticmethod
    def validate_download_filename(filename: str, download_dir: str = ".") -> str:
        safe_name = os.path.basename(filename)
        if not safe_name:
            raise ValueError("Invalid filename: empty after sanitization")
        dangerous_patterns = ['..', '/', '\\', '\x00']
        for pattern in dangerous_patterns:
            if pattern in safe_name:
                raise ValueError(f"Invalid filename: contains '{pattern}'")
        if len(safe_name) > 255:
            raise ValueError("Filename too long (max 255 characters)")
        download_path = Path(download_dir).resolve()
        final_path = (download_path / safe_name).resolve()
        if not str(final_path).startswith(str(download_path)):
            raise ValueError("Path traversal detected")
        return safe_name
    
    @staticmethod
    def validate_upload_filename(filename: str) -> str:
        return FileValidator.validate_download_filename(filename)
    
    @staticmethod
    def get_safe_save_path(filename: str, directory: str = ".", 
                           prefix: str = "downloaded_") -> str:
        """Get safe path with symlink protection."""
        safe_name = FileValidator.validate_download_filename(filename, directory)
        name_with_prefix = f"{prefix}{safe_name}"
        base_path = Path(directory) / name_with_prefix
        
        # Check if parent directory is a symlink
        if base_path.parent.is_symlink():
            raise ValueError("Parent directory is a symlink - security risk!")
        
        if base_path.exists() or base_path.is_symlink():
            if base_path.is_symlink():
                raise ValueError("Symlink detected - security risk!")
            
            stem = base_path.stem
            suffix = base_path.suffix
            counter = 1
            while True:
                new_name = f"{prefix}{stem}({counter}){suffix}"
                new_path = Path(directory) / new_name
                if not new_path.exists() and not new_path.is_symlink():
                    return str(new_path)
                counter += 1
                if counter > 1000:
                    raise ValueError("Too many files with similar names")
        
        return str(base_path)
    
    @staticmethod
    def validate_file_size(size: int, max_size_mb: int = 0) -> bool:
        if size <= 0:
            return False
        if max_size_mb > 0:
            max_bytes = max_size_mb * 1024 * 1024
            if size > max_bytes:
                return False
        if size > 100 * 1024 * 1024 * 1024:
            return False
        return True
    
    @staticmethod
    def check_disk_space(required_bytes: int, path: str = ".") -> bool:
        try:
            stat = os.statvfs(path)
            available_bytes = stat.f_bavail * stat.f_frsize
            required_with_buffer = int(required_bytes * 1.1)
            return available_bytes >= required_with_buffer
        except Exception:
            return True
    
    @staticmethod
    def is_safe_file(file_path: str) -> bool:
        """Check if file is safe to read (simplified version)."""
        try:
            # Must exist and be a regular file
            if not os.path.exists(file_path):
                return False
            if not os.path.isfile(file_path):
                return False
            
            # Reject symlinks (security)
            if os.path.islink(file_path):
                return False
            
            # Reject special system files (only exact paths, not subpaths)
            abs_path = os.path.abspath(file_path)
            dangerous_exact = ['/dev/null', '/dev/zero', '/proc/self', '/sys/kernel']
            for dangerous in dangerous_exact:
                if abs_path == dangerous or abs_path.startswith(dangerous + '/'):
                    return False
            
            return True
        except Exception:
            return False


# ============================================================================
# MESSAGE VALIDATOR
# ============================================================================

class MessageValidator:
    """Validates JSON messages from server."""
    
    @staticmethod
    def validate_message(message: dict, required_fields: dict) -> bool:
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
        return MessageValidator.validate_message(message, {
            'filename': str, 'size': int, 'sha256': str
        })
    
    @staticmethod
    def validate_resume_meta(message: dict) -> bool:
        return MessageValidator.validate_message(message, {
            'filename': str, 'size': int, 'offset': int,
            'remaining': int, 'sha256': str
        })
    
    @staticmethod
    def validate_file_list(message: dict) -> bool:
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
        if not MessageValidator.validate_message(message, {
            'pattern': str, 'count': int, 'files': list
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
        return MessageValidator.validate_message(message, {
            'username': str, 'uploaded': int, 'downloaded': int,
            'files_sent': int, 'files_received': int
        })
    
    @staticmethod
    def validate_pending_requests(message: dict) -> bool:
        return MessageValidator.validate_message(message, {
            'incoming': list, 'outgoing': list
        })


# ============================================================================
# DEVICE IDENTITY
# ============================================================================

class DeviceIdentity:
    """Generates and manages unique device identity."""
    
    def __init__(self, config_dir: Path = None):
        config_dir = config_dir or Path.home() / CONFIG["client"]["config_dir"]
        config_dir.mkdir(parents=True, exist_ok=True)
        self.identity_file = config_dir / CONFIG["client"]["device_id_file"]
        self.identity = self._load_or_create_identity()
    
    def _load_or_create_identity(self) -> dict:
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
        if Path('/etc/machine-id').exists():
            try:
                with open('/etc/machine-id', 'r') as f:
                    return f.read().strip()
            except Exception:
                pass
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
        if platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SOFTWARE\Microsoft\Cryptography")
                value, _ = winreg.QueryValueEx(key, "MachineGuid")
                winreg.CloseKey(key)
                return value
            except Exception:
                pass
        return str(uuid.uuid4())
    
    def get_fingerprint(self) -> str:
        factors = [self.identity["device_uuid"], self.identity["machine_id"]]
        combined = "|".join(factors)
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def get_device_id(self) -> str:
        fingerprint = self.get_fingerprint()
        chunks = [fingerprint[i:i+7].upper() for i in range(0, 56, 7)]
        return "-".join(chunks)


# ============================================================================
# CREDENTIALS ENCRYPTION (Optional)
# ============================================================================

class CredentialsEncryption:
    """Optional encryption for stored credentials."""
    
    @staticmethod
    def is_available() -> bool:
        return CRYPTO_AVAILABLE
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, 
                         salt=salt, iterations=480000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    @staticmethod
    def encrypt(data: str, password: str) -> str:
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
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography package not installed")
        combined = base64.b64decode(encrypted_data.encode())
        salt = combined[:16]
        encrypted = combined[16:]
        key = CredentialsEncryption.derive_key(password, salt)
        f = Fernet(key)
        return f.decrypt(encrypted).decode()


# ============================================================================
# CREDENTIAL MANAGER (Race Condition Safe)
# ============================================================================

class CredentialManager:
    """Manages saved pairing info with optional encryption."""
    
    def __init__(self, config_dir: Path = None):
        config_dir = config_dir or Path.home() / CONFIG["client"]["config_dir"]
        config_dir.mkdir(parents=True, exist_ok=True)
        self.credentials_file = config_dir / CONFIG["client"]["credentials_file"]
        self.encrypt = CONFIG["security"]["encrypt_credentials"]
    
    def save_pairing(self, server_ip: str, port: int, username: str, 
                     device_fingerprint: str) -> None:
        credentials = {
            'server_ip': server_ip, 'port': port, 'username': username,
            'device_fingerprint': device_fingerprint, 'encrypted': False
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
                credentials = {'encrypted': True, 'credentials_data': encrypted_data}
                json_data = json.dumps(credentials, indent=2)
        try:
            with open(self.credentials_file, 'w') as f:
                f.write(json_data)
            os.chmod(self.credentials_file, 0o600)
        except Exception as e:
            logging.error(f"Failed to save credentials: {e}", exc_info=True)
            print(f"❌ Failed to save credentials")
    
    def load_pairing(self) -> Optional[dict]:
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
                    'server_ip': data['server_ip'], 'port': data['port'],
                    'username': data['username'], 
                    'device_fingerprint': data['device_fingerprint']
                }
        except FileNotFoundError:
            return None
        except Exception as e:
            logging.error(f"Error loading credentials: {e}", exc_info=True)
            print(f"❌ Error loading credentials")
            return None
    
    def clear_pairing(self) -> None:
        try:
            if self.credentials_file.exists():
                self.credentials_file.unlink()
                print("✅ Pairing cleared.")
            else:
                print("⚠️  No saved pairing found")
        except Exception as e:
            logging.error(f"Failed to clear pairing: {e}", exc_info=True)
            print(f"❌ Failed to clear pairing")


# ============================================================================
# RESUME TRANSFER MANAGER
# ============================================================================

class ResumeManager:
    """Manages partial downloads/uploads for resume capability."""
    
    def __init__(self, directory: str = "."):
        self.directory = directory
    
    def get_partial_path(self, filename: str) -> str:
        return os.path.join(self.directory, 
                           f"{filename}{CONFIG['client']['partial_suffix']}")
    
    def get_meta_path(self, filename: str) -> str:
        return os.path.join(self.directory, 
                           f"{filename}{CONFIG['client']['partial_suffix']}.meta")
    
    def save_metadata(self, filename: str, total_size: int, sha256: str, 
                      bytes_transferred: int) -> None:
        meta = {
            'filename': filename, 'total_size': total_size, 'sha256': sha256,
            'bytes_transferred': bytes_transferred, 'last_updated': time.time()
        }
        meta_path = self.get_meta_path(filename)
        try:
            with open(meta_path, 'w') as f:
                json.dump(meta, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save metadata: {e}", exc_info=True)
    
    def load_metadata(self, filename: str) -> Optional[dict]:
        meta_path = self.get_meta_path(filename)
        if not os.path.exists(meta_path):
            return None
        try:
            with open(meta_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    
    def cleanup(self, filename: str) -> None:
        for path in [self.get_partial_path(filename), self.get_meta_path(filename)]:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
    
    def list_partials(self) -> List[dict]:
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
                        'filename': original_name, 'partial_path': partial_path,
                        'actual_size': actual_size, 'total_size': total_size,
                        'sha256': meta['sha256'] if meta else None,
                        'progress': (actual_size / total_size * 100) if total_size > 0 else 0
                    })
        except Exception:
            pass
        return partials


# ============================================================================
# SENT HISTORY MANAGER (NEW)
# ============================================================================

class SentHistoryManager:
    """Manages sent files history in ~/JulianSent/."""
    
    def __init__(self):
        self.history_dir = Path.home() / CONFIG["client"]["sent_history_folder"]
        self.history_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.history_dir, 0o700)
        except Exception:
            pass
        self.history_file = self.history_dir / CONFIG["client"]["sent_history_file"]
        self.lock = threading.Lock()
    
    def add_entry(self, filename: str, sent_to: str, size: int, 
                  request_id: str = "", status: str = "sent") -> None:
        """Add a new entry to sent history."""
        entry = {
            'filename': filename,
            'sent_to': sent_to,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'size': size,
            'status': status,
            'request_id': request_id
        }
        with self.lock:
            history = self._load_history()
            history.insert(0, entry)
            # Keep only last N entries
            limit = CONFIG["client"]["history_limit"]
            history = history[:limit]
            self._save_history(history)
    
    def update_status(self, request_id: str, status: str) -> None:
        """Update status of a sent request."""
        with self.lock:
            history = self._load_history()
            for entry in history:
                if entry.get('request_id') == request_id:
                    entry['status'] = status
                    break
            self._save_history(history)
    
    def get_recent(self, limit: int = 5) -> List[dict]:
        """Get recent sent history."""
        with self.lock:
            history = self._load_history()
            return history[:limit]
    
    def get_all(self) -> List[dict]:
        """Get all sent history."""
        with self.lock:
            return self._load_history()
    
    def clear(self) -> None:
        """Clear sent history."""
        with self.lock:
            self._save_history([])
    
    def _load_history(self) -> List[dict]:
        if not self.history_file.exists():
            return []
        try:
            with open(self.history_file, 'r') as f:
                return json.load(f)
        except Exception:
            return []
    
    def _save_history(self, history: List[dict]) -> None:
        try:
            with open(self.history_file, 'w') as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save history: {e}", exc_info=True)


# ============================================================================
# SAFETY NUMBERS
# ============================================================================

class SafetyNumbers:
    """Verifies server identity using Safety Numbers."""
    
    @staticmethod
    def verify(client_socket, expected_numbers: str = None) -> bool:
        try:
            JsonProtocol.send_message(client_socket, {"type": "SERVER_FINGERPRINT"})
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
            print("=" * 60)
            if expected_numbers:
                return safety_numbers == expected_numbers
            else:
                user_input = input("\n🔍 Do the numbers match? (yes/no): ").strip().lower()
                return user_input in ['yes', 'y']
        except Exception as e:
            logging.error(f"Verification error: {e}", exc_info=True)
            print(f"❌ Verification error")
            return False


# ============================================================================
# LOCK FILE
# ============================================================================

class LockFile:
    """Prevents multiple instances from running simultaneously."""
    
    def __init__(self, config_dir: Path):
        self.lock_file = config_dir / "client.lock"
    
    def acquire(self) -> bool:
        if self.lock_file.exists():
            try:
                with open(self.lock_file, 'r') as f:
                    old_pid = int(f.read().strip())
                os.kill(old_pid, 0)
                return False
            except (ProcessLookupError, ValueError, OSError):
                try:
                    self.lock_file.unlink()
                except Exception:
                    pass
        try:
            with open(self.lock_file, 'w') as f:
                f.write(str(os.getpid()))
            return True
        except Exception as e:
            logging.error(f"Failed to acquire lock: {e}", exc_info=True)
            return False
    
    def release(self) -> None:
        try:
            if self.lock_file.exists():
                self.lock_file.unlink()
        except Exception:
            pass


# ============================================================================
# SERVICE DISCOVERY
# ============================================================================

class ServiceDiscovery:
    """Discover Julian servers on the local network via UDP broadcast."""
    
    def __init__(self, timeout: int = None):
        self.timeout = timeout or CONFIG["discovery"]["timeout"]
        self.broadcast_port = CONFIG["discovery"]["broadcast_port"]
    
    def discover(self) -> List[dict]:
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
                            'ip': addr[0], 'port': server_info.get('port'),
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
# JSON PROTOCOL (TCP-Safe)
# ============================================================================

class JsonProtocol:
    """JSON-based protocol with length prefix."""
    
    @staticmethod
    def send_message(sock: socket.socket, data: dict) -> None:
        message = json.dumps(data)
        encoded = message.encode('utf-8')
        length = len(encoded).to_bytes(4, 'big')
        sock.send(length + encoded)
    
    @staticmethod
    def recv_message(sock: socket.socket, timeout: int = None) -> Optional[dict]:
        if timeout:
            sock.settimeout(timeout)
        try:
            length_bytes = b""
            while len(length_bytes) < 4:
                chunk = sock.recv(4 - len(length_bytes))
                if not chunk:
                    return None
                length_bytes += chunk
            length = int.from_bytes(length_bytes, 'big')
            if length > 10 * 1024 * 1024:
                logging.error(f"Received oversized message: {length} bytes")
                return None
            message_bytes = b""
            while len(message_bytes) < length:
                chunk = sock.recv(min(4096, length - len(message_bytes)))
                if not chunk:
                    return None
                message_bytes += chunk
            return json.loads(message_bytes.decode('utf-8'))
        except json.JSONDecodeError as e:
            logging.error(f"Received invalid JSON: {e}")
            return None
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
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def show_progress(current: int, total: int, prefix: str = "") -> None:
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
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    @staticmethod
    def get_system_info() -> tuple:
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
# SECURE CLIENT (Security Hardened)
# ============================================================================

class SecureClient:
    """Main client class with all security features."""
    
    def __init__(self, server_ip: str, server_port: int, config_dir: Path = None):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.is_connected = False
        self.username = None
        self.pending_requests = []
        self.config_dir = config_dir or Path.home() / CONFIG["client"]["config_dir"]
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.device_identity = DeviceIdentity(self.config_dir)
        self.resume_manager = ResumeManager(".")
        self.sent_history = SentHistoryManager()
        self.os_info, self.distribution, self.device_type = FileTransferUtils.get_system_info()
        log_file = self.config_dir / CONFIG["client"]["log_file"]
        logging.basicConfig(
            filename=str(log_file), filemode='a',
            format='%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO
        )
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context
    
    def _connect_socket(self) -> bool:
        max_retries = CONFIG["client"]["max_retries"]
        retry_delay = CONFIG["client"]["retry_delay"]
        connect_timeout = CONFIG["client"]["connect_timeout"]
        for attempt in range(1, max_retries + 1):
            try:
                context = self._create_ssl_context()
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(connect_timeout)
                self.socket = context.wrap_socket(self.socket, server_hostname=self.server_ip)
                self.socket.connect((self.server_ip, self.server_port))
                self.socket.settimeout(None)
                return True
            except Exception as e:
                if attempt < max_retries:
                    print(f"⚠️  Connection attempt {attempt}/{max_retries} failed: {e}")
                    print(f"⏳ Retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                else:
                    logging.error(f"Connection failed: {e}", exc_info=True)
                    print(f"❌ Connection failed after {max_retries} attempts")
                    return False
    
    def setup(self, username: str) -> bool:
        if not self._connect_socket():
            return False
        try:
            device_info = f"{self.os_info}||{self.distribution}||{self.device_type}"
            device_fingerprint = self.device_identity.get_fingerprint()
            JsonProtocol.send_message(self.socket, {
                "type": "PAIR_REQUEST", "username": username,
                "device_info": device_info, "device_fingerprint": device_fingerprint
            })
            response = JsonProtocol.recv_message(self.socket)
            if not response or response.get('type') != 'PAIR_CODE':
                print(f"❌ Unexpected response")
                return False
            print("\n" + "=" * 60)
            print("🔑 PAIRING REQUIRED")
            print("=" * 60)
            print(f"The server has generated a pairing code.")
            print(f"👉 Look at the SERVER console to see the code.")
            print("=" * 60)
            entered_code = input("\n🔑 Enter the pairing code from server admin: ").strip()
            JsonProtocol.send_message(self.socket, {"type": "PAIR_CONFIRM", "code": entered_code})
            response = JsonProtocol.recv_message(self.socket)
            if not response or response.get('type') != 'PAIRED_OK':
                error_msg = response.get('message', 'Unknown error') if response else 'Pairing failed'
                print(f"❌ Pairing failed: {error_msg}")
                return False
            self.username = username
            self.is_connected = True
            print("\n✅ Pairing successful!")
            return True
        except Exception as e:
            logging.error(f"Setup error: {e}", exc_info=True)
            print(f"❌ Setup error")
            return False
    
    def connect_with_code(self, username: str, code: str) -> bool:
        if not self._connect_socket():
            return False
        try:
            device_fingerprint = self.device_identity.get_fingerprint()
            JsonProtocol.send_message(self.socket, {
                "type": "CODE_LOGIN", "username": username,
                "code": code, "device_fingerprint": device_fingerprint
            })
            response = JsonProtocol.recv_message(self.socket)
            if response and response.get('type') == 'LOGIN_OK':
                self.username = response.get('username')
                self.is_connected = True
                self._check_for_notifications()
                return True
            else:
                error_msg = response.get('message', 'Unknown error') if response else 'Connection failed'
                print(f"❌ Login failed: {error_msg}")
                return False
        except Exception as e:
            logging.error(f"Login error: {e}", exc_info=True)
            print(f"❌ Login error")
            return False
    
    def _check_for_notifications(self) -> None:
        try:
            self.socket.settimeout(2)
            response = JsonProtocol.recv_message(self.socket)
            self.socket.settimeout(None)
            if response:
                if response.get('type') == 'PENDING_REQUESTS':
                    self._handle_pending_requests_notification(response)
                elif response.get('type') == 'INCOMING_TRANSFER_REQUEST':
                    self._handle_incoming_transfer_request(response)
        except socket.timeout:
            pass
        except Exception as e:
            logging.debug(f"Notification check error: {e}")
    
    def _handle_pending_requests_notification(self, response: dict) -> None:
        incoming = response.get('incoming', [])
        if incoming:
            print(f"\n📬 You have {len(incoming)} pending transfer request(s)!")
            print("💡 Use 'requests' command to view and manage them")
            self.pending_requests = incoming
    
    def _handle_incoming_transfer_request(self, response: dict) -> None:
        request_id = response.get('request_id', '')
        from_user = response.get('from_user', 'unknown')
        filename = response.get('filename', '')
        file_size = response.get('file_size', 0)
        print(f"\n" + "=" * 60)
        print(f"📥 INCOMING TRANSFER REQUEST")
        print(f"=" * 60)
        print(f"   From: {from_user}")
        print(f"   File: {filename} ({FileTransferUtils.format_size(file_size)})")
        print(f"   Request ID: {request_id}")
        print(f"=" * 60)
        print(f"💡 Use 'accept {request_id}' to accept")
        print(f"💡 Use 'reject {request_id}' to reject")
        print("=" * 60 + "\n")
    
    def verify_server(self) -> bool:
        return SafetyNumbers.verify(self.socket)
    
    def send_command(self, data: dict) -> Optional[dict]:
        try:
            JsonProtocol.send_message(self.socket, data)
            return JsonProtocol.recv_message(self.socket)
        except Exception as e:
            logging.error(f"Command error: {e}", exc_info=True)
            print(f"\n❌ Error")
            return None
    
    def send_file(self, file_path: str, to_user: str = "server") -> bool:
        """Upload file with proper resource management (FIXED)."""
        file_handle = None
        
        try:
            # Step 1: Validate file exists and is readable
            if not os.path.exists(file_path):
                print(f"❌ File not found: {file_path}")
                return False
            
            if not os.path.isfile(file_path):
                print(f"❌ Not a regular file: {file_path}")
                return False
            
            # Step 2: Open file ONCE and keep it open
            try:
                file_handle = open(file_path, 'rb')
            except PermissionError:
                print(f"❌ Permission denied: {file_path}")
                return False
            except Exception as e:
                print(f"❌ Cannot open file: {e}")
                return False
            
            # Step 3: Get file info
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            if file_size == 0:
                print(f"❌ File is empty: {file_name}")
                return False
            
            # Step 4: Calculate SHA256 from the OPENED file handle (NOT opening again!)
            print(f"🔐 Calculating SHA256 for {file_name}...")
            sha256_hash = hashlib.sha256()
            file_handle.seek(0)
            while True:
                chunk = file_handle.read(8192)
                if not chunk:
                    break
                sha256_hash.update(chunk)
            file_sha256 = sha256_hash.hexdigest()
            
            # Reset file pointer to beginning for sending
            file_handle.seek(0)
            
            print(f"\n📤 Sending: {file_name} ({FileTransferUtils.format_size(file_size)})")
            print(f"   🔏 SHA256: {file_sha256[:16]}...")
            
            # Step 5: Send metadata to server
            try:
                JsonProtocol.send_message(self.socket, {
                    "type": "UPLOAD", 
                    "filename": file_name,
                    "size": file_size, 
                    "sha256": file_sha256
                })
            except Exception as e:
                print(f"\n❌ Failed to send metadata: {e}")
                return False
            
            # Step 6: Send file data
            transfer_timeout = CONFIG["client"]["transfer_timeout"]
            sent_size = 0
            self.socket.settimeout(transfer_timeout)
            
            try:
                while sent_size < file_size:
                    try:
                        chunk = file_handle.read(4096)
                        if not chunk:
                            break
                        self.socket.send(chunk)
                        sent_size += len(chunk)
                        FileTransferUtils.show_progress(sent_size, file_size, "Sending")
                    except socket.timeout:
                        print(f"\n⚠️  Transfer timeout after sending {sent_size} bytes")
                        return False
                    except Exception as e:
                        print(f"\n❌ Network error during transfer: {e}")
                        return False
                
                self.socket.settimeout(None)
                
                # Step 7: Wait for server confirmation
                try:
                    response = JsonProtocol.recv_message(self.socket)
                except Exception as e:
                    print(f"\n❌ Failed to receive server response: {e}")
                    return False
                
                if not response:
                    print(f"\n❌ No response from server")
                    return False
                
                if response.get('type') == 'FILE_OK':
                    print(f"\n✅ File sent successfully!")
                    # Record in sent history
                    self.sent_history.add_entry(file_name, to_user, file_size)
                    return True
                elif response.get('type') == 'FILE_CORRUPTED':
                    print(f"\n❌ Server detected file corruption (SHA256 mismatch)")
                    print(f"   Expected: {file_sha256}")
                    return False
                else:
                    error_msg = response.get('message', 'Unknown error')
                    print(f"\n❌ Server rejected file: {error_msg}")
                    return False
            
            finally:
                self.socket.settimeout(None)
        
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        finally:
            # ALWAYS close the file handle
            if file_handle:
                try:
                    file_handle.close()
                except Exception:
                    pass
    
    def download_file(self, file_name: str, resume: bool = True, 
                      target_dir: str = None) -> bool:
        """Download file with size validation and infinite loop protection."""
        try:
            safe_name = FileValidator.validate_download_filename(file_name)
            
            # Use target_dir if provided, else use current directory
            if target_dir is None:
                target_dir = self.resume_manager.directory
            
            partial_path = os.path.join(target_dir, 
                                        f"{safe_name}{CONFIG['client']['partial_suffix']}")
            
            # Load metadata from target_dir
            old_dir = self.resume_manager.directory
            self.resume_manager.directory = target_dir
            meta = self.resume_manager.load_metadata(safe_name) if resume else None
            self.resume_manager.directory = old_dir
            
            if resume and meta and os.path.exists(partial_path):
                offset = os.path.getsize(partial_path)
                if offset < 0:
                    print("❌ Invalid offset in partial file")
                    return self._download_fresh(safe_name, target_dir)
                
                print(f"\n🔄 Resuming download from {FileTransferUtils.format_size(offset)}")
                
                JsonProtocol.send_message(self.socket, {
                    "type": "RESUME_DOWNLOAD", "filename": safe_name, "offset": offset
                })
                
                metadata = JsonProtocol.recv_message(self.socket)
                
                if not metadata or metadata.get('type') != 'RESUME_META':
                    print("⚠️ Resume failed, starting fresh download")
                    return self._download_fresh(safe_name, target_dir)
                
                if not MessageValidator.validate_resume_meta(metadata):
                    print("❌ Invalid resume metadata")
                    return self._download_fresh(safe_name, target_dir)
                
                file_size = metadata['size']
                remaining = metadata['remaining']
                file_sha256 = metadata['sha256']
                
                if remaining <= 0:
                    print("❌ Invalid remaining size")
                    return self._download_fresh(safe_name, target_dir)
                
                if offset + remaining != file_size:
                    print("⚠️ Size mismatch, starting fresh download")
                    return self._download_fresh(safe_name, target_dir)
                
                # Check download size limit
                max_download_size = CONFIG["client"]["max_download_size_mb"] * 1024 * 1024
                if max_download_size > 0 and file_size > max_download_size:
                    print(f"❌ File too large: {FileTransferUtils.format_size(file_size)}")
                    print(f"💡 Maximum allowed: {FileTransferUtils.format_size(max_download_size)}")
                    return False
                
                JsonProtocol.send_message(self.socket, {"type": "READY"})
                print(f"📥 Downloading remaining: {FileTransferUtils.format_size(remaining)}")
                
                transfer_timeout = CONFIG["client"]["transfer_timeout"]
                self.socket.settimeout(transfer_timeout)
                
                received_size = 0
                file_handle = None
                
                try:
                    file_handle = open(partial_path, 'ab')
                    
                    while received_size < remaining:
                        try:
                            chunk_size = min(4096, remaining - received_size)
                            data = self.socket.recv(chunk_size)
                            if not data:
                                break
                            file_handle.write(data)
                            received_size += len(data)
                            FileTransferUtils.show_progress(offset + received_size, 
                                                            file_size, "Downloading")
                        except socket.timeout:
                            print(f"\n⚠️  Transfer timeout. Progress saved.")
                            old_dir = self.resume_manager.directory
                            self.resume_manager.directory = target_dir
                            self.resume_manager.save_metadata(safe_name, file_size, 
                                                              file_sha256, 
                                                              offset + received_size)
                            self.resume_manager.directory = old_dir
                            return False
                finally:
                    if file_handle:
                        try:
                            file_handle.close()
                        except Exception:
                            pass
                    self.socket.settimeout(None)
                
                if FileTransferUtils.calculate_sha256(partial_path) == file_sha256:
                    final_path = os.path.join(target_dir, 
                                             f"{CONFIG['client']['download_prefix']}{safe_name}")
                    os.rename(partial_path, final_path)
                    old_dir = self.resume_manager.directory
                    self.resume_manager.directory = target_dir
                    self.resume_manager.cleanup(safe_name)
                    self.resume_manager.directory = old_dir
                    print(f"\n✅ Downloaded: {final_path}")
                    # Record in sent history (as received)
                    self.sent_history.add_entry(safe_name, "server (download)", 
                                               file_size, status="received")
                    return True
                else:
                    print(f"\n⚠️ File corrupted!")
                    return False
            else:
                return self._download_fresh(safe_name, target_dir)
        
        except ValueError as e:
            print(f"❌ Validation error: {e}")
            return False
        except Exception as e:
            logging.error(f"Download error: {e}", exc_info=True)
            print(f"❌ Download error")
            return False
    
    def _download_fresh(self, file_name: str, target_dir: str = None) -> bool:
        """Fresh download with size validation."""
        if target_dir is None:
            target_dir = self.resume_manager.directory
        
        JsonProtocol.send_message(self.socket, {"type": "DOWNLOAD", "filename": file_name})
        metadata = JsonProtocol.recv_message(self.socket)
        
        if not MessageValidator.validate_file_meta(metadata):
            print("❌ Invalid file metadata from server")
            return False
        
        file_name = metadata['filename']
        file_size = metadata['size']
        file_sha256 = metadata['sha256']
        
        # Check download size limit
        max_download_size = CONFIG["client"]["max_download_size_mb"] * 1024 * 1024
        if max_download_size > 0 and file_size > max_download_size:
            print(f"❌ File too large: {FileTransferUtils.format_size(file_size)}")
            print(f"💡 Maximum allowed: {FileTransferUtils.format_size(max_download_size)}")
            return False
        
        if not FileValidator.validate_file_size(file_size):
            print(f"❌ Invalid file size: {file_size}")
            return False
        
        if not FileValidator.check_disk_space(file_size, target_dir):
            print(f"❌ Not enough disk space")
            return False
        
        save_path = FileValidator.get_safe_save_path(
            file_name, directory=target_dir, prefix=CONFIG['client']['download_prefix']
        )
        partial_path = os.path.join(target_dir, 
                                    f"{file_name}{CONFIG['client']['partial_suffix']}")
        
        JsonProtocol.send_message(self.socket, {"type": "READY"})
        print(f"\n📥 Downloading: {file_name} ({FileTransferUtils.format_size(file_size)})")
        print(f"💾 Saving to: {save_path}")
        
        transfer_timeout = CONFIG["client"]["transfer_timeout"]
        self.socket.settimeout(transfer_timeout)
        
        received_size = 0
        file_handle = None
        
        try:
            file_handle = open(partial_path, 'wb')
            
            while received_size < file_size:
                try:
                    chunk_size = min(4096, file_size - received_size)
                    data = self.socket.recv(chunk_size)
                    if not data:
                        break
                    file_handle.write(data)
                    received_size += len(data)
                    FileTransferUtils.show_progress(received_size, file_size, "Downloading")
                    
                    if received_size % (1024 * 1024) < 4096:
                        old_dir = self.resume_manager.directory
                        self.resume_manager.directory = target_dir
                        self.resume_manager.save_metadata(file_name, file_size, 
                                                          file_sha256, received_size)
                        self.resume_manager.directory = old_dir
                except socket.timeout:
                    print(f"\n⚠️  Transfer timeout. Progress saved.")
                    old_dir = self.resume_manager.directory
                    self.resume_manager.directory = target_dir
                    self.resume_manager.save_metadata(file_name, file_size, 
                                                      file_sha256, received_size)
                    self.resume_manager.directory = old_dir
                    return False
        finally:
            if file_handle:
                try:
                    file_handle.close()
                except Exception:
                    pass
            self.socket.settimeout(None)
        
        if FileTransferUtils.calculate_sha256(partial_path) == file_sha256:
            os.rename(partial_path, save_path)
            old_dir = self.resume_manager.directory
            self.resume_manager.directory = target_dir
            self.resume_manager.cleanup(file_name)
            self.resume_manager.directory = old_dir
            print(f"\n✅ Downloaded: {save_path}")
            # Record in sent history
            self.sent_history.add_entry(file_name, "server (download)", 
                                       file_size, status="received")
            return True
        else:
            print(f"\n⚠️ File corrupted!")
            try:
                os.remove(partial_path)
            except Exception:
                pass
            return False
    
    def delete_file(self, file_name: str) -> bool:
        JsonProtocol.send_message(self.socket, {"type": "DELETE", "filename": file_name})
        response = JsonProtocol.recv_message(self.socket)
        if response and response.get('type') == 'DELETE_OK':
            print(f"✅ Deleted: {file_name}")
            return True
        else:
            error = response.get('message', 'Unknown error') if response else 'Connection failed'
            print(f"❌ Delete failed: {error}")
            return False
    
    def rename_file(self, old_name: str, new_name: str) -> bool:
        JsonProtocol.send_message(self.socket, {
            "type": "RENAME", "old_name": old_name, "new_name": new_name
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
        JsonProtocol.send_message(self.socket, {"type": "SEARCH", "pattern": pattern})
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
        response = self.send_command({"type": "LIST"})
        if not response or not MessageValidator.validate_file_list(response):
            return []
        return response.get('files', [])
    
    def get_users_list(self) -> None:
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
    
    def request_transfer(self, to_user: str, filename: str) -> bool:
        response = self.send_command({
            "type": "REQUEST_TRANSFER", "to_user": to_user, "filename": filename
        })
        if not response:
            print("❌ No response from server")
            return False
        if response.get('type') == 'REQUEST_CREATED':
            request_id = response.get('request_id', '')
            file_size = response.get('file_size', 0)
            print(f"\n✅ Transfer request created!")
            print(f"   Request ID: {request_id}")
            print(f"   To: {response.get('to_user')}")
            print(f"   File: {response.get('filename')} ({FileTransferUtils.format_size(file_size)})")
            print(f"\n💡 Waiting for {to_user} to accept the request...")
            # Record in sent history
            self.sent_history.add_entry(filename, to_user, file_size, 
                                       request_id=request_id, status="pending")
            return True
        else:
            error = response.get('message', 'Unknown error')
            print(f"❌ Failed to create request: {error}")
            return False
    
    def list_pending_requests(self) -> None:
        response = self.send_command({"type": "LIST_PENDING_REQUESTS"})
        if not response or not MessageValidator.validate_pending_requests(response):
            print("\n❌ Could not retrieve pending requests")
            return
        incoming = response.get('incoming', [])
        outgoing = response.get('outgoing', [])
        if not incoming and not outgoing:
            print("\n📭 No pending transfer requests")
            return
        if incoming:
            print(f"\n📥 Incoming Requests ({len(incoming)}):")
            print("=" * 80)
            for i, req in enumerate(incoming, 1):
                print(f"  [{i}] 📄 {req['filename']} ({FileTransferUtils.format_size(req['file_size'])})")
                print(f"       From: {req['from_user']}")
                print(f"       Request ID: {req['id']}")
            print("=" * 80)
        if outgoing:
            print(f"\n📤 Outgoing Requests ({len(outgoing)}):")
            print("=" * 80)
            for i, req in enumerate(outgoing, 1):
                status_icon = {'pending': '⏳', 'accepted': '✅'}.get(req['status'], '?')
                print(f"  [{i}] {status_icon} 📄 {req['filename']}")
                print(f"       To: {req['to_user']}")
                print(f"       Request ID: {req['id']}")
            print("=" * 80)
    
    def accept_transfer(self, request_id: str) -> bool:
        response = self.send_command({"type": "ACCEPT_TRANSFER", "request_id": request_id})
        if not response:
            print("❌ No response from server")
            return False
        if response.get('type') == 'REQUEST_ACCEPTED':
            filename = response.get('filename', '')
            file_size = response.get('file_size', 0)
            print(f"\n✅ Transfer request accepted!")
            print(f"📥 Downloading: {filename} ({FileTransferUtils.format_size(file_size)})")
            # Update sent history
            self.sent_history.update_status(request_id, "accepted")
            success = self.download_file(filename, resume=False)
            if success:
                self.sent_history.update_status(request_id, "received")
            return success
        else:
            error = response.get('message', 'Unknown error')
            print(f"❌ Failed to accept request: {error}")
            return False
    
    def reject_transfer(self, request_id: str, reason: str = "") -> bool:
        response = self.send_command({
            "type": "REJECT_TRANSFER", "request_id": request_id, "reason": reason
        })
        if not response:
            print("❌ No response from server")
            return False
        if response.get('type') == 'REQUEST_REJECTED':
            print(f"\n✅ Transfer request rejected")
            self.sent_history.update_status(request_id, "rejected")
            return True
        else:
            error = response.get('message', 'Unknown error')
            print(f"❌ Failed to reject request: {error}")
            return False
    
    def cancel_transfer(self, request_id: str) -> bool:
        response = self.send_command({"type": "CANCEL_TRANSFER", "request_id": request_id})
        if not response:
            print("❌ No response from server")
            return False
        if response.get('type') == 'REQUEST_CANCELLED':
            print(f"\n✅ Transfer request cancelled")
            self.sent_history.update_status(request_id, "cancelled")
            return True
        else:
            error = response.get('message', 'Unknown error')
            print(f"❌ Failed to cancel request: {error}")
            return False
    
    def close(self) -> None:
        self.is_connected = False
        try:
            if self.socket:
                JsonProtocol.send_message(self.socket, {"type": "QUIT"})
                self.socket.close()
        except Exception:
            pass
        logging.info("Client disconnected")


# ============================================================================
# TUI FILE BROWSER (curses-based, Zero Dependencies)
# ============================================================================

class JulianBrowser:
    """TUI file browser using curses."""
    
    def __init__(self, client: Optional[SecureClient] = None):
        self.client = client
        self.connected = client.is_connected if client else False
        self.username = client.username if client else ""
        
        # Setup folders
        self.local_folder = Path.home() / CONFIG["client"]["browser_folder"]
        self.local_folder.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.local_folder, 0o700)
        except Exception:
            pass
        
        self.sent_history = SentHistoryManager()
        
        # State
        self.active_panel = "local"  # "local" or "server"
        self.local_files: List[dict] = []
        self.server_files: List[dict] = []
        self.sent_history_list: List[dict] = []
        self.selected_local = 0
        self.selected_server = 0
        self.running = False
    
    def start(self):
        """Start the TUI browser."""
        if not CURSES_AVAILABLE:
            print("❌ curses not available on this system")
            print("💡 On Windows, install with: pip install windows-curses")
            return
        
        try:
            curses.wrapper(self._main)
        except Exception as e:
            print(f"❌ Browser error: {e}")
    
    def _main(self, stdscr):
        """Main curses loop."""
        curses.curs_set(0)
        stdscr.nodelay(False)
        
        # Initialize colors
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_RED, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_BLUE, -1)
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_GREEN)
        curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_CYAN)
        
        # Initial data load
        self._refresh_local_files()
        if self.connected:
            self._refresh_server_files()
        self._refresh_sent_history()
        
        self.running = True
        status_msg = "Ready. Press '?' for help."
        
        while self.running:
            try:
                self._draw(stdscr, status_msg)
                key = stdscr.getch()
                status_msg = self._handle_key(key, stdscr)
            except KeyboardInterrupt:
                break
            except curses.error:
                pass
            except Exception as e:
                status_msg = f"Error: {e}"
    
    def _draw(self, stdscr, status_msg: str):
        """Draw the complete browser UI."""
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        
        if h < 20 or w < 80:
            stdscr.addstr(0, 0, "Terminal too small! Need at least 80x20")
            stdscr.refresh()
            return
        
        # === HEADER ===
        header = f" Julian File Browser v4.4.0 "
        if self.connected:
            header += f" - {self.username}@{self.client.server_ip}:{self.client.server_port} "
        stdscr.attron(curses.color_pair(6))
        stdscr.addstr(0, 0, header.center(w)[:w-1])
        stdscr.attroff(curses.color_pair(6))
        
        # Layout: 2 columns, 3 sections
        left_w = w // 2 - 1
        right_w = w - left_w - 2
        right_x = left_w + 2
        
        # === LEFT PANEL: Local Files ===
        local_height = h - 10
        
        # Title
        title = f" 📁 JulianFiles ({len(self.local_files)}) "
        if self.active_panel == "local":
            stdscr.attron(curses.color_pair(7))
        else:
            stdscr.attron(curses.color_pair(4))
        stdscr.addstr(2, 0, title.center(left_w)[:left_w-1])
        stdscr.attroff(curses.color_pair(7) if self.active_panel == "local" else curses.color_pair(4))
        
        # File list
        visible_files = local_height - 3
        start_idx = max(0, self.selected_local - visible_files + 1)
        
        if not self.local_files:
            stdscr.addstr(3, 1, "(empty - drop files here)")
        else:
            for i in range(min(visible_files, len(self.local_files))):
                idx = start_idx + i
                if idx >= len(self.local_files):
                    break
                f = self.local_files[idx]
                line = f"  {f['icon']} {f['name'][:30]:<30} {f['size_str']:>10}"
                line = line[:left_w-2]
                
                if idx == self.selected_local and self.active_panel == "local":
                    stdscr.attron(curses.A_REVERSE)
                
                try:
                    stdscr.addstr(4 + i, 0, line.ljust(left_w))
                except curses.error:
                    pass
                
                if idx == self.selected_local and self.active_panel == "local":
                    stdscr.attroff(curses.A_REVERSE)
        
        # === RIGHT PANEL: Server Files ===
        server_height = h - 4
        
        title = f" 🌐 Server Files ({len(self.server_files)}) "
        if self.active_panel == "server":
            stdscr.attron(curses.color_pair(7))
        else:
            stdscr.attron(curses.color_pair(5))
        stdscr.addstr(2, right_x, title.center(right_w)[:right_w-1])
        stdscr.attroff(curses.color_pair(7) if self.active_panel == "server" else curses.color_pair(5))
        
        if not self.connected:
            stdscr.addstr(3, right_x + 1, "(not connected)")
        elif not self.server_files:
            stdscr.addstr(3, right_x + 1, "(empty)")
        else:
            visible_files = server_height - 3
            start_idx = max(0, self.selected_server - visible_files + 1)
            
            for i in range(min(visible_files, len(self.server_files))):
                idx = start_idx + i
                if idx >= len(self.server_files):
                    break
                f = self.server_files[idx]
                line = f"  {f['icon']} {f['name'][:30]:<30} {f['size_str']:>10}"
                line = line[:right_w-2]
                
                if idx == self.selected_server and self.active_panel == "server":
                    stdscr.attron(curses.A_REVERSE)
                
                try:
                    stdscr.addstr(4 + i, right_x, line.ljust(right_w))
                except curses.error:
                    pass
                
                if idx == self.selected_server and self.active_panel == "server":
                    stdscr.attroff(curses.A_REVERSE)
        
        # === BOTTOM: Sent History ===
        history_y = h - 8
        stdscr.attron(curses.color_pair(8))
        stdscr.addstr(history_y, 0, f" 📤 Sent History (Last 5) ".center(w)[:w-1])
        stdscr.attroff(curses.color_pair(8))
        
        recent = self.sent_history_list[:5]
        if not recent:
            stdscr.addstr(history_y + 1, 1, "  (no history yet)")
        else:
            for i, entry in enumerate(recent):
                status_icon = {
                    'sent': '✅', 'received': '📥', 'pending': '⏳',
                    'accepted': '✅', 'rejected': '❌', 'cancelled': '🚫'
                }.get(entry.get('status', ''), '?')
                
                line = f"  {status_icon} {entry['filename'][:25]:<25} → {entry['sent_to'][:15]:<15} {entry['timestamp'][11:16]}"
                line = line[:w-2]
                
                try:
                    stdscr.addstr(history_y + 1 + i, 0, line.ljust(w))
                except curses.error:
                    pass
        
        # === STATUS BAR ===
        status = status_msg + " | [?]Help [q]uit"
        stdscr.attron(curses.color_pair(6))
        try:
            stdscr.addstr(h - 1, 0, status[:w].ljust(w))
        except curses.error:
            pass
        stdscr.attroff(curses.color_pair(6))
        
        stdscr.refresh()
    
    def _handle_key(self, key, stdscr) -> str:
        """Handle keyboard input. Returns status message."""
        import curses
        
        if key == ord('q') or key == 27:  # q or ESC
            self.running = False
            return "Quitting..."
        
        elif key == ord('j') or key == curses.KEY_DOWN:
            if self.active_panel == "local":
                if self.local_files:
                    self.selected_local = min(self.selected_local + 1, len(self.local_files) - 1)
            else:
                if self.server_files:
                    self.selected_server = min(self.selected_server + 1, len(self.server_files) - 1)
        
        elif key == ord('k') or key == curses.KEY_UP:
            if self.active_panel == "local":
                self.selected_local = max(0, self.selected_local - 1)
            else:
                self.selected_server = max(0, self.selected_server - 1)
        
        elif key == ord('\t'):
            self.active_panel = "server" if self.active_panel == "local" else "local"
            return f"📂 {self.active_panel.title()} panel active"
        
        elif key == ord('u'):  # Upload
            return self._action_upload(stdscr)
        
        elif key == ord('d'):  # Download
            return self._action_download(stdscr)
        
        elif key == ord('s'):  # Send to user
            return self._action_send(stdscr)
        
        elif key == ord('x'):  # Delete
            return self._action_delete(stdscr)
        
        elif key == ord('r'):  # Rename
            return self._action_rename(stdscr)
        
        elif key == ord('h'):  # Show full history
            return self._action_show_history(stdscr)
        
        elif key == ord('?'):  # Help
            self._show_help(stdscr)
            return "Help closed"
        
        return ""
    
    def _refresh_local_files(self):
        """Refresh local files list."""
        self.local_files = []
        try:
            for item in sorted(self.local_folder.iterdir()):
                if item.name.startswith('.'):
                    continue
                if item.is_file():
                    size = item.stat().st_size
                    ext = item.suffix.lower()
                    icons = {
                        '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️',
                        '.pdf': '📕', '.doc': '📘', '.txt': '📄',
                        '.mp3': '🎵', '.mp4': '🎬', '.zip': '📦',
                    }
                    icon = icons.get(ext, '📄')
                    self.local_files.append({
                        'name': item.name,
                        'size': size,
                        'size_str': FileTransferUtils.format_size(size),
                        'path': str(item),
                        'icon': icon
                    })
        except Exception as e:
            logging.error(f"Error reading local files: {e}")
    
    def _refresh_server_files(self):
        """Refresh server files list."""
        if not self.connected or not self.client:
            self.server_files = []
            return
        try:
            files = self.client.list_server_files()
            self.server_files = []
            for f in files:
                size = f.get('size', 0)
                ext = Path(f['name']).suffix.lower()
                icons = {
                    '.jpg': '🖼️', '.jpeg': '🖼️', '.png': '🖼️',
                    '.pdf': '📕', '.doc': '📘', '.txt': '📄',
                    '.mp3': '🎵', '.mp4': '🎬', '.zip': '📦',
                }
                icon = icons.get(ext, '📄')
                self.server_files.append({
                    'name': f['name'],
                    'size': size,
                    'size_str': FileTransferUtils.format_size(size),
                    'icon': icon
                })
        except Exception as e:
            logging.error(f"Error reading server files: {e}")
    
    def _refresh_sent_history(self):
        """Refresh sent history list."""
        self.sent_history_list = self.sent_history.get_recent(5)
    
    def _input_dialog(self, stdscr, prompt: str, default: str = "") -> str:
        """Show input dialog and return user input."""
        stdscr.nodelay(False)
        h, w = stdscr.getmaxyx()
        
        # Draw dialog box
        box_w = 60
        box_h = 5
        box_x = (w - box_w) // 2
        box_y = (h - box_h) // 2
        
        # Clear area
        for i in range(box_h):
            try:
                stdscr.addstr(box_y + i, box_x, " " * box_w)
            except curses.error:
                pass
        
        # Draw border
        try:
            stdscr.addstr(box_y, box_x, "┌" + "─" * (box_w - 2) + "┐")
            stdscr.addstr(box_y + 1, box_x, "│" + " " * (box_w - 2) + "│")
            stdscr.addstr(box_y + 2, box_x, "│" + " " * (box_w - 2) + "│")
            stdscr.addstr(box_y + 3, box_x, "│" + " " * (box_w - 2) + "│")
            stdscr.addstr(box_y + 4, box_x, "└" + "─" * (box_w - 2) + "┘")
        except curses.error:
            pass
        
        # Draw prompt
        try:
            stdscr.addstr(box_y + 1, box_x + 2, prompt[:box_w-4])
        except curses.error:
            pass
        
        # Input field
        curses.echo()
        try:
            stdscr.addstr(box_y + 3, box_x + 2, " " * (box_w - 4))
            stdscr.addstr(box_y + 3, box_x + 2, default)
            stdscr.refresh()
            user_input = stdscr.getstr(box_y + 3, box_x + 2, box_w - 4).decode('utf-8')
        except Exception:
            user_input = ""
        curses.noecho()
        
        return user_input
    
    def _confirm_dialog(self, stdscr, message: str) -> bool:
        """Show confirmation dialog."""
        stdscr.nodelay(False)
        h, w = stdscr.getmaxyx()
        
        box_w = 60
        box_h = 6
        box_x = (w - box_w) // 2
        box_y = (h - box_h) // 2
        
        for i in range(box_h):
            try:
                stdscr.addstr(box_y + i, box_x, " " * box_w)
            except curses.error:
                pass
        
        try:
            stdscr.addstr(box_y, box_x, "┌" + "─" * (box_w - 2) + "┐")
            for i in range(1, box_h - 1):
                stdscr.addstr(box_y + i, box_x, "│" + " " * (box_w - 2) + "│")
            stdscr.addstr(box_y + box_h - 1, box_x, "└" + "─" * (box_w - 2) + "┘")
            
            # Split message into lines
            lines = message.split('\n')
            for i, line in enumerate(lines[:3]):
                stdscr.addstr(box_y + 1 + i, box_x + 2, line[:box_w-4])
            
            stdscr.addstr(box_y + box_h - 2, box_x + 2, "[y] Yes   [n] No")
            stdscr.refresh()
        except curses.error:
            pass
        
        while True:
            key = stdscr.getch()
            if key == ord('y') or key == ord('Y'):
                return True
            elif key == ord('n') or key == ord('N') or key == 27:
                return False
    
    def _action_upload(self, stdscr) -> str:
        """Upload selected local file to server."""
        if not self.connected:
            return "❌ Not connected to server"
        if self.active_panel != "local" or not self.local_files:
            return "❌ No file selected"
        
        file = self.local_files[self.selected_local]
        
        stdscr.nodelay(False)
        stdscr.addstr(stdscr.getmaxyx()[0] - 1, 0, 
                      f" Uploading {file['name']}...".ljust(stdscr.getmaxyx()[1]))
        stdscr.refresh()
        
        if self.client.send_file(file['path'], to_user="server"):
            self._refresh_server_files()
            self._refresh_sent_history()
            return f"✅ Uploaded: {file['name']}"
        return f"❌ Upload failed: {file['name']}"
    
    def _action_download(self, stdscr) -> str:
        """Download selected server file to JulianFiles."""
        if not self.connected:
            return "❌ Not connected to server"
        if self.active_panel != "server" or not self.server_files:
            return "❌ No file selected"
        
        file = self.server_files[self.selected_server]
        
        stdscr.nodelay(False)
        stdscr.addstr(stdscr.getmaxyx()[0] - 1, 0, 
                      f" Downloading {file['name']}...".ljust(stdscr.getmaxyx()[1]))
        stdscr.refresh()
        
        # Download to JulianFiles folder
        old_dir = self.client.resume_manager.directory
        self.client.resume_manager.directory = str(self.local_folder)
        
        try:
            if self.client.download_file(file['name'], resume=False, 
                                         target_dir=str(self.local_folder)):
                self._refresh_local_files()
                self._refresh_sent_history()
                return f"✅ Downloaded: {file['name']}"
            return f"❌ Download failed: {file['name']}"
        finally:
            self.client.resume_manager.directory = old_dir
    
    def _action_send(self, stdscr) -> str:
        """Send file to another user."""
        if not self.connected:
            return "❌ Not connected to server"
        
        # Get file from active panel
        if self.active_panel == "local":
            if not self.local_files:
                return "❌ No file selected"
            file = self.local_files[self.selected_local]
            filename = file['name']
            
            # Upload first
            stdscr.nodelay(False)
            stdscr.addstr(stdscr.getmaxyx()[0] - 1, 0, 
                          f" Uploading {filename}...".ljust(stdscr.getmaxyx()[1]))
            stdscr.refresh()
            
            if not self.client.send_file(file['path'], to_user="server"):
                return f"❌ Upload failed: {filename}"
        else:
            if not self.server_files:
                return "❌ No file selected"
            file = self.server_files[self.selected_server]
            filename = file['name']
        
        # Ask for recipient
        to_user = self._input_dialog(stdscr, f"Send '{filename}' to user:")
        if not to_user:
            return "❌ Cancelled"
        
        if self.client.request_transfer(to_user, filename):
            self._refresh_sent_history()
            return f"✅ Sent to {to_user}"
        return f"❌ Failed to send to {to_user}"
    
    def _action_delete(self, stdscr) -> str:
        """Delete selected file."""
        if self.active_panel == "local":
            if not self.local_files:
                return "❌ No file selected"
            file = self.local_files[self.selected_local]
            
            if not self._confirm_dialog(stdscr, f"Delete '{file['name']}' from local?"):
                return "Cancelled"
            
            try:
                Path(file['path']).unlink()
                self._refresh_local_files()
                if self.local_files:
                    self.selected_local = min(self.selected_local, len(self.local_files) - 1)
                return f"✅ Deleted: {file['name']}"
            except Exception as e:
                return f"❌ Delete failed: {e}"
        
        else:  # server
            if not self.connected:
                return "❌ Not connected"
            if not self.server_files:
                return "❌ No file selected"
            file = self.server_files[self.selected_server]
            
            if not self._confirm_dialog(stdscr, f"Delete '{file['name']}' from server?"):
                return "Cancelled"
            
            if self.client.delete_file(file['name']):
                self._refresh_server_files()
                if self.server_files:
                    self.selected_server = min(self.selected_server, len(self.server_files) - 1)
                return f"✅ Deleted from server: {file['name']}"
            return "❌ Delete failed"
    
    def _action_rename(self, stdscr) -> str:
        """Rename selected file."""
        if self.active_panel == "local":
            if not self.local_files:
                return "❌ No file selected"
            file = self.local_files[self.selected_local]
            
            new_name = self._input_dialog(stdscr, f"Rename '{file['name']}' to:", 
                                         default=file['name'])
            if not new_name or new_name == file['name']:
                return "Cancelled"
            
            try:
                old_path = Path(file['path'])
                new_path = old_path.parent / new_name
                old_path.rename(new_path)
                self._refresh_local_files()
                return f"✅ Renamed: {file['name']} → {new_name}"
            except Exception as e:
                return f"❌ Rename failed: {e}"
        
        else:  # server
            if not self.connected:
                return "❌ Not connected"
            if not self.server_files:
                return "❌ No file selected"
            file = self.server_files[self.selected_server]
            
            new_name = self._input_dialog(stdscr, f"Rename '{file['name']}' to:", 
                                         default=file['name'])
            if not new_name or new_name == file['name']:
                return "Cancelled"
            
            if self.client.rename_file(file['name'], new_name):
                self._refresh_server_files()
                return f"✅ Renamed: {file['name']} → {new_name}"
            return "❌ Rename failed"
    
    def _action_show_history(self, stdscr) -> str:
        """Show full sent history."""
        history = self.sent_history.get_all()
        
        stdscr.nodelay(False)
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        
        stdscr.addstr(0, 0, "📤 Sent History (Full)", curses.A_BOLD)
        stdscr.addstr(1, 0, "=" * min(w - 1, 80))
        
        if not history:
            stdscr.addstr(3, 2, "(no history yet)")
        else:
            for i, entry in enumerate(history[:h-6]):
                status_icon = {
                    'sent': '✅', 'received': '📥', 'pending': '⏳',
                    'accepted': '✅', 'rejected': '❌', 'cancelled': '🚫'
                }.get(entry.get('status', ''), '?')
                
                line = f"{status_icon} {entry['filename'][:25]:<25} → {entry['sent_to'][:15]:<15} {entry['timestamp']}"
                try:
                    stdscr.addstr(3 + i, 2, line[:w-4])
                except curses.error:
                    pass
        
        stdscr.addstr(h - 2, 0, "Press any key to return...")
        stdscr.refresh()
        stdscr.getch()
        
        return "History closed"
    
    def _show_help(self, stdscr):
        """Show help screen."""
        stdscr.nodelay(False)
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        
        help_text = [
            "=== Julian File Browser - Help ===",
            "",
            "NAVIGATION:",
            "  j / Down    Move down",
            "  k / Up      Move up",
            "  Tab         Switch panels (Local/Server)",
            "",
            "FILE OPERATIONS:",
            "  u           Upload selected local file to server",
            "  d           Download selected server file to JulianFiles",
            "  s           Send file to another user",
            "  x           Delete selected file",
            "  r           Rename selected file",
            "  h           Show full sent history",
            "",
            "OTHER:",
            "  ?           Show this help",
            "  q / ESC     Quit browser",
            "",
            "FOLDERS:",
            f"  Local:   {self.local_folder}",
            f"  History: {Path.home() / CONFIG['client']['sent_history_folder']}",
            "",
            "Press any key to continue..."
        ]
        
        for i, line in enumerate(help_text):
            if i >= h - 2:
                break
            try:
                if i == 0:
                    stdscr.addstr(i, 2, line, curses.A_BOLD)
                else:
                    stdscr.addstr(i, 2, line)
            except curses.error:
                pass
        
        stdscr.refresh()
        stdscr.getch()


# ============================================================================
# INTERACTIVE REPL
# ============================================================================

class JulianREPL:
    """Interactive Read-Eval-Print Loop for Julian client."""
    
    def __init__(self):
        self.client = None
        self.connected = False
        self.server_ip = None
        self.server_port = None
        self.username = None
    
    def run(self):
        print("=" * 60)
        print("🌟 Julian Client v4.4.0 - Interactive Mode")
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
                elif cmd == 'send_to':
                    self._cmd_send_to(args)
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
                elif cmd == 'requests':
                    self._cmd_requests()
                elif cmd == 'accept':
                    self._cmd_accept(args)
                elif cmd == 'reject':
                    self._cmd_reject(args)
                elif cmd == 'cancel':
                    self._cmd_cancel(args)
                elif cmd == 'users':
                    self._cmd_users()
                elif cmd == 'stats':
                    self._cmd_stats()
                elif cmd == 'verify':
                    self._cmd_verify()
                elif cmd == 'info':
                    self._cmd_info()
                elif cmd == 'history':
                    self._cmd_history()
                elif cmd == 'browser':
                    self._cmd_browser()
                else:
                    print(f"❌ Unknown command: {cmd}")
                    print("💡 Type 'help' for available commands")
            except KeyboardInterrupt:
                print("\n\n⚠️  Use 'exit' to quit")
            except EOFError:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                logging.error(f"REPL error: {e}", exc_info=True)
                print(f"❌ Error")
    
    def _show_help(self):
        print("\n" + "=" * 60)
        print("📚 Available Commands")
        print("=" * 60)
        print("\n🔌 Connection:")
        print("  connect [code]      - Connect to saved server")
        print("  disconnect          - Disconnect from server")
        print("  verify              - Verify server identity")
        print("  info                - Show connection info")
        print("\n📁 File Operations:")
        print("  send <file>         - Upload file to server")
        print("  send_to <user> <file> - Send file to another user")
        print("  download <file>     - Download file")
        print("  list                - List server files")
        print("  search <pattern>    - Search files (*, ?)")
        print("  delete <file>       - Delete file")
        print("  rename <old> <new>  - Rename file")
        print("  resume              - List resumable downloads")
        print("\n📨 Transfer Requests:")
        print("  requests            - List pending requests")
        print("  accept <request_id> - Accept a request")
        print("  reject <request_id> - Reject a request")
        print("  cancel <request_id> - Cancel a request")
        print("\n👥 Social:")
        print("  users               - Show connected users")
        print("  stats               - Show your statistics")
        print("\n📊 History:")
        print("  history             - Show sent/received history")
        print("\n🎨 Interface:")
        print("  browser             - Launch TUI file browser")
        print("\n⚙️  Other:")
        print("  help                - Show this help")
        print("  exit                - Exit Julian")
        print("=" * 60)
    
    def _cmd_connect(self, args):
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
        if not self.connected:
            print("⚠️  Not connected")
            return
        self.client.close()
        self.client = None
        self.connected = False
        print("🔌 Disconnected")
    
    def _cmd_send(self, args):
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
    
    def _cmd_send_to(self, args):
        if not self._check_connected():
            return
        if len(args) < 2:
            print("❌ Usage: send_to <username> <filename>")
            return
        self.client.request_transfer(args[0], args[1])
    
    def _cmd_download(self, args):
        if not self._check_connected():
            return
        if not args:
            file_name = input("📄 File name: ").strip()
        else:
            file_name = args[0]
        self.client.download_file(file_name, resume=True)
    
    def _cmd_list(self):
        if not self._check_connected():
            return
        files = self.client.list_server_files()
        if not files:
            print("\n📭 No files on server")
            return
        print(f"\n📋 Server Files ({len(files)}):")
        print("=" * 60)
        for i, file in enumerate(files, 1):
            name = file.get('name', 'unknown')
            size = file.get('size', 0)
            print(f"  [{i}] 📄 {name} ({FileTransferUtils.format_size(size)})")
        print("=" * 60)
    
    def _cmd_search(self, args):
        if not self._check_connected():
            return
        if not args:
            pattern = input("🔍 Pattern: ").strip()
        else:
            pattern = ' '.join(args)
        self.client.search_files(pattern)
    
    def _cmd_delete(self, args):
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
        if not self._check_connected():
            return
        if len(args) >= 2:
            old_name, new_name = args[0], args[1]
        else:
            old_name = input("📝 Old name: ").strip()
            new_name = input("📝 New name: ").strip()
        self.client.rename_file(old_name, new_name)
    
    def _cmd_resume(self):
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
    
    def _cmd_requests(self):
        if not self._check_connected():
            return
        self.client.list_pending_requests()
    
    def _cmd_accept(self, args):
        if not self._check_connected():
            return
        if not args:
            print("❌ Usage: accept <request_id>")
            return
        self.client.accept_transfer(args[0])
    
    def _cmd_reject(self, args):
        if not self._check_connected():
            return
        if not args:
            print("❌ Usage: reject <request_id> [reason]")
            return
        request_id = args[0]
        reason = ' '.join(args[1:]) if len(args) > 1 else ""
        self.client.reject_transfer(request_id, reason)
    
    def _cmd_cancel(self, args):
        if not self._check_connected():
            return
        if not args:
            print("❌ Usage: cancel <request_id>")
            return
        self.client.cancel_transfer(args[0])
    
    def _cmd_users(self):
        if not self._check_connected():
            return
        self.client.get_users_list()
    
    def _cmd_stats(self):
        if not self._check_connected():
            return
        self.client.get_stats()
    
    def _cmd_verify(self):
        if not self._check_connected():
            return
        self.client.verify_server()
    
    def _cmd_info(self):
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
    
    def _cmd_history(self):
        """Show sent/received history."""
        history = self.client.sent_history.get_all() if self.client else SentHistoryManager().get_all()
        if not history:
            print("\n📭 No history yet")
            return
        print(f"\n📤 Sent/Received History ({len(history)} entries):")
        print("=" * 90)
        for i, entry in enumerate(history[:20], 1):
            status_icon = {
                'sent': '✅', 'received': '📥', 'pending': '⏳',
                'accepted': '✅', 'rejected': '❌', 'cancelled': '🚫'
            }.get(entry.get('status', ''), '?')
            print(f"  [{i:2d}] {status_icon} {entry['filename'][:25]:<25} → {entry['sent_to'][:15]:<15} "
                  f"{FileTransferUtils.format_size(entry['size']):>10}  {entry['timestamp']}")
        print("=" * 90)
    
    def _cmd_browser(self):
        """Launch the TUI file browser."""
        if not CURSES_AVAILABLE:
            print("❌ curses not available on this system")
            print("💡 On Windows, install with: pip install windows-curses")
            return
        
        print("🎨 Launching TUI file browser...")
        browser = JulianBrowser(self.client if self.connected else None)
        browser.start()
        print("\n🔙 Returned from browser")
    
    def _check_connected(self) -> bool:
        if not self.connected:
            print("⚠️  Not connected. Use 'connect' first.")
            return False
        return True


# ============================================================================
# CLI COMMANDS
# ============================================================================

def cmd_setup(args):
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
        cred_manager.save_pairing(server_ip, port, username, client.device_identity.get_fingerprint())
        print("\n✅ Setup complete!")
    client.close()


def cmd_connect(args):
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


def cmd_browser(args):
    """Launch TUI file browser directly."""
    if not CURSES_AVAILABLE:
        print("❌ curses not available on this system")
        print("💡 On Windows, install with: pip install windows-curses")
        sys.exit(1)
    
    client = None
    if args.auto_connect:
        cred_manager = CredentialManager()
        pairing = cred_manager.load_pairing()
        if pairing:
            print(f"🔗 Auto-connecting as '{pairing['username']}'...")
            code = input("🔑 Enter code from admin: ").strip()
            client = SecureClient(pairing['server_ip'], pairing['port'])
            if not client.connect_with_code(pairing['username'], code):
                print("❌ Connection failed. Launching in local-only mode.")
                client = None
            else:
                print("✅ Connected!")
        else:
            print("⚠️  No saved pairing. Launching in local-only mode.")
    
    browser = JulianBrowser(client)
    browser.start()
    
    if client:
        client.close()


def _require_code_and_connect(operation_name, operation_func):
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
    def do_send(client):
        client.send_file(args.file)
    _require_code_and_connect("send", do_send)


def cmd_send_to(args):
    def do_send_to(client):
        client.request_transfer(args.user, args.file)
    _require_code_and_connect("send_to", do_send_to)


def cmd_download(args):
    def do_download(client):
        client.download_file(args.file, resume=True)
    _require_code_and_connect("download", do_download)


def cmd_list(args):
    def do_list(client):
        files = client.list_server_files()
        if not files:
            print("\n📭 No files on server")
            return
        print(f"\n📋 Server Files ({len(files)}):")
        print("=" * 60)
        for i, file in enumerate(files, 1):
            name = file.get('name', 'unknown')
            size = file.get('size', 0)
            print(f"  [{i}] 📄 {name} ({FileTransferUtils.format_size(size)})")
        print("=" * 60)
    _require_code_and_connect("list", do_list)


def cmd_search(args):
    def do_search(client):
        client.search_files(args.pattern)
    _require_code_and_connect("search", do_search)


def cmd_delete(args):
    def do_delete(client):
        confirm = input(f"⚠️  Delete '{args.file}'? (y/n): ").strip().lower()
        if confirm in ['y', 'yes']:
            client.delete_file(args.file)
    _require_code_and_connect("delete", do_delete)


def cmd_rename(args):
    def do_rename(client):
        client.rename_file(args.old_name, args.new_name)
    _require_code_and_connect("rename", do_rename)


def cmd_resume():
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


def cmd_requests(args):
    def do_requests(client):
        client.list_pending_requests()
    _require_code_and_connect("requests", do_requests)


def cmd_accept(args):
    def do_accept(client):
        client.accept_transfer(args.request_id)
    _require_code_and_connect("accept", do_accept)


def cmd_reject(args):
    def do_reject(client):
        reason = ' '.join(args.reason) if args.reason else ""
        client.reject_transfer(args.request_id, reason)
    _require_code_and_connect("reject", do_reject)


def cmd_cancel(args):
    def do_cancel(client):
        client.cancel_transfer(args.request_id)
    _require_code_and_connect("cancel", do_cancel)


def cmd_users(args):
    def do_users(client):
        client.get_users_list()
    _require_code_and_connect("users", do_users)


def cmd_stats(args):
    def do_stats(client):
        client.get_stats()
    _require_code_and_connect("stats", do_stats)


def cmd_discover(args):
    discovery = ServiceDiscovery(timeout=args.timeout)
    servers = discovery.discover()
    if servers:
        print(f"\n✅ Found {len(servers)} Julian server(s):")
        for i, server in enumerate(servers, 1):
            tls_status = "🔐 TLS" if server['tls'] else "⚠️  No TLS"
            print(f"  [{i}] {server['ip']}:{server['port']} ({tls_status})")
    else:
        print("\n⚠️  No Julian servers found on the network.")


def cmd_history(args):
    """Show sent/received history."""
    history = SentHistoryManager().get_all()
    if not history:
        print("\n📭 No history yet")
        return
    print(f"\n📤 Sent/Received History ({len(history)} entries):")
    print("=" * 90)
    for i, entry in enumerate(history[:20], 1):
        status_icon = {
            'sent': '✅', 'received': '📥', 'pending': '⏳',
            'accepted': '✅', 'rejected': '❌', 'cancelled': '🚫'
        }.get(entry.get('status', ''), '?')
        print(f"  [{i:2d}] {status_icon} {entry['filename'][:25]:<25} → {entry['sent_to'][:15]:<15} "
              f"{FileTransferUtils.format_size(entry['size']):>10}  {entry['timestamp']}")
    print("=" * 90)


def cmd_reset(args):
    cred_manager = CredentialManager()
    cred_manager.clear_pairing()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    config_dir = Path.home() / CONFIG["client"]["config_dir"]
    config_dir.mkdir(parents=True, exist_ok=True)
    lock = LockFile(config_dir)
    if not lock.acquire():
        print("❌ Another Julian client is already running.")
        print("💡 Close the other instance or delete ~/.julian/client.lock")
        sys.exit(1)
    try:
        if len(sys.argv) == 1:
            repl = JulianREPL()
            repl.run()
            return
        parser = argparse.ArgumentParser(
            description="Julian Client - Secure File Transfer",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  ju_client                              Launch interactive mode (REPL)
  ju_client setup                        First-time pairing
  ju_client setup --discover             Auto-discover servers
  ju_client connect                      Connect with code
  ju_client browser                      Launch TUI file browser
  ju_client browser --auto-connect       Browser with auto-connect
  ju_client send <file>                  Upload file
  ju_client send_to <user> <file>        Send file to user
  ju_client download <file>              Download file
  ju_client list                         List server files
  ju_client search <pattern>             Search files
  ju_client delete <file>                Delete file
  ju_client rename <old> <new>           Rename file
  ju_client requests                     List pending requests
  ju_client accept <request_id>          Accept request
  ju_client reject <request_id> [reason] Reject request
  ju_client cancel <request_id>          Cancel request
  ju_client users                        Show connected users
  ju_client stats                        Show statistics
  ju_client history                      Show sent/received history
  ju_client discover                     Discover servers
  ju_client resume                       List resumable downloads
  ju_client reset                        Clear pairing
            """
        )
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        setup_parser = subparsers.add_parser('setup', help='First-time pairing')
        setup_parser.add_argument('--discover', action='store_true')
        
        subparsers.add_parser('connect', help='Connect with code')
        
        browser_parser = subparsers.add_parser('browser', help='Launch TUI file browser')
        browser_parser.add_argument('--auto-connect', action='store_true',
                                    help='Auto-connect using saved pairing')
        
        send_parser = subparsers.add_parser('send', help='Upload file')
        send_parser.add_argument('file')
        
        send_to_parser = subparsers.add_parser('send_to', help='Send file to user')
        send_to_parser.add_argument('user')
        send_to_parser.add_argument('file')
        
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
        
        subparsers.add_parser('requests', help='List pending requests')
        
        accept_parser = subparsers.add_parser('accept', help='Accept request')
        accept_parser.add_argument('request_id')
        
        reject_parser = subparsers.add_parser('reject', help='Reject request')
        reject_parser.add_argument('request_id')
        reject_parser.add_argument('reason', nargs='*', default=[])
        
        cancel_parser = subparsers.add_parser('cancel', help='Cancel request')
        cancel_parser.add_argument('request_id')
        
        subparsers.add_parser('resume', help='List resumable downloads')
        subparsers.add_parser('users', help='Show users')
        subparsers.add_parser('stats', help='Show statistics')
        subparsers.add_parser('history', help='Show sent/received history')
        
        discover_parser = subparsers.add_parser('discover', help='Discover servers')
        discover_parser.add_argument('--timeout', type=int, default=5)
        
        subparsers.add_parser('reset', help='Clear pairing')
        
        args = parser.parse_args()
        
        if args.command == 'setup':
            cmd_setup(args)
        elif args.command == 'connect':
            cmd_connect(args)
        elif args.command == 'browser':
            cmd_browser(args)
        elif args.command == 'send':
            cmd_send(args)
        elif args.command == 'send_to':
            cmd_send_to(args)
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
        elif args.command == 'requests':
            cmd_requests(args)
        elif args.command == 'accept':
            cmd_accept(args)
        elif args.command == 'reject':
            cmd_reject(args)
        elif args.command == 'cancel':
            cmd_cancel(args)
        elif args.command == 'resume':
            cmd_resume()
        elif args.command == 'users':
            cmd_users(args)
        elif args.command == 'stats':
            cmd_stats(args)
        elif args.command == 'history':
            cmd_history(args)
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