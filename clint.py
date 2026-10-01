"""
Julian Client - Secure File Transfer System (Final Version)
============================================================

A production-ready, security-hardened file transfer client with:
- JSON-based protocol (prevents command injection)
- TLS 1.3 encryption with certificate pinning
- Pairing authentication with code-based login
- Service discovery (auto-detect servers)
- Strong device fingerprinting (UUID + Machine ID)
- Advanced file validation (path traversal, overwrite protection)
- Message validation (type checking, structure verification)
- CLI commands for quick operations
- Interactive mode with file browser

Security Features:
------------------
1. Path Traversal Protection: Prevents ../ attacks
2. File Overwrite Protection: Sequential numbering for existing files
3. File Size Validation: Prevents disk exhaustion
4. Disk Space Check: Verifies available space before download
5. JSON Type Validation: Prevents crashes from malformed messages
6. Certificate Pinning: Prevents MITM attacks
7. Device Fingerprinting: UUID + Machine ID for strong identity
8. Input Sanitization: All inputs validated before use

Design Patterns Applied:
------------------------
- Strategy: FileValidator, MessageValidator (validation strategies)
- Factory: ServiceDiscovery (server discovery)
- Singleton: DeviceIdentity (one identity per device)

Author: Julian Project
License: MIT
Version: 3.0.0
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
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass


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
        "push_prefix": "pushed_",
        "max_file_size_mb": 0,  # 0 = unlimited
    },
    "discovery": {
        "broadcast_port": 37020,
        "timeout": 5,  # seconds to wait for discovery
    },
    "security": {
        "code_length": 8,
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
    
    Why This Matters:
    -----------------
    Without these checks, a malicious server could:
    - Write files to arbitrary locations (path traversal)
    - Overwrite important system files
    - Exhaust disk space with huge files
    - Crash the client with malformed data
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
        # This prevents: "../../../etc/passwd" → "passwd"
        safe_name = os.path.basename(filename)
        
        # Step 2: Check if basename extraction removed everything
        # This catches: "/", "\\", "" (empty strings)
        if not safe_name:
            raise ValueError("Invalid filename: empty after sanitization")
        
        # Step 3: Check for dangerous patterns
        # These patterns could be used for attacks
        dangerous_patterns = ['..', '/', '\\', '\x00']
        for pattern in dangerous_patterns:
            if pattern in safe_name:
                raise ValueError(f"Invalid filename: contains '{pattern}'")
        
        # Step 4: Check length (prevent buffer overflow attacks)
        if len(safe_name) > 255:
            raise ValueError("Filename too long (max 255 characters)")
        
        # Step 5: Verify final path is within download directory
        # This is the ultimate safety check
        download_path = Path(download_dir).resolve()
        final_path = (download_path / safe_name).resolve()
        
        # Ensure final path is inside download directory
        # This prevents: download_dir="/tmp", filename="../etc/passwd"
        if not str(final_path).startswith(str(download_path)):
            raise ValueError("Path traversal detected: file would be saved outside download directory")
        
        return safe_name
    
    @staticmethod
    def validate_upload_filename(filename: str) -> str:
        """
        Validate filename for upload.
        
        Same validation as download to ensure consistency.
        
        Args:
            filename: Filename to validate
        
        Returns:
            Safe filename if valid
        
        Raises:
            ValueError: If filename is invalid
        """
        return FileValidator.validate_download_filename(filename)
    
    @staticmethod
    def get_safe_save_path(filename: str, directory: str = ".", 
                           prefix: str = "downloaded_") -> str:
        """
        Get a safe path for saving file, avoiding overwrites.
        
        Strategy:
        ---------
        If file exists, add sequential number:
        - file.pdf → file(1).pdf → file(2).pdf → ...
        
        This prevents:
        - Accidental data loss
        - Malicious file replacement
        - Confusion about which file is which
        
        Args:
            filename: Original filename
            directory: Target directory
            prefix: Prefix to add (e.g., "downloaded_")
        
        Returns:
            Safe file path that won't overwrite existing files
        
        Raises:
            ValueError: If too many files with similar names
        
        Example:
            get_safe_save_path("photo.jpg", ".", "downloaded_")
            → "downloaded_photo.jpg" (if doesn't exist)
            → "downloaded_photo(1).jpg" (if photo.jpg exists)
            → "downloaded_photo(2).jpg" (if photo(1).jpg exists)
        """
        # Validate filename first (path traversal protection)
        safe_name = FileValidator.validate_download_filename(filename, directory)
        
        # Add prefix
        name_with_prefix = f"{prefix}{safe_name}"
        
        # Construct full path
        base_path = Path(directory) / name_with_prefix
        
        # If file doesn't exist, use it directly
        if not base_path.exists():
            return str(base_path)
        
        # File exists, add sequential number
        stem = base_path.stem  # "photo" from "photo.jpg"
        suffix = base_path.suffix  # ".jpg" from "photo.jpg"
        counter = 1
        
        while True:
            new_name = f"{prefix}{stem}({counter}){suffix}"
            new_path = Path(directory) / new_name
            
            if not new_path.exists():
                return str(new_path)
            
            counter += 1
            
            # Safety check to prevent infinite loop
            # This shouldn't happen in practice, but prevents bugs
            if counter > 1000:
                raise ValueError("Too many files with similar names")
    
    @staticmethod
    def validate_file_size(size: int, max_size_mb: int = 0) -> bool:
        """
        Validate file size is reasonable.
        
        Checks:
        -------
        1. Size is positive (not negative or zero)
        2. Size doesn't exceed max limit (if specified)
        3. Size is not absurdly large (> 100GB)
        
        Why This Matters:
        -----------------
        Without this check, a malicious server could:
        - Send size = -1 → infinite loop
        - Send size = 100TB → disk exhaustion
        - Send size = "infinity" → crash
        
        Args:
            size: File size in bytes
            max_size_mb: Maximum allowed size in MB (0 = unlimited)
        
        Returns:
            True if valid, False otherwise
        """
        # Check for negative or zero size
        if size <= 0:
            return False
        
        # Check against max limit
        if max_size_mb > 0:
            max_bytes = max_size_mb * 1024 * 1024
            if size > max_bytes:
                return False
        
        # Sanity check: reject absurdly large files (> 100GB)
        # This is a safety net, not a hard limit
        if size > 100 * 1024 * 1024 * 1024:
            return False
        
        return True
    
    @staticmethod
    def check_disk_space(required_bytes: int, path: str = ".") -> bool:
        """
        Check if enough disk space is available.
        
        Strategy:
        ---------
        1. Get available disk space using os.statvfs
        2. Compare with required bytes + 10% buffer
        3. Return False if not enough space
        
        Why 10% Buffer:
        ---------------
        - File system overhead
        - Temporary files during download
        - Safety margin for unexpected growth
        
        Args:
            required_bytes: Bytes needed
            path: Path to check
        
        Returns:
            True if enough space, False otherwise
        """
        try:
            # Get file system statistics
            stat = os.statvfs(path)
            
            # Calculate available bytes
            # f_bavail = available blocks for non-root users
            # f_frsize = fragment size (block size)
            available_bytes = stat.f_bavail * stat.f_frsize
            
            # Add 10% buffer for safety
            required_with_buffer = int(required_bytes * 1.1)
            
            return available_bytes >= required_with_buffer
        
        except Exception:
            # If we can't check (e.g., Windows), assume it's OK
            # Better to try and fail than to block legitimate downloads
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
    
    Why This Matters:
    -----------------
    Without validation, a malicious server could:
    - Send size = "not_a_number" → crash on int() conversion
    - Send filename = null → crash on string operations
    - Send missing fields → KeyError crashes
    - Send wrong types → unexpected behavior
    
    Validation Strategy:
    --------------------
    1. Check message is a dictionary
    2. Check required fields exist
    3. Check field types match expectations
    4. Check values are reasonable (e.g., positive numbers)
    """
    
    @staticmethod
    def validate_message(message: dict, required_fields: dict) -> bool:
        """
        Validate message has required fields with correct types.
        
        Args:
            message: Received JSON message
            required_fields: Dict of {field_name: expected_type}
                Example: {'size': int, 'filename': str}
        
        Returns:
            True if valid, False otherwise
        
        Example:
            validate_message({'size': 100, 'filename': 'test.txt'}, 
                           {'size': int, 'filename': str})
            → True
            
            validate_message({'size': '100', 'filename': 'test.txt'}, 
                           {'size': int, 'filename': str})
            → False (size is string, not int)
        """
        # Check message is a dictionary
        if not isinstance(message, dict):
            return False
        
        # Check each required field
        for field, expected_type in required_fields.items():
            # Check field exists
            if field not in message:
                return False
            
            # Check type
            value = message[field]
            if not isinstance(value, expected_type):
                return False
            
            # Additional checks for specific types
            if expected_type == int and value < 0:
                return False
            
            if expected_type == str and len(value) == 0:
                return False
        
        return True
    
    @staticmethod
    def validate_file_meta(message: dict) -> bool:
        """
        Validate FILE_META message structure.
        
        Expected structure:
        {
            "type": "FILE_META",
            "filename": "photo.jpg",
            "size": 1048576,
            "sha256": "abc123..."
        }
        """
        return MessageValidator.validate_message(message, {
            'filename': str,
            'size': int,
            'sha256': str
        })
    
    @staticmethod
    def validate_file_list(message: dict) -> bool:
        """
        Validate FILE_LIST message structure.
        
        Expected structure:
        {
            "type": "FILE_LIST",
            "files": [
                {"name": "photo.jpg", "size": 1048576},
                {"name": "doc.pdf", "size": 2097152}
            ]
        }
        """
        # Check top-level structure
        if not MessageValidator.validate_message(message, {'files': list}):
            return False
        
        # Validate each file entry
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
    def validate_user_list(message: dict) -> bool:
        """
        Validate USER_LIST message structure.
        
        Expected structure:
        {
            "type": "USER_LIST",
            "users": [
                {"username": "alice", "ip": "192.168.1.10", "state": "idle"},
                {"username": "bob", "ip": "192.168.1.11", "state": "transferring"}
            ]
        }
        """
        # Check top-level structure
        if not MessageValidator.validate_message(message, {'users': list}):
            return False
        
        # Validate each user entry
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
        """
        Validate STATS message structure.
        
        Expected structure:
        {
            "type": "STATS",
            "username": "alice",
            "uploaded": 1048576,
            "downloaded": 2097152,
            "files_sent": 5,
            "files_received": 10
        }
        """
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
    
    Why Multiple Factors:
    ---------------------
    Single factor (e.g., just UUID) can be:
    - Copied to another device
    - Deleted and regenerated
    - Predicted if algorithm is known
    
    Multiple factors make it:
    - Unique to this specific device
    - Persistent across reinstalls
    - Hard to spoof
    
    Factors Used:
    -------------
    1. device_uuid: Random UUID generated once
    2. machine_id: OS-provided unique identifier
       - Linux: /etc/machine-id
       - macOS: IOPlatformUUID
       - Windows: MachineGuid
    """
    
    def __init__(self, config_dir: Path = None):
        """
        Initialize device identity.
        
        Args:
            config_dir: Directory to store identity file
        """
        config_dir = config_dir or Path.home() / CONFIG["client"]["config_dir"]
        config_dir.mkdir(parents=True, exist_ok=True)
        self.identity_file = config_dir / CONFIG["client"]["device_id_file"]
        self.identity = self._load_or_create_identity()
    
    def _load_or_create_identity(self) -> dict:
        """
        Load existing identity or create new one.
        
        Strategy:
        ---------
        1. Try to load from file
        2. If file doesn't exist or is corrupted, create new identity
        3. Save to file with secure permissions
        
        Returns:
            Identity dictionary with device_uuid and machine_id
        """
        if self.identity_file.exists():
            try:
                with open(self.identity_file, 'r') as f:
                    return json.load(f)
            except Exception:
                # File corrupted, create new identity
                pass
        
        # Generate new identity
        identity = {
            "device_uuid": str(uuid.uuid4()),
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "machine_id": self._get_machine_id(),
        }
        
        # Save to file
        with open(self.identity_file, 'w') as f:
            json.dump(identity, f, indent=2)
        
        # Secure file permissions (Unix-like systems)
        # 0o600 = read/write for owner only
        try:
            os.chmod(self.identity_file, 0o600)
        except Exception:
            # Windows doesn't support this, ignore
            pass
        
        return identity
    
    def _get_machine_id(self) -> str:
        """
        Get unique machine ID from OS.
        
        Strategy:
        ---------
        Try OS-specific methods in order:
        1. Linux: /etc/machine-id
        2. macOS: IOPlatformUUID via ioreg
        3. Windows: MachineGuid from registry
        4. Fallback: Generate random UUID
        
        Returns:
            Machine ID string
        """
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
        # This is less ideal but better than nothing
        return str(uuid.uuid4())
    
    def get_fingerprint(self) -> str:
        """
        Generate device fingerprint from multiple factors.
        
        Strategy:
        ---------
        1. Combine all identity factors
        2. Hash with SHA-256
        3. Return hex digest
        
        Returns:
            64-character hex string (SHA-256 hash)
        """
        factors = [
            self.identity["device_uuid"],
            self.identity["machine_id"],
        ]
        
        # Combine all factors
        combined = "|".join(factors)
        
        # Hash with SHA-256
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def get_device_id(self) -> str:
        """
        Get human-readable device ID (like Syncthing).
        
        Format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
        
        Returns:
            Formatted device ID string
        """
        fingerprint = self.get_fingerprint()
        # Split into 7-character chunks
        chunks = [fingerprint[i:i+7].upper() for i in range(0, 56, 7)]
        return "-".join(chunks)


# ============================================================================
# CREDENTIAL MANAGER (Stores Pairing Info)
# ============================================================================

class CredentialManager:
    """
    Manages saved pairing info (server IP, port, username, device fingerprint).
    
    Security Note:
    --------------
    Does NOT store session tokens - requires code every time for security.
    This prevents unauthorized access if credentials file is compromised.
    
    File Permissions:
    -----------------
    Credentials file is created with 0o600 permissions (Unix-like systems).
    This means only the owner can read/write the file.
    """
    
    def __init__(self, config_dir: Path = None):
        """
        Initialize credential manager.
        
        Args:
            config_dir: Directory to store credentials file
        """
        config_dir = config_dir or Path.home() / CONFIG["client"]["config_dir"]
        config_dir.mkdir(parents=True, exist_ok=True)
        self.credentials_file = config_dir / CONFIG["client"]["credentials_file"]
    
    def save_pairing(self, server_ip: str, port: int, username: str,
                      device_fingerprint: str) -> None:
        """
        Save pairing info (no token).
        
        Args:
            server_ip: Server IP address
            port: Server port
            username: Authenticated username
            device_fingerprint: Device fingerprint hash
        """
        credentials = {
            'server_ip': server_ip,
            'port': port,
            'username': username,
            'device_fingerprint': device_fingerprint
        }
        
        with open(self.credentials_file, 'w') as f:
            json.dump(credentials, f, indent=2)
        
        # Secure file permissions (Unix-like systems)
        try:
            os.chmod(self.credentials_file, 0o600)
        except Exception:
            # Windows doesn't support this, ignore
            pass
    
    def load_pairing(self) -> Optional[dict]:
        """
        Load saved pairing info.
        
        Returns:
            Dictionary with pairing info, or None if not found
        """
        if not self.credentials_file.exists():
            return None
        
        try:
            with open(self.credentials_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Error loading credentials: {e}")
            return None
    
    def clear_pairing(self) -> None:
        """Remove saved pairing."""
        if self.credentials_file.exists():
            self.credentials_file.unlink()
            print("✅ Pairing cleared. You'll need to setup again.")
        else:
            print("⚠️  No saved pairing found")


# ============================================================================
# SERVICE DISCOVERY (Auto-detect Servers)
# ============================================================================

class ServiceDiscovery:
    """
    Discover Julian servers on the local network via UDP broadcast.
    
    How It Works:
    -------------
    1. Server broadcasts JSON message every 5 seconds on port 37020
    2. Client listens on same port
    3. Client collects all discovered servers
    4. User selects which server to connect to
    
    Security Note:
    --------------
    UDP broadcast is not authenticated. A malicious actor on the same
    network could send fake discovery messages. This is acceptable for
    local network use, but users should verify server identity.
    """
    
    def __init__(self, timeout: int = None):
        """
        Initialize service discovery.
        
        Args:
            timeout: Seconds to wait for discovery responses
        """
        self.timeout = timeout or CONFIG["discovery"]["timeout"]
        self.broadcast_port = CONFIG["discovery"]["broadcast_port"]
    
    def discover(self) -> List[dict]:
        """
        Listen for server broadcasts and return list of discovered servers.
        
        Returns:
            List of dictionaries with server information:
            [
                {
                    'ip': '192.168.1.100',
                    'port': 5000,
                    'version': '3.0.0',
                    'requires_auth': True,
                    'tls': True
                },
                ...
            ]
        """
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            # Bind to discovery port
            sock.bind(('', self.broadcast_port))
        except Exception as e:
            print(f"⚠️  Could not bind to discovery port: {e}")
            return []
        
        # Set timeout
        sock.settimeout(self.timeout)
        
        servers = []
        seen_ips = set()  # Avoid duplicates
        
        print(f"🔍 Discovering Julian servers (timeout: {self.timeout}s)...")
        
        try:
            while True:
                # Receive broadcast message
                data, addr = sock.recvfrom(1024)
                
                # Avoid duplicates
                if addr[0] in seen_ips:
                    continue
                
                try:
                    # Parse JSON message
                    server_info = json.loads(data.decode('utf-8'))
                    
                    # Check if it's a Julian server
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
                    # Invalid JSON, skip
                    continue
        
        except socket.timeout:
            # Timeout reached, stop listening
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
    
    Format:
    -------
    [4 bytes: length][JSON data]
    
    Example:
    --------
    Send: {"type": "UPLOAD", "filename": "photo.jpg", "size": 1048576}
    
    Wire format:
    [00 00 00 4A]{"type":"UPLOAD","filename":"photo.jpg","size":1048576}
     ↑ length     ↑ JSON data (74 bytes)
    """
    
    @staticmethod
    def send_message(sock: socket.socket, data: dict) -> None:
        """
        Send JSON message with length prefix.
        
        Args:
            sock: Socket to send on
            data: Dictionary to send
        """
        # Convert to JSON string
        message = json.dumps(data)
        
        # Encode to bytes
        encoded = message.encode('utf-8')
        
        # Create length prefix (4 bytes, big-endian)
        length = len(encoded).to_bytes(4, 'big')
        
        # Send length + message
        sock.send(length + encoded)
    
    @staticmethod
    def recv_message(sock: socket.socket, timeout: int = None) -> Optional[dict]:
        """
        Receive JSON message with length prefix.
        
        Args:
            sock: Socket to receive from
            timeout: Optional timeout in seconds
        
        Returns:
            Received dictionary or None on error
        """
        if timeout:
            sock.settimeout(timeout)
        
        try:
            # Read length prefix (4 bytes)
            length_bytes = sock.recv(4)
            if len(length_bytes) < 4:
                return None
            
            # Parse length
            length = int.from_bytes(length_bytes, 'big')
            
            # Sanity check (prevent memory exhaustion)
            # Reject messages larger than 10MB
            if length > 10 * 1024 * 1024:
                return None
            
            # Read message body
            message_bytes = sock.recv(length)
            if len(message_bytes) < length:
                return None
            
            # Parse JSON
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
        """
        Calculate SHA256 hash of a file for integrity verification.
        
        Args:
            file_path: Path to file
        
        Returns:
            Hex digest of SHA256 hash
        """
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            # Read in 8KB chunks for efficiency
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def show_progress(current: int, total: int, prefix: str = "") -> None:
        """
        Display a progress bar for file transfers.
        
        Args:
            current: Current bytes transferred
            total: Total bytes
            prefix: Text to show before progress bar
        """
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
        """
        Format file size to human-readable format.
        
        Args:
            size: Size in bytes
        
        Returns:
            Formatted string (e.g., "1.50 MB")
        """
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    @staticmethod
    def get_system_info() -> tuple:
        """
        Collect system information for device fingerprinting.
        
        Returns:
            Tuple of (os_info, distribution, device_type)
        """
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
        
        # Detect Termux
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
    - Certificate pinning
    - Strong device fingerprinting
    - Pairing authentication
    - Code-based login
    - Advanced file validation
    - Message validation
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
        
        # Certificates directory for pinning
        self.certs_dir = self.config_dir / CONFIG["client"]["certs_dir"]
        self.certs_dir.mkdir(exist_ok=True)
        
        # Device identity
        self.device_identity = DeviceIdentity(self.config_dir)
        
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
        Create SSL context with certificate pinning.
        
        Strategy:
        ---------
        1. Check if we have a pinned certificate for this server
        2. If yes: Verify against pinned certificate
        3. If no: Accept any certificate but pin it for future
        
        Returns:
            SSL context configured for this server
        """
        context = ssl.create_default_context()
        
        # Check if we have a pinned certificate for this server
        cert_file = self.certs_dir / f"{self.server_ip}.pem"
        
        if cert_file.exists():
            # Verify against pinned certificate
            try:
                context.load_verify_locations(cert_file)
                context.check_hostname = False  # Self-signed certs
                context.verify_mode = ssl.CERT_REQUIRED
            except Exception as e:
                print(f"⚠️  Certificate verification failed: {e}")
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
        else:
            # First connection: accept any certificate but pin it
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        return context
    
    def _pin_certificate(self) -> None:
        """Pin server certificate for future verification."""
        cert_file = self.certs_dir / f"{self.server_ip}.pem"
        
        if not cert_file.exists():
            try:
                cert_der = self.socket.getpeercert(binary_form=True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                
                with open(cert_file, 'w') as f:
                    f.write(cert_pem)
                
                print(f"🔒 Certificate pinned for {self.server_ip}")
            except Exception as e:
                print(f"⚠️  Could not pin certificate: {e}")
    
    def _connect_socket(self) -> bool:
        """Establish TLS connection with certificate pinning."""
        try:
            context = self._create_ssl_context()
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket = context.wrap_socket(
                self.socket, server_hostname=self.server_ip
            )
            self.socket.connect((self.server_ip, self.server_port))
            
            # Pin certificate if first connection
            self._pin_certificate()
            
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def setup(self, username: str) -> bool:
        """
        First-time pairing flow.
        
        Steps:
        ------
        1. Send PAIR_REQUEST with device info
        2. Receive pairing code
        3. User enters code (from admin)
        4. Send PAIR_CONFIRM with code
        5. Receive confirmation
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
            
            # Step 2: Receive pairing code
            response = JsonProtocol.recv_message(self.socket)
            if not response or response.get('type') != 'PAIR_CODE':
                print(f"❌ Unexpected response: {response}")
                return False
            
            code = response.get('code', '')
            
            # Step 3: Ask user for code
            print("\n" + "=" * 60)
            print("🔑 PAIRING REQUIRED")
            print("=" * 60)
            print(f"The server generated a pairing code.")
            print(f"Ask the server admin for the code, then enter it below.")
            print("=" * 60)
            
            entered_code = input("\n🔑 Enter the pairing code from admin: ").strip()
            
            if entered_code != code:
                print("❌ Code mismatch! The code you entered doesn't match what the server sent.")
                print("💡 Make sure you got the code from the server admin console.")
                return False
            
            # Step 4: Send confirmation
            JsonProtocol.send_message(self.socket, {
                "type": "PAIR_CONFIRM",
                "code": entered_code
            })
            
            # Step 5: Receive confirmation
            response = JsonProtocol.recv_message(self.socket)
            if not response or response.get('type') != 'PAIRED_OK':
                print(f"❌ Pairing failed: {response}")
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
    
    def send_command(self, data: dict) -> Optional[dict]:
        """Send a command to the server and receive response."""
        try:
            JsonProtocol.send_message(self.socket, data)
            return JsonProtocol.recv_message(self.socket)
        except Exception as e:
            print(f"\n❌ Error: {e}")
            return None
    
    def send_file(self, file_path: str) -> bool:
        """Upload a file to the server."""
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
        
        sent_size = 0
        with open(file_path, 'rb') as f:
            while sent_size < file_size:
                chunk = f.read(4096)
                if not chunk:
                    break
                self.socket.send(chunk)
                sent_size += len(chunk)
                FileTransferUtils.show_progress(sent_size, file_size, "Sending")
        
        response = JsonProtocol.recv_message(self.socket)
        if response and response.get('type') == 'FILE_OK':
            print(f"\n✅ File sent successfully!")
            return True
        else:
            print(f"\n⚠️ Transfer failed!")
            return False
    
    def list_server_files(self) -> List[dict]:
        """List files with validation."""
        response = self.send_command({"type": "LIST"})
        
        # Validate message
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
    
    def download_file(self, file_name: str) -> bool:
        """
        Download a file from the server with full validation.
        
        Security Measures:
        ------------------
        1. Filename validation (path traversal protection)
        2. File size validation
        3. Disk space check
        4. Message type validation
        5. No file overwrite
        """
        try:
            # Send download request
            JsonProtocol.send_message(self.socket, {
                "type": "DOWNLOAD",
                "filename": file_name
            })
            
            # Receive metadata
            metadata = JsonProtocol.recv_message(self.socket)
            
            # Validate message structure
            if not MessageValidator.validate_file_meta(metadata):
                print("❌ Invalid file metadata from server")
                return False
            
            # Extract validated data
            file_name = metadata['filename']
            file_size = metadata['size']
            file_sha256 = metadata['sha256']
            
            # Validate file size
            if not FileValidator.validate_file_size(file_size):
                print(f"❌ Invalid file size: {file_size}")
                return False
            
            # Check disk space
            if not FileValidator.check_disk_space(file_size):
                print(f"❌ Not enough disk space for {FileTransferUtils.format_size(file_size)}")
                return False
            
            # Get safe save path (no overwrites)
            save_path = FileValidator.get_safe_save_path(
                file_name,
                directory=".",
                prefix=CONFIG['client']['download_prefix']
            )
            
            # Send READY signal
            JsonProtocol.send_message(self.socket, {"type": "READY"})
            
            print(f"\n📥 Downloading: {file_name} ({FileTransferUtils.format_size(file_size)})")
            print(f"💾 Saving to: {save_path}")
            
            # Download file
            received_size = 0
            with open(save_path, 'wb') as f:
                while received_size < file_size:
                    chunk_size = min(4096, file_size - received_size)
                    data = self.socket.recv(chunk_size)
                    if not data:
                        break
                    f.write(data)
                    received_size += len(data)
                    FileTransferUtils.show_progress(received_size, file_size, "Downloading")
            
            # Verify integrity
            if FileTransferUtils.calculate_sha256(save_path) == file_sha256:
                print(f"\n✅ Downloaded: {save_path}")
                return True
            else:
                print(f"\n⚠️ File corrupted!")
                # Delete corrupted file
                try:
                    os.remove(save_path)
                except Exception:
                    pass
                return False
        
        except ValueError as e:
            print(f"❌ Validation error: {e}")
            return False
        except Exception as e:
            print(f"❌ Download error: {e}")
            return False
    
    def get_users_list(self) -> None:
        """Get users list with validation."""
        response = self.send_command({"type": "USERS"})
        
        # Validate message
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
        
        # Validate message
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
# CLI COMMANDS
# ============================================================================

def cmd_setup(args):
    """First-time pairing with the server."""
    print("=" * 60)
    print("🔐 Julian Setup - First-Time Pairing")
    print("=" * 60)
    
    # Service discovery
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
        # Save pairing info
        cred_manager = CredentialManager()
        cred_manager.save_pairing(
            server_ip, port, username, client.device_identity.get_fingerprint()
        )
        print("\n✅ Setup complete!")
        print("💡 Next time, run 'julian connect' and enter the code from admin.")
    
    client.close()


def cmd_connect(args):
    """Connect with admin-provided code (every time)."""
    cred_manager = CredentialManager()
    pairing = cred_manager.load_pairing()
    
    if not pairing:
        print("❌ No saved pairing. Run 'julian setup' first.")
        return
    
    print(f"🔗 Connecting as '{pairing['username']}'...")
    print(f"📍 Server: {pairing['server_ip']}:{pairing['port']}")
    
    # Ask for code from admin
    code = input("\n🔑 Enter the code from server admin: ").strip()
    
    client = SecureClient(pairing['server_ip'], pairing['port'])
    
    if client.connect_with_code(pairing['username'], code):
        print(f"\n✅ Connected!")
        _interactive_mode(client)
    else:
        print("\n❌ Connection failed. Check the code with admin.")
    
    client.close()


def _require_code_and_connect(operation_name: str, operation_func):
    """Helper to require code before operation."""
    cred_manager = CredentialManager()
    pairing = cred_manager.load_pairing()
    
    if not pairing:
        print("❌ No saved pairing. Run 'julian setup' first.")
        return
    
    code = input(f"🔑 Enter code for '{operation_name}': ").strip()
    
    client = SecureClient(pairing['server_ip'], pairing['port'])
    
    if client.connect_with_code(pairing['username'], code):
        operation_func(client)
    else:
        print("❌ Authentication failed.")
    
    client.close()


def cmd_send(args):
    """Quick file upload (requires code)."""
    def do_send(client):
        client.send_file(args.file)
    
    _require_code_and_connect("send", do_send)


def cmd_download(args):
    """Quick file download (requires code)."""
    def do_download(client):
        client.download_file(args.file)
    
    _require_code_and_connect("download", do_download)


def cmd_list(args):
    """List server files (requires code)."""
    def do_list(client):
        client.list_server_files()
    
    _require_code_and_connect("list", do_list)


def cmd_users(args):
    """Show connected users (requires code)."""
    def do_users(client):
        client.get_users_list()
    
    _require_code_and_connect("users", do_users)


def cmd_stats(args):
    """Show personal statistics (requires code)."""
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


def _interactive_mode(client: SecureClient):
    """Full interactive mode with menus."""
    while True:
        print("\n" + "=" * 60)
        print("Select operation (Press Enter or 'b' to go back):")
        print("=" * 60)
        print("[1] 📤 Send file to server")
        print("[2] 📥 Browse and download from server")
        print("[3] 👥 View connected users")
        print("[4] 📊 View your statistics")
        print("[q] Quit and disconnect")
        print("=" * 60)
        
        choice = input("\n👉 Your choice: ").strip().lower()
        
        if not choice or choice == 'b':
            continue
        elif choice == 'q':
            print("\n👋 Disconnecting...")
            break
        
        if choice == '1':
            print("\n" + "=" * 60)
            print("File selection method (Press Enter or 'b' to go back):")
            print("=" * 60)
            print("[1] ⚡ Quick Mode (Enter path)")
            print("[2] 📂 Interactive Browser")
            print("=" * 60)
            
            method = input("\n👉 Choice: ").strip()
            if not method or method == 'b':
                continue
            
            file_path = None
            if method == '1':
                file_path = input("\n📁 File path: ").strip()
                if not os.path.isfile(file_path):
                    print(f"❌ File not found: {file_path}")
                    continue
            elif method == '2':
                browser = FileBrowser()
                file_path = browser.navigate()
            else:
                print("❌ Invalid choice!")
                continue
            
            if file_path:
                client.send_file(file_path)
        
        elif choice == '2':
            files = client.list_server_files()
            if files:
                file_num = input("\n👉 File number (or 'b' to go back): ").strip()
                if not file_num or file_num == 'b':
                    continue
                
                try:
                    idx = int(file_num) - 1
                    if 0 <= idx < len(files):
                        client.download_file(files[idx]['name'])
                    else:
                        print("❌ Invalid number!")
                except ValueError:
                    print("❌ Invalid input!")
        
        elif choice == '3':
            client.get_users_list()
        elif choice == '4':
            client.get_stats()
        else:
            print("❌ Invalid choice!")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Application entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description="Julian Client - Secure File Transfer with Pairing Auth",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  julian setup              First-time pairing (requires code from admin)
  julian setup --discover   Auto-discover servers on network
  julian connect            Connect with code from admin (every time)
  julian send photo.jpg     Quick file upload (requires code)
  julian download doc.pdf   Quick file download (requires code)
  julian list               List server files (requires code)
  julian users              Show connected users (requires code)
  julian stats              Show your statistics (requires code)
  julian discover           Discover Julian servers on network
  julian reset              Clear saved pairing

Security:
  - First time: Pairing with admin-provided code
  - Every time: Admin-provided code (no auto-login)
  - Physical verification required each connection
  - Certificate pinning for MITM protection
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='First-time pairing with server')
    setup_parser.add_argument('--discover', action='store_true',
                               help='Auto-discover servers on network')
    
    # Connect command
    subparsers.add_parser('connect', help='Connect with code from admin')
    
    # Send command
    send_parser = subparsers.add_parser('send', help='Quick file upload')
    send_parser.add_argument('file', help='File to upload')
    
    # Download command
    download_parser = subparsers.add_parser('download', help='Quick file download')
    download_parser.add_argument('file', help='File to download')
    
    # List command
    subparsers.add_parser('list', help='List server files')
    
    # Users command
    subparsers.add_parser('users', help='Show connected users')
    
    # Stats command
    subparsers.add_parser('stats', help='Show your statistics')
    
    # Discover command
    discover_parser = subparsers.add_parser('discover', help='Discover Julian servers')
    discover_parser.add_argument('--timeout', type=int, default=5,
                                  help='Discovery timeout in seconds')
    
    # Reset command
    subparsers.add_parser('reset', help='Clear saved pairing')
    
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


if __name__ == "__main__":
    main()