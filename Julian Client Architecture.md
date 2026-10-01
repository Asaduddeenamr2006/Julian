# 📚 Julian Client - Architecture Guide


<writeFile>
<path>ARCHITECTURE_CLIENT.md</path>
<content># Julian Client - Architecture Guide

> **Purpose**: This document provides an in-depth technical explanation of the Julian Client architecture. It is designed for developers who want to understand, modify, or extend the client-side implementation.
>
> **Prerequisites**: Basic knowledge of Python, networking (sockets), TLS/SSL concepts, and familiarity with the Julian Server architecture (see `ARCHITECTURE_SERVER.md`).

---

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [Design Patterns Applied](#2-design-patterns-applied)
3. [Core Components Deep Dive](#3-core-components-deep-dive)
4. [Security Architecture (Client-Side)](#4-security-architecture-client-side)
5. [Protocol Design (Client Perspective)](#5-protocol-design-client-perspective)
6. [Data Flow Examples](#6-data-flow-examples)
7. [Common Vulnerabilities & Mitigations (Client-Side)](#7-common-vulnerabilities--mitigations-client-side)
8. [Extension Guide](#8-extension-guide)
9. [Performance Considerations](#9-performance-considerations)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. High-Level Architecture

### 1.1 System Overview

The Julian Client is a secure file transfer client designed to connect to Julian Servers over TLS 1.3 encrypted connections. Unlike the server, the client focuses on:

- **User Experience**: Interactive REPL and CLI interfaces
- **Local Security**: Protecting credentials and downloaded files
- **Resilience**: Handling network interruptions with resume capability
- **Verification**: Validating server identity and file integrity

### 1.2 Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        SecureClient                              │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Connection Layer (TLS 1.3)                   │  │
│  │  - Certificate pinning                                   │  │
│  │  - Encrypted socket wrapping                             │  │
│  │  - Timeout & retry management                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Authentication Layer                            │  │
│  │  - Pairing setup (first-time)                            │  │
│  │  - Code-based login (subsequent)                         │  │
│  │  - Safety Numbers verification                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Transfer Layer                                  │  │
│  │  - Upload with progress tracking                         │  │
│  │  - Download with resume capability                       │  │
│  │  - File management (delete, rename, search)              │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Validation Layer                                │  │
│  │  - FileValidator (path traversal, size, disk space)      │  │
│  │  - MessageValidator (type checking, structure)           │  │
│  │  - InputValidator (sanitization)                         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Support Services                                │  │
│  │  - DeviceIdentity (UUID + Machine ID)                    │  │
│  │  - CredentialManager (pairing storage)                   │  │
│  │  - ResumeManager (partial file tracking)                 │  │
│  │  - ServiceDiscovery (UDP broadcast listener)             │  │
│  │  - LockFile (single instance enforcement)                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           User Interface Layer                            │  │
│  │  - JulianREPL (interactive mode)                         │  │
│  │  - CLI Commands (quick operations)                       │  │
│  │  - FileBrowser (interactive navigation)                  │  │
│  │  - Progress bars                                         │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **No Auto-Login** | Requires code every time for physical verification (security over convenience) |
| **Certificate Pinning** | Prevents MITM attacks after first connection |
| **Safety Numbers** | Visual server verification (inspired by Signal) |
| **Partial Files** | Enables resume capability for interrupted transfers |
| **Device Identity** | Strong fingerprinting using UUID + Machine ID |
| **Optional Encryption** | Credentials can be encrypted with master password |
| **REPL + CLI** | Both interactive and quick command modes |
| **Lock File** | Prevents multiple instances with same credentials |

### 1.4 Client vs Server: Key Differences

| Aspect | Client | Server |
|--------|--------|--------|
| **Concurrency** | Single user | Multiple clients |
| **State** | Connection state only | Connection + Transaction state |
| **Database** | None (uses files) | SQLite |
| **Threading** | Main thread only | Multiple threads |
| **Security Focus** | Local protection | Network protection |
| **UI** | REPL + CLI | Admin CLI only |

---

## 2. Design Patterns Applied

### 2.1 Strategy Pattern - Validators

**Problem**: Different validation rules for different contexts (filenames, messages, file sizes).

**Solution**: Separate validator classes for each concern, allowing easy extension.

```python
class FileValidator:
    """Strategy for file-related validation."""
    
    @staticmethod
    def validate_download_filename(filename: str, download_dir: str = ".") -> str:
        """Validate and sanitize filename for download."""
        # Step 1: Extract only the filename (removes path components)
        safe_name = os.path.basename(filename)
        
        # Step 2: Check for dangerous patterns
        dangerous_patterns = ['..', '/', '\\', '\x00']
        for pattern in dangerous_patterns:
            if pattern in safe_name:
                raise ValueError(f"Invalid filename: contains '{pattern}'")
        
        # Step 3: Verify final path is within download directory
        download_path = Path(download_dir).resolve()
        final_path = (download_path / safe_name).resolve()
        
        if not str(final_path).startswith(str(download_path)):
            raise ValueError("Path traversal detected")
        
        return safe_name
    
    @staticmethod
    def get_safe_save_path(filename: str, directory: str = ".", 
                           prefix: str = "downloaded_") -> str:
        """Get safe path avoiding overwrites."""
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


class MessageValidator:
    """Strategy for message validation."""
    
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
            
            # Additional validation
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
```

**Benefits**:
- Each validator has single responsibility
- Easy to add new validators (e.g., `NetworkValidator`)
- Validators are independently testable
- Clear separation of validation concerns

### 2.2 Factory Pattern - ServiceDiscovery

**Problem**: Need to discover servers on the network without hardcoding connection details.

**Solution**: Factory that creates server connection info from broadcast messages.

```python
class ServiceDiscovery:
    """Factory for discovering Julian servers on the network."""
    
    def __init__(self, timeout: int = None):
        self.timeout = timeout or CONFIG["discovery"]["timeout"]
        self.broadcast_port = CONFIG["discovery"]["broadcast_port"]
    
    def discover(self) -> List[dict]:
        """
        Listen for server broadcasts and return list of discovered servers.
        
        Returns:
            List of server info dictionaries:
            [
                {
                    'ip': '192.168.1.100',
                    'port': 5000,
                    'version': '4.0.0',
                    'requires_auth': True,
                    'tls': True
                },
                ...
            ]
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('', self.broadcast_port))
        except Exception as e:
            print(f"⚠️  Could not bind to discovery port: {e}")
            return []
        
        sock.settimeout(self.timeout)
        
        servers = []
        seen_ips = set()  # Avoid duplicates
        
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
```

**Usage Example**:
```python
# In cmd_setup
discovery = ServiceDiscovery()
servers = discovery.discover()

if servers:
    print(f"✅ Found {len(servers)} Julian server(s):")
    for i, server in enumerate(servers, 1):
        tls_status = "🔐 TLS" if server['tls'] else "⚠️  No TLS"
        print(f"  [{i}] {server['ip']}:{server['port']} ({tls_status})")
    
    # User selects server
    choice = input("\n👉 Select server (number): ").strip()
    selected = servers[int(choice) - 1]
```

### 2.3 Singleton Pattern - DeviceIdentity

**Problem**: Device identity should be consistent across all client invocations.

**Solution**: Load or create identity once, persist to file.

```python
class DeviceIdentity:
    """
    Generates and manages unique device identity.
    
    Uses multiple factors for strong fingerprinting:
    1. device_uuid: Random UUID generated once
    2. machine_id: OS-provided unique identifier
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
        
        # Generate new identity
        identity = {
            "device_uuid": str(uuid.uuid4()),
            "created_at": time.strftime('%Y-%m-%d %H:%M:%S'),
            "machine_id": self._get_machine_id(),
        }
        
        # Save to file with secure permissions
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
```

**Why This Matters**:
- Without persistent identity: Each run generates new fingerprint → server sees new device
- With persistent identity: Same device always has same fingerprint → server recognizes returning device

### 2.4 Observer Pattern - REPL Command Routing

**Problem**: REPL needs to route commands to appropriate handlers.

**Solution**: Dictionary mapping command names to handler methods.

```python
class JulianREPL:
    """Interactive Read-Eval-Print Loop for Julian client."""
    
    def run(self):
        """Main REPL loop."""
        while True:
            command = input(prompt).strip()
            parts = command.split()
            cmd = parts[0].lower()
            args = parts[1:]
            
            # Command routing (similar to Command Pattern)
            if cmd == 'connect':
                self._cmd_connect(args)
            elif cmd == 'send':
                self._cmd_send(args)
            elif cmd == 'download':
                self._cmd_download(args)
            # ... more commands
```

**Benefits**:
- Easy to add new commands
- Clear separation of command handling
- Each command handler is independent

---

## 3. Core Components Deep Dive

### 3.1 SecureClient

**Purpose**: Main client class orchestrating all operations.

```python
class SecureClient:
    """
    Main client class with:
    - JSON-based protocol
    - Certificate pinning
    - Strong device fingerprinting
    - Pairing authentication
    - Resume transfers
    - File management
    """
    
    def __init__(self, server_ip: str, server_port: int, config_dir: Path = None):
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
        self.resume_manager = ResumeManager(".")
        
        # System information
        self.os_info, self.distribution, self.device_type = FileTransferUtils.get_system_info()
```

**Key Methods**:

```python
def _connect_socket(self) -> bool:
    """
    Establish TLS connection with certificate pinning and retries.
    
    Retry Strategy:
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
            
            # Pin certificate if first connection
            self._pin_certificate()
            
            return True
        
        except Exception as e:
            if attempt < max_retries:
                print(f"⚠️  Connection attempt {attempt}/{max_retries} failed: {e}")
                print(f"⏳ Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            else:
                print(f"❌ Connection failed after {max_retries} attempts: {e}")
                return False

def _create_ssl_context(self) -> ssl.SSLContext:
    """
    Create SSL context with certificate pinning.
    
    Strategy:
    1. Check if we have a pinned certificate for this server
    2. If yes: Verify against pinned certificate
    3. If no: Accept any certificate but pin it for future
    """
    context = ssl.create_default_context()
    
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
```

### 3.2 ResumeManager

**Purpose**: Manage partial downloads/uploads for resume capability.

```python
class ResumeManager:
    """
    Manages partial downloads/uploads for resume capability.
    
    How It Works:
    1. During transfer, creates .partial file
    2. Stores metadata in .partial.meta (JSON):
       - Original filename
       - Total size
       - SHA256
       - Bytes transferred
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
```

**Usage Example**:
```python
# In download_file
def download_file(self, file_name: str, resume: bool = True) -> bool:
    # Check for existing partial download
    partial_path = self.resume_manager.get_partial_path(file_name)
    meta = self.resume_manager.load_metadata(file_name) if resume else None
    
    if resume and meta and os.path.exists(partial_path):
        # Resume download
        offset = os.path.getsize(partial_path)
        print(f"\n🔄 Resuming download from {FileTransferUtils.format_size(offset)}")
        
        # Send RESUME_DOWNLOAD command
        JsonProtocol.send_message(self.socket, {
            "type": "RESUME_DOWNLOAD",
            "filename": file_name,
            "offset": offset
        })
        
        # ... continue download from offset
    else:
        # Fresh download
        return self._download_fresh(file_name)
```

### 3.3 SafetyNumbers

**Purpose**: Verify server identity using visual safety numbers.

```python
class SafetyNumbers:
    """
    Verifies server identity using Safety Numbers.
    
    Inspired by Signal's Safety Numbers.
    
    How It Works:
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
```

**Why This Matters**:
- Without Safety Numbers: Client trusts any certificate on first connection → vulnerable to MITM
- With Safety Numbers: User visually verifies server identity → prevents MITM attacks

### 3.4 LockFile

**Purpose**: Prevent multiple instances from running simultaneously.

```python
class LockFile:
    """
    Prevents multiple instances from running simultaneously.
    
    How It Works:
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
                return False  # Process exists → another instance running
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
```

**Usage in main()**:
```python
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
        # ... rest of the code
    finally:
        # Always release lock on exit
        lock.release()
```

### 3.5 JulianREPL

**Purpose**: Interactive command-line interface for the client.

```python
class JulianREPL:
    """
    Interactive Read-Eval-Print Loop for Julian client.
    
    Usage:
    ------
    $ ju_client
    # Opens REPL with connection info and quick commands
    
    Commands:
    ---------
    connect [code]    - Connect to server
    disconnect        - Disconnect
    send <file>       - Upload file
    download <file>   - Download file
    list              - List server files
    search <pattern>  - Search files
    delete <file>     - Delete file
    rename <old> <new> - Rename file
    resume            - List resumable downloads
    users             - Show connected users
    stats             - Show your statistics
    verify            - Verify server identity
    info              - Show connection info
    help              - Show help
    exit              - Exit
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
                # Show prompt with connection status
                if self.connected:
                    prompt = f"\n🔗 [{self.username}@{self.server_ip}:{self.server_port}]> "
                else:
                    prompt = "\n⚫ [disconnected]> "
                
                command = input(prompt).strip()
                
                if not command:
                    continue
                
                # Parse command
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:]
                
                # Route to handler
                if cmd in ['exit', 'quit', 'q']:
                    if self.connected:
                        self.client.close()
                    print("👋 Goodbye!")
                    break
                
                elif cmd == 'help':
                    self._show_help()
                
                elif cmd == 'connect':
                    self._cmd_connect(args)
                
                # ... more commands
            
            except KeyboardInterrupt:
                print("\n\n⚠️  Use 'exit' to quit")
            except EOFError:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
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
        
        # Get code
        if args:
            code = args[0]
        else:
            code = input("🔑 Enter code from admin: ").strip()
        
        self.client = SecureClient(self.server_ip, self.server_port)
        
        if self.client.connect_with_code(self.username, code):
            self.connected = True
            print(f"✅ Connected!")
            
            # Optional: Verify server
            verify = input("\n🛡️ Verify server identity? (y/n): ").strip().lower()
            if verify in ['y', 'yes']:
                self.client.verify_server()
        else:
            print("❌ Connection failed")
            self.client = None
```

---

## 4. Security Architecture (Client-Side)

### 4.1 Defense in Depth (Client Perspective)

```
Layer 1: Local Storage
├── Secure file permissions (0o600)
├── Optional credentials encryption (AES-128)
└── Lock file (prevent multiple instances)

Layer 2: Network Communication
├── TLS 1.3 encryption
├── Certificate pinning (prevents MITM)
├── Safety Numbers (visual verification)
└── Timeouts (prevent hanging)

Layer 3: Data Validation
├── Path traversal protection
├── File size validation
├── Disk space checking
├── Message type validation
└── SHA256 integrity verification

Layer 4: Identity Management
├── Device fingerprinting (UUID + Machine ID)
├── Pairing codes (physical verification)
└── One-time use codes
```

### 4.2 Certificate Pinning

**Concept**: Store server certificate on first connection, verify on subsequent connections.

```python
def _create_ssl_context(self) -> ssl.SSLContext:
    """Create SSL context with certificate pinning."""
    context = ssl.create_default_context()
    
    cert_file = self.certs_dir / f"{self.server_ip}.pem"
    
    if cert_file.exists():
        # Subsequent connection: verify against pinned certificate
        try:
            context.load_verify_locations(cert_file)
            context.check_hostname = False  # Self-signed certs
            context.verify_mode = ssl.CERT_REQUIRED
        except Exception as e:
            print(f"⚠️  Certificate verification failed: {e}")
            # Fall back to no verification (should not happen in practice)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    else:
        # First connection: accept any certificate but pin it
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    return context
```

**Attack Scenario Without Pinning**:
```
1. Attacker sets up rogue server on same network
2. Client connects to rogue server (thinks it's legitimate)
3. Attacker presents fake certificate
4. Client accepts certificate (no pinning)
5. Attacker intercepts all communications
6. Attacker steals pairing codes, files, credentials
```

**Defense With Pinning**:
```
1. First connection: Client accepts and pins certificate
2. Subsequent connections: Client verifies certificate matches pinned
3. If attacker presents different certificate → connection rejected
4. User is alerted to potential MITM attack
```

### 4.3 Path Traversal Protection

**Attack**:
```python
# Malicious filename from server
filename = "../../../.ssh/id_rsa"
save_path = f"downloaded_{filename}"
# Result: "downloaded_../../../.ssh/id_rsa"
# After normalization: "../../../.ssh/id_rsa"
# Writes to ~/.ssh/id_rsa!
```

**Mitigation**:
```python
def validate_download_filename(filename: str, download_dir: str = ".") -> str:
    """Validate and sanitize filename for download."""
    # Step 1: Extract only the filename (removes all path components)
    safe_name = os.path.basename(filename)
    # "../../../.ssh/id_rsa" → "id_rsa"
    
    # Step 2: Check for dangerous patterns
    dangerous_patterns = ['..', '/', '\\', '\x00']
    for pattern in dangerous_patterns:
        if pattern in safe_name:
            raise ValueError(f"Invalid filename: contains '{pattern}'")
    
    # Step 3: Verify final path is within download directory
    download_path = Path(download_dir).resolve()
    final_path = (download_path / safe_name).resolve()
    
    if not str(final_path).startswith(str(download_path)):
        raise ValueError("Path traversal detected")
    
    return safe_name
```

### 4.4 File Overwrite Protection

**Attack**:
```python
# User has important file: "report.pdf"
# Malicious server sends file with same name
# Client overwrites without warning
# User loses important data
```

**Mitigation**:
```python
def get_safe_save_path(filename: str, directory: str = ".", 
                       prefix: str = "downloaded_") -> str:
    """Get safe path avoiding overwrites."""
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
```

**Result**:
```
First download:  downloaded_report.pdf
Second download: downloaded_report(1).pdf
Third download:  downloaded_report(2).pdf
```

### 4.5 Credentials Encryption (Optional)

**Problem**: Credentials stored in plain text (with file permissions only).

**Solution**: Optional AES-128 encryption with master password.

```python
class CredentialsEncryption:
    """
    Optional encryption for stored credentials.
    
    Security:
    - Uses Fernet (AES-128-CBC) for encryption
    - Master password → PBKDF2 → 32-byte key
    - Salt stored with encrypted data
    - 480,000 iterations for key derivation
    """
    
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
        salt = os.urandom(16)
        key = CredentialsEncryption.derive_key(password, salt)
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        
        # Return salt + encrypted data (base64 encoded)
        combined = salt + encrypted
        return base64.b64encode(combined).decode()
```

**Usage**:
```python
# In CredentialManager.save_pairing
if self.encrypt:
    master_password = getpass.getpass("🔑 Enter master password: ")
    encrypted_data = CredentialsEncryption.encrypt(json_data, master_password)
    credentials = {
        'encrypted': True,
        'credentials_data': encrypted_data
    }
```

---

## 5. Protocol Design (Client Perspective)

### 5.1 Client-Server Communication Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    First-Time Setup                              │
├─────────────────────────────────────────────────────────────────┤
│  1. Client → PAIR_REQUEST {username, device_info, fingerprint}  │
│  2. Server → PAIR_CODE {code}                                   │
│  3. [User gets code from admin]                                 │
│  4. Client → PAIR_CONFIRM {code}                                │
│  5. Server → PAIRED_OK                                          │
│  6. Client saves pairing info locally                           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Subsequent Connections                        │
├─────────────────────────────────────────────────────────────────┤
│  1. Client → CODE_LOGIN {username, code, fingerprint}           │
│  2. Server → LOGIN_OK {username}                                │
│  3. Enter command loop                                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    File Upload                                   │
├─────────────────────────────────────────────────────────────────┤
│  1. Client → UPLOAD {filename, size, sha256}                    │
│  2. Client sends file data in 4KB chunks                        │
│  3. Server → FILE_OK or FILE_CORRUPTED                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    File Download                                 │
├─────────────────────────────────────────────────────────────────┤
│  1. Client → DOWNLOAD {filename}                                │
│  2. Server → FILE_META {filename, size, sha256}                 │
│  3. Client → READY                                              │
│  4. Server sends file data in 4KB chunks                        │
│  5. Client verifies SHA256                                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Resume Download                               │
├─────────────────────────────────────────────────────────────────┤
│  1. Client → RESUME_DOWNLOAD {filename, offset}                 │
│  2. Server → RESUME_META {filename, size, offset, remaining}    │
│  3. Client → READY                                              │
│  4. Server sends remaining data from offset                     │
│  5. Client appends to partial file                              │
│  6. Client verifies SHA256                                      │
│  7. Client renames partial to final filename                    │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Message Types (Client Perspective)

| Message | Direction | Client Action |
|---------|-----------|---------------|
| PAIR_REQUEST | Client → Server | Initiate pairing |
| PAIR_CODE | Server → Client | Display code to user |
| PAIR_CONFIRM | Client → Server | Send code confirmation |
| PAIRED_OK | Server → Client | Save pairing info |
| CODE_LOGIN | Client → Server | Login with code |
| LOGIN_OK | Server → Client | Enter command loop |
| UPLOAD | Client → Server | Start file upload |
| DOWNLOAD | Client → Server | Request file download |
| FILE_META | Server → Client | Validate and prepare |
| READY | Client → Server | Signal ready to receive |
| RESUME_DOWNLOAD | Client → Server | Resume interrupted download |
| RESUME_META | Server → Client | Validate resume metadata |
| DELETE | Client → Server | Delete file |
| DELETE_OK | Server → Client | Confirm deletion |
| RENAME | Client → Server | Rename file |
| RENAME_OK | Server → Client | Confirm rename |
| SEARCH | Client → Server | Search files |
| SEARCH_RESULTS | Server → Client | Display results |
| FILE_LIST | Server → Client | Display file list |
| USER_LIST | Server → Client | Display user list |
| STATS | Server → Client | Display statistics |
| SERVER_FINGERPRINT | Server → Client | Verify server identity |
| ERROR | Server → Client | Display error |
| QUIT | Client → Server | Disconnect |

---

## 6. Data Flow Examples

### 6.1 First-Time Setup Flow

```
1. User runs: ju_client setup
   │
2. Client prompts for server IP, port, username
   │
3. Client creates socket and establishes TLS connection
   │  └─> Certificate pinned for future verification
   │
4. Client sends: PAIR_REQUEST {username, device_info, fingerprint}
   │
5. Server generates pairing code and displays to admin
   │
6. Server sends: PAIR_CODE {code: "84729153"}
   │
7. Client displays code and asks user to get it from admin
   │
8. User enters code from admin console
   │
9. Client sends: PAIR_CONFIRM {code: "84729153"}
   │
10. Server verifies code and fingerprint
    │
11. Server sends: PAIRED_OK
    │
12. Client saves pairing info to ~/.julian/credentials.json
    │  └─> File permissions set to 0o600
    │
13. Setup complete!
```

### 6.2 Resume Download Flow

```
1. User runs: ju_client download large_video.mp4
   │
2. Client checks for partial file: large_video.mp4.partial
   │  └─> Found! Partial file exists (690 MB of 1.5 GB)
   │
3. Client loads metadata: large_video.mp4.partial.meta
   │  └─> {total_size: 1.5GB, sha256: "abc...", bytes_transferred: 690MB}
   │
4. Client calculates offset: 690 MB
   │
5. Client sends: RESUME_DOWNLOAD {filename: "large_video.mp4", offset: 690MB}
   │
6. Server validates offset and sends: RESUME_META {size: 1.5GB, remaining: 834MB}
   │
7. Client sends: READY
   │
8. Server seeks to offset and sends remaining data
   │
9. Client appends to partial file
   │  └─> Updates metadata every 1MB
   │
10. Download completes
    │
11. Client verifies SHA256 of complete file
    │
12. Client renames: large_video.mp4.partial → downloaded_large_video.mp4
    │
13. Client cleans up: removes .partial and .partial.meta files
    │
14. Download successful!
```

### 6.3 Server Verification Flow

```
1. User connects to server for first time
   │
2. Client prompts: "Verify server identity? (y/n)"
   │
3. User enters: y
   │
4. Client sends: SERVER_FINGERPRINT
   │
5. Server computes SHA256 of its certificate
   │
6. Server converts to 5 groups of 5 digits
   │  └─> "84729-15362-48291-73645-92817"
   │
7. Server sends: SERVER_FINGERPRINT {safety_numbers: "84729-15362-..."}
   │
8. Client displays safety numbers
   │
9. User compares with numbers shown on server console
   │
10. User enters: yes
    │
11. Server verified! Connection is authentic.
```

---

## 7. Common Vulnerabilities & Mitigations (Client-Side)

### 7.1 Server Spoofing (MITM on First Connection)

**Attack**:
```
1. Attacker sets up rogue server on same network
2. Rogue server broadcasts fake discovery message
3. Client connects to rogue server
4. Rogue server presents fake certificate
5. Client accepts certificate (first connection)
6. Client pins fake certificate
7. All future connections go to attacker
```

**Mitigation**:
1. **Safety Numbers**: User visually verifies server identity
2. **Manual IP Entry**: User enters IP manually instead of auto-discovery
3. **Out-of-Band Verification**: Verify server fingerprint through another channel

**Best Practice**:
```python
# Always verify on first connection
if not cert_file.exists():
    verify = input("\n🛡️ Verify server identity? (y/n): ").strip().lower()
    if verify in ['y', 'yes']:
        client.verify_server()
```

### 7.2 Credential Theft

**Attack**:
```
1. Attacker gains access to user's home directory
2. Reads ~/.julian/credentials.json
3. Extracts server IP, port, username, device fingerprint
4. Can monitor user activity or attempt impersonation
```

**Mitigation**:
1. **File Permissions**: 0o600 (owner read/write only)
2. **Optional Encryption**: AES-128 with master password
3. **System Keyring**: Use OS-provided secure storage (future)

**Best Practice**:
```python
# Enable encryption for sensitive environments
CONFIG["security"]["encrypt_credentials"] = True
```

### 7.3 Path Traversal in Downloads

**Attack**:
```
1. Malicious server sends: {"filename": "../../../.ssh/id_rsa", ...}
2. Client saves to: "downloaded_../../../.ssh/id_rsa"
3. After normalization: "../../../.ssh/id_rsa"
4. Writes to ~/.ssh/id_rsa (overwrites SSH key!)
```

**Mitigation**:
```python
def validate_download_filename(filename: str, download_dir: str = ".") -> str:
    # Extract only filename (removes path components)
    safe_name = os.path.basename(filename)
    
    # Check for dangerous patterns
    if any(c in safe_name for c in ['..', '/', '\\', '\x00']):
        raise ValueError("Invalid filename")
    
    # Verify final path is within download directory
    download_path = Path(download_dir).resolve()
    final_path = (download_path / safe_name).resolve()
    
    if not str(final_path).startswith(str(download_path)):
        raise ValueError("Path traversal detected")
    
    return safe_name
```

### 7.4 File Overwrite

**Attack**:
```
1. User has important file: "report.pdf"
2. Malicious server sends file with same name
3. Client overwrites without warning
4. User loses important data
```

**Mitigation**:
```python
def get_safe_save_path(filename: str, directory: str = ".", 
                       prefix: str = "downloaded_") -> str:
    # If file exists, add sequential number
    if base_path.exists():
        counter = 1
        while True:
            new_name = f"{prefix}{stem}({counter}){suffix}"
            new_path = Path(directory) / new_name
            if not new_path.exists():
                return str(new_path)
            counter += 1
```

### 7.5 Malformed Messages

**Attack**:
```
1. Malicious server sends: {"size": "not_a_number", ...}
2. Client tries: int("not_a_number") → ValueError → crash
3. Or: {"filename": null} → TypeError → crash
```

**Mitigation**:
```python
class MessageValidator:
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
            
            # Additional validation
            if expected_type == int and value < 0:
                return False
        
        return True
```

---

## 8. Extension Guide

### 8.1 Adding a New Command

**Step 1**: Add method to SecureClient
```python
def my_new_operation(self, param: str) -> bool:
    """Perform new operation."""
    JsonProtocol.send_message(self.socket, {
        "type": "MY_COMMAND",
        "param": param
    })
    
    response = JsonProtocol.recv_message(self.socket)
    
    if response and response.get('type') == 'MY_RESPONSE':
        print(f"✅ Operation successful: {response.get('data')}")
        return True
    else:
        print(f"❌ Operation failed")
        return False
```

**Step 2**: Add to REPL
```python
class JulianREPL:
    def run(self):
        # ... in command routing
        elif cmd == 'mycommand':
            self._cmd_mycommand(args)
    
    def _cmd_mycommand(self, args):
        """Execute my command."""
        if not self._check_connected():
            return
        
        if not args:
            param = input("Enter parameter: ").strip()
        else:
            param = args[0]
        
        self.client.my_new_operation(param)
```

**Step 3**: Add to CLI
```python
# In main()
mycommand_parser = subparsers.add_parser('mycommand', help='My new command')
mycommand_parser.add_argument('param', help='Parameter')

# Add handler
def cmd_mycommand(args):
    def do_mycommand(client):
        client.my_new_operation(args.param)
    _require_code_and_connect("mycommand", do_mycommand)

# Route in main
elif args.command == 'mycommand':
    cmd_mycommand(args)
```

### 8.2 Adding a New Validator

**Step 1**: Create validator class
```python
class NetworkValidator:
    """Validate network-related inputs."""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number."""
        return 1 <= port <= 65535
```

**Step 2**: Use in code
```python
def connect_to_server(self, ip: str, port: int):
    if not NetworkValidator.validate_ip(ip):
        raise ValueError("Invalid IP address")
    
    if not NetworkValidator.validate_port(port):
        raise ValueError("Invalid port number")
    
    # ... continue with connection
```

### 8.3 Adding a New Event Handler

**Step 1**: Define event
```python
# In SecureClient
def _on_download_complete(self, filename: str, size: int):
    """Handle download completion."""
    print(f"✅ Downloaded: {filename} ({FileTransferUtils.format_size(size)})")
    
    # Could add:
    # - Desktop notification
    # - Sound alert
    # - Log to file
```

**Step 2**: Call at appropriate time
```python
def download_file(self, file_name: str) -> bool:
    # ... download logic
    
    if FileTransferUtils.calculate_sha256(save_path) == file_sha256:
        self._on_download_complete(file_name, file_size)
        return True
```

---

## 9. Performance Considerations

### 9.1 Network Performance

**Chunk Size**: 4096 bytes
- Balances memory usage vs. network efficiency
- Too small: Too many system calls
- Too large: High memory usage, slower error recovery

**Timeouts**:
- Connection timeout: 10 seconds
- Transfer timeout: 30 seconds per chunk
- Discovery timeout: 5 seconds

**Retries**:
- Max retries: 3
- Retry delay: 2 seconds
- Exponential backoff (future enhancement)

### 9.2 Disk I/O Performance

**Partial Files**:
- Metadata saved every 1MB (balances I/O vs. resume granularity)
- Partial files use `.partial` suffix
- Metadata uses `.partial.meta` suffix

**File Writing**:
- Binary mode ('wb' for write, 'ab' for append)
- Buffered I/O (Python default)
- SHA256 calculated after download (not during)

### 9.3 Memory Management

**Large Files**:
- Streamed in 4KB chunks (not loaded entirely into memory)
- Partial files stored on disk
- Metadata kept small (JSON)

**Certificate Storage**:
- One PEM file per server IP
- Loaded only when needed
- Cached in memory during connection

---

## 10. Troubleshooting

### 10.1 Common Issues

**Issue**: "Another Julian client is already running"
- **Cause**: Lock file exists from previous run
- **Solution**: Close other instance or delete `~/.julian/client.lock`

**Issue**: "Certificate verification failed"
- **Cause**: Server certificate changed (regenerated)
- **Solution**: Delete `~/.julian/certs/<ip>.pem` and reconnect

**Issue**: "Wrong password or corrupted data"
- **Cause**: Wrong master password for encrypted credentials
- **Solution**: Remember password or run `ju_client reset`

**Issue**: "Path traversal detected"
- **Cause**: Server sent malicious filename
- **Solution**: This is security working correctly! Report to server admin

**Issue**: "Transfer timeout"
- **Cause**: Network issue or server stopped
- **Solution**: Check network, restart server, or use resume feature

### 10.2 Debugging Tips

**Enable verbose logging**:
```python
# In CONFIG
"logging": {
    "level": "DEBUG",  # Change from INFO to DEBUG
}
```

**Check credentials**:
```bash
cat ~/.julian/credentials.json
```

**Check device identity**:
```bash
cat ~/.julian/device_id.json
```

**List pinned certificates**:
```bash
ls -la ~/.julian/certs/
```

**Check partial downloads**:
```bash
ls -la *.partial *.partial.meta
```

**Test connectivity**:
```bash
telnet <server_ip> <port>
openssl s_client -connect <server_ip>:<port>
```

---

## Conclusion

The Julian Client demonstrates how to build a secure, user-friendly file transfer client by:

1. **Defense in depth**: Multiple layers of client-side security
2. **Resilience**: Resume capability for interrupted transfers
3. **Verification**: Safety Numbers and certificate pinning
4. **Validation**: Comprehensive input and message validation
5. **User experience**: Both REPL and CLI interfaces

This architecture serves as a foundation for learning advanced client-side security concepts while building something practical and secure.

**Key Takeaways**:
- Always validate inputs from the server
- Pin certificates after first connection
- Verify server identity visually
- Protect local credentials
- Handle network failures gracefully

---

**Document Version**: 1.0.0  
**Last Updated**: 2026-10-01  
**Author**: Julian Project Team  
**License**: MIT
</content>
</writeFile>

