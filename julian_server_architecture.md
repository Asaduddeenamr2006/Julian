# Julian Server - Deep Architecture Guide

> **Purpose**: This document provides an in-depth technical explanation of the Julian Server architecture. It is designed for developers who want to understand, modify, or extend the system.
>
> **Prerequisites**: Basic knowledge of Python, networking (sockets), and security concepts.

---

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [Design Patterns Applied](#2-design-patterns-applied)
3. [Core Components Deep Dive](#3-core-components-deep-dive)
4. [Security Architecture](#4-security-architecture)
5. [Protocol Design](#5-protocol-design)
6. [Data Flow Examples](#6-data-flow-examples)
7. [Common Vulnerabilities & Mitigations](#7-common-vulnerabilities--mitigations)
8. [Extension Guide](#8-extension-guide)

---

## 1. High-Level Architecture

### 1.1 System Overview

Julian is a **secure, multi-client file transfer system** designed for local networks. It implements a client-server architecture where:

- **Server**: Manages connections, authenticates clients, stores files, and enforces security policies.
- **Client**: Connects to the server, authenticates via pairing codes, and performs file operations.

### 1.2 Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        SecureServer                              │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              Connection Layer (TLS 1.3)                   │  │
│  │  - SSL certificate management                            │  │
│  │  - Encrypted socket wrapping                             │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           ConnectionManager (State Tracking)              │  │
│  │  - Tracks all active connections                         │  │
│  │  - Manages connection states (auth, idle, transfer)      │  │
│  │  - Detects zombie connections                            │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           TransactionManager (File Operations)            │  │
│  │  - Tracks file uploads/downloads                         │  │
│  │  - Progress monitoring                                   │  │
│  │  - Transaction persistence                               │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Command Layer (Command Pattern)                 │  │
│  │  ┌─────────┐ ┌──────────┐ ┌──────┐ ┌──────┐ ┌──────┐  │  │
│  │  │ UPLOAD  │ │ DOWNLOAD │ │ LIST │ │STATS │ │ QUIT │  │  │
│  │  └─────────┘ └──────────┘ └──────┘ └──────┘ └──────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Database Layer (Singleton Pattern)              │  │
│  │  - SQLite database with thread-safe access               │  │
│  │  - Users, stats, bans, transactions, logs                │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │           Support Services                                │  │
│  │  - EventBus (Observer Pattern)                           │  │
│  │  - HeartbeatMonitor (zombie detection)                   │  │
│  │  - RateLimiter (brute force protection)                  │  │
│  │  - ServiceDiscovery (UDP broadcast)                      │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **JSON Protocol** | Prevents command injection and data corruption (vs. text-based `|` separator) |
| **Random Port** | Hides service from automated scanners (security through obscurity) |
| **Pairing Codes** | Requires physical verification (prevents remote unauthorized access) |
| **TLS 1.3** | Latest encryption standard with perfect forward secrecy |
| **SQLite** | Simple, embedded database suitable for single-server deployment |
| **Threading** | Handles multiple clients concurrently without async complexity |

---

## 2. Design Patterns Applied

### 2.1 Singleton Pattern - DatabaseManager

**Problem**: Multiple threads need database access, but SQLite only allows one connection per database file.

**Solution**: Ensure only ONE instance of DatabaseManager exists across the entire application.

```python
class DatabaseManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, db_name: str = None):
        """
        Override __new__ to implement Singleton.
        
        How it works:
        1. First call: _instance is None → create new instance
        2. Subsequent calls: _instance exists → return same instance
        3. _lock ensures thread safety during instance creation
        """
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self, db_name: str = None):
        """Initialize only once (guarded by _initialized flag)."""
        if self._initialized:
            return
        # ... initialization code ...
        self._initialized = True
```

**Usage Example**:
```python
# In SecureServer.__init__
self.db = DatabaseManager()  # Creates instance

# In UploadCommand.execute
self.db.update_stats(...)  # Uses SAME instance

# In DownloadCommand.execute
self.db.log_transfer(...)  # Uses SAME instance

# All three share the same database connection!
```

**Why This Matters**:
- Without Singleton: Each command creates its own connection → SQLite locks conflict
- With Singleton: All commands share one connection → coordinated by `db_lock`

---

### 2.2 Observer Pattern - EventBus

**Problem**: Business logic (file upload) is tightly coupled with side effects (logging, notifications).

**Solution**: Decouple them using an event bus where components subscribe to events.

```python
class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()
    
    def subscribe(self, event_type: str, callback: Callable) -> None:
        """Register a callback for a specific event type."""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(callback)
    
    def publish(self, event_type: str, data: dict = None) -> None:
        """Notify all subscribers of an event."""
        # Copy list to avoid holding lock during callbacks
        with self._lock:
            subscribers = self._subscribers.get(event_type, []).copy()
        
        for callback in subscribers:
            try:
                callback(data or {})
            except Exception as e:
                logging.error(f"Event handler error: {e}")
```

**Usage Example**:
```python
# Setup (in SecureServer.__init__)
self.event_bus = EventBus()
self.event_bus.subscribe('file_uploaded', self._on_file_uploaded)
self.event_bus.subscribe('user_connected', self._on_user_connected)

# Publishing (in UploadCommand.execute)
self.event_bus.publish('file_uploaded', {
    'username': username,
    'filename': file_name,
    'size': file_size
})

# Handling (in SecureServer)
def _on_file_uploaded(self, data: dict) -> None:
    logging.info(f"File uploaded: {data['filename']} by {data['username']}")
```

**Benefits**:
- UploadCommand doesn't know about logging → easier to test
- Can add new subscribers (e.g., send email notification) without modifying UploadCommand
- Follows Open-Closed Principle (open for extension, closed for modification)

---

### 2.3 Command Pattern - Protocol Commands

**Problem**: Adding new commands requires modifying a giant `if/elif` chain.

**Solution**: Encapsulate each command in its own class with a common interface.

```python
# Abstract base class defines the interface
class Command(ABC):
    @abstractmethod
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        pass

# Each command is a separate class
class UploadCommand(Command):
    def __init__(self, event_bus, db, shared_folder, transaction_manager, connection_manager):
        # Inject dependencies
        self.event_bus = event_bus
        self.db = db
        # ...
    
    def execute(self, client, data, context):
        # Upload logic here
        pass

class DownloadCommand(Command):
    def execute(self, client, data, context):
        # Download logic here
        pass
```

**Factory for command routing**:
```python
class CommandFactory:
    def __init__(self, ...):
        self.commands = {
            "UPLOAD": UploadCommand(...),
            "DOWNLOAD": DownloadCommand(...),
            "LIST": ListCommand(...),
            # ...
        }
    
    def get_command(self, command_name: str) -> Optional[Command]:
        return self.commands.get(command_name)

# Usage in main loop
command = self.command_factory.get_command(msg.get('type', ''))
if command:
    command.execute(client, msg, context)
```

**Benefits**:
- Adding a new command = creating a new class (no modification of existing code)
- Each command is independently testable
- Clear separation of concerns

---

### 2.4 Strategy Pattern - Connection States

**Problem**: Connection behavior changes based on state (authenticating vs. transferring).

**Solution**: Use an Enum to represent states, and check state before operations.

```python
class ConnectionState(Enum):
    AUTHENTICATING = "authenticating"
    IDLE = "idle"
    TRANSFERRING = "transferring"
    CLOSING = "closing"

# Usage
class Connection:
    state: ConnectionState = ConnectionState.AUTHENTICATING
    
    # State transitions
    def transition_to(self, new_state: ConnectionState):
        # Could add validation here
        self.state = new_state
```

**State Machine**:
```
[AUTHENTICATING] ──success──> [IDLE] ──start transfer──> [TRANSFERRING]
       │                        │                              │
       │                        │                              │
       └──fail──> [CLOSING] <───┘──────transfer done──────────┘
```

---

## 3. Core Components Deep Dive

### 3.1 ConnectionManager

**Purpose**: Track all active client connections with their state and statistics.

```python
@dataclass
class Connection:
    id: str                           # UUID for unique identification
    username: str                     # Authenticated username
    socket: socket.socket             # Underlying TCP socket
    address: tuple                    # (IP, port) of client
    state: ConnectionState            # Current state
    current_transaction: Optional[str] # Active transaction ID
    last_activity: float              # Timestamp for idle detection
    created_at: float                 # Connection start time
    bytes_sent: int                   # Outgoing bytes counter
    bytes_received: int               # Incoming bytes counter
    mac_address: str                  # Client MAC (if available)
    device_fingerprint: str           # Unique device identifier
```

**Key Methods**:

```python
class ConnectionManager:
    def register(self, username, client_socket, address, mac_address, device_fingerprint):
        """
        Register a new connection.
        
        Returns:
            Connection object if successful, None if max connections reached
            or username already connected.
        """
        with self._lock:
            # Check capacity
            if len(self._connections) >= self.max_connections:
                return None
            
            # Check for duplicate username
            for conn in self._connections.values():
                if conn.username == username:
                    return None
            
            # Create and store
            connection_id = str(uuid.uuid4())
            connection = Connection(...)
            self._connections[connection_id] = connection
            return connection
    
    def get_zombie_connections(self, timeout=None):
        """
        Find connections with no activity for longer than timeout.
        Used by HeartbeatMonitor for cleanup.
        """
        timeout = timeout or CONFIG["connections"]["heartbeat_timeout"]
        now = time.time()
        
        with self._lock:
            return [
                conn for conn in self._connections.values()
                if now - conn.last_activity > timeout
            ]
    
    def cleanup(self):
        """Close and remove zombie connections."""
        zombies = self.get_zombie_connections()
        for conn in zombies:
            try:
                conn.socket.close()
            except Exception:
                pass
            self.unregister(conn.id)
        return len(zombies)
```

**Thread Safety**: All methods use `self._lock` to prevent race conditions when multiple threads access the connection dictionary.

---

### 3.2 TransactionManager

**Purpose**: Track file transfer operations with progress monitoring.

```python
@dataclass
class Transaction:
    id: str
    connection_id: str
    username: str
    type: str  # 'upload' or 'download'
    filename: str
    size: int
    status: TransactionStatus
    bytes_transferred: int = 0
    started_at: float = field(default_factory=time.time)
    
    @property
    def progress_percent(self) -> float:
        """Calculate progress as percentage."""
        if self.size == 0:
            return 0.0
        return (self.bytes_transferred / self.size) * 100
```

**Progress Tracking Example**:
```python
# In UploadCommand.execute
transaction = self.transaction_manager.create_transaction(
    connection_id, username, 'upload', file_name, file_size
)

received_size = 0
with open(save_path, 'wb') as f:
    while received_size < file_size:
        chunk = client.recv(4096)
        if not chunk:
            break
        f.write(chunk)
        received_size += len(chunk)
        
        # Update progress after each chunk
        self.transaction_manager.update_progress(transaction.id, received_size)

# After completion
self.transaction_manager.complete_transaction(transaction.id, success=True)
```

**Why This Matters**:
- Enables future features like "pause/resume" transfers
- Provides real-time statistics for admin
- Helps identify stuck transfers

---

### 3.3 HeartbeatMonitor

**Purpose**: Detect and clean up zombie connections (connections that died without proper closure).

```python
class HeartbeatMonitor:
    def __init__(self, connection_manager):
        self.connection_manager = connection_manager
        self.running = False
        self.thread = None
    
    def start(self):
        """Start monitoring in a daemon thread."""
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    
    def _monitor_loop(self):
        """Main monitoring loop running every N seconds."""
        interval = CONFIG["connections"]["heartbeat_interval"]
        cleanup_interval = CONFIG["connections"]["cleanup_interval"]
        last_cleanup = time.time()
        
        while self.running:
            try:
                # Check for zombies
                zombies = self.connection_manager.get_zombie_connections()
                if zombies:
                    logging.warning(f"Detected {len(zombies)} zombie connections")
                
                # Periodic cleanup
                now = time.time()
                if now - last_cleanup > cleanup_interval:
                    cleaned = self.connection_manager.cleanup()
                    if cleaned > 0:
                        logging.info(f"Cleaned up {cleaned} zombies")
                    last_cleanup = now
                
                time.sleep(interval)
            except Exception as e:
                logging.error(f"Heartbeat monitor error: {e}")
```

**Why This Matters**:
- Without this: Zombie connections accumulate → memory exhaustion → server crash
- With this: Dead connections are detected and cleaned automatically

---

### 3.4 RateLimiter

**Purpose**: Prevent brute force attacks by limiting connection attempts per IP.

**Algorithm**: Sliding Window Log

```python
class RateLimiter:
    def __init__(self, max_attempts=5, window_seconds=60):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self.attempts = defaultdict(list)  # {ip: [timestamps]}
        self.lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> bool:
        """
        Check if IP can make another attempt.
        
        Algorithm:
        1. Remove attempts older than `window` seconds
        2. If remaining attempts >= max_attempts → reject
        3. Otherwise, record this attempt and allow
        """
        now = time.time()
        
        with self.lock:
            # Step 1: Clean old attempts
            self.attempts[ip] = [
                t for t in self.attempts[ip] 
                if now - t < self.window
            ]
            
            # Step 2: Check limit
            if len(self.attempts[ip]) >= self.max_attempts:
                return False
            
            # Step 3: Record and allow
            self.attempts[ip].append(now)
            return True
```

**Example Scenario**:
```
Time 0:  IP 192.168.1.50 makes attempt → allowed (1/5)
Time 10: IP 192.168.1.50 makes attempt → allowed (2/5)
Time 20: IP 192.168.1.50 makes attempt → allowed (3/5)
Time 30: IP 192.168.1.50 makes attempt → allowed (4/5)
Time 40: IP 192.168.1.50 makes attempt → allowed (5/5)
Time 50: IP 192.168.1.50 makes attempt → REJECTED (5/5 in window)
Time 70: IP 192.168.1.50 makes attempt → allowed (first attempt expired)
```

---

## 4. Security Architecture

### 4.1 Defense in Depth

Julian implements multiple security layers:

```
Layer 1: Network Level
├── Random Port (hides from scanners)
├── Stealth Mode (silent drop for unauthorized)
└── Rate Limiting (prevents brute force)

Layer 2: Transport Level
├── TLS 1.3 (encrypts all traffic)
└── Certificate Pinning (prevents MITM)

Layer 3: Authentication Level
├── Pairing Codes (physical verification)
├── Device Fingerprinting (device binding)
└── MAC-based Banning (device blocking)

Layer 4: Application Level
├── Input Validation (prevents injection)
├── Path Traversal Protection
└── JSON Protocol (prevents command injection)
```

### 4.2 TLS 1.3 Implementation

```python
# Server-side setup
self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
self.context.load_cert_chain(cert_file, key_file)

# Wrap socket
self.server_socket = self.context.wrap_socket(
    self.server_socket, server_side=True
)
```

**Why TLS 1.3?**
- Faster handshake (1-RTT vs 2-RTT in TLS 1.2)
- Perfect Forward Secrecy by default
- Removed insecure cipher suites
- Better resistance to downgrade attacks

### 4.3 Stealth Mode

**Concept**: Unauthorized connections are silently dropped without any response.

```python
def _silent_close(self, client, ip, mac, attempt_type, details):
    """
    Close connection without sending any response.
    
    Why? Attackers scanning ports can't distinguish between:
    - Port closed (no service)
    - Port filtered (firewall)
    - Our server (rejecting unauthorized access)
    
    All three look the same to the attacker!
    """
    self.db.log_security_event(ip, mac, attempt_type, details)
    self.event_bus.publish('security_event', {...})
    try:
        client.close()
    except Exception:
        pass
```

**Effect on Attackers**:
- `nmap` shows port as "filtered" or "closed"
- Attacker doesn't know if service exists
- Every failed attempt is logged for admin review

### 4.4 Pairing Authentication Flow

```
Client                          Server
  │                               │
  │──PAIR_REQUEST───────────────>│
  │  (username, fingerprint)     │
  │                               │──Generate 8-digit code
  │                               │──Display to admin
  │<──PAIR_CODE──────────────────│
  │                               │
  │  [User gets code from admin]  │
  │                               │
  │──PAIR_CONFIRM───────────────>│
  │  (code)                      │──Verify code
  │                               │──Verify fingerprint
  │<──PAIRED_OK──────────────────│──Register device
  │                               │
```

**Security Properties**:
- Code is one-time use
- Code expires after 5 minutes
- Requires physical access to admin console
- Device fingerprint binds pairing to specific device

---

## 5. Protocol Design

### 5.1 JSON-Based Protocol

**Old Approach (Vulnerable)**:
```python
# Text-based with | separator
command = f"UPLOAD|{filename}|{size}|{hash}"
parts = command.split("|")  # Breaks if filename contains "|"
```

**New Approach (Secure)**:
```python
# JSON with length prefix
def send_message(sock, data):
    message = json.dumps(data).encode('utf-8')
    length = len(message).to_bytes(4, 'big')
    sock.send(length + message)

def recv_message(sock):
    length_bytes = sock.recv(4)
    length = int.from_bytes(length_bytes, 'big')
    message = sock.recv(length)
    return json.loads(message.decode('utf-8'))
```

**Benefits**:
- No parsing ambiguities
- Type safety (numbers, booleans, arrays)
- Extensible (add new fields without breaking old clients)
- Safe against injection (no string splitting)

### 5.2 Message Types

| Type | Direction | Purpose |
|------|-----------|---------|
| `PAIR_REQUEST` | Client → Server | Initiate pairing |
| `PAIR_CODE` | Server → Client | Send pairing code |
| `PAIR_CONFIRM` | Client → Server | Confirm code |
| `PAIRED_OK` | Server → Client | Pairing success |
| `CODE_LOGIN` | Client → Server | Login with code |
| `LOGIN_OK` | Server → Client | Login success |
| `UPLOAD` | Client → Server | Start file upload |
| `DOWNLOAD` | Client → Server | Request file download |
| `FILE_META` | Server → Client | File metadata |
| `FILE_OK` | Server → Client | Upload success |
| `FILE_LIST` | Server → Client | List of files |
| `USER_LIST` | Server → Client | Connected users |
| `STATS` | Server → Client | User statistics |
| `ERROR` | Server → Client | Error message |
| `QUIT` | Client → Server | Disconnect |

---

## 6. Data Flow Examples

### 6.1 File Upload Flow

```
1. Client sends: {"type": "UPLOAD", "filename": "photo.jpg", "size": 1048576, "sha256": "abc123..."}
   │
2. Server validates filename (InputValidator.validate_filename)
   │
3. Server creates Transaction record
   │
4. Server updates Connection state to TRANSFERRING
   │
5. Client sends file data in 4KB chunks
   │  └─> Server writes to disk
   │  └─> Server updates Transaction progress
   │
6. After all chunks received:
   │  └─> Server calculates SHA256 of saved file
   │  └─> Compares with client-provided hash
   │
7a. If match: Send FILE_OK, update stats, mark transaction COMPLETED
7b. If mismatch: Send FILE_CORRUPTED, mark transaction FAILED
   │
8. Server clears transaction from Connection
   │
9. Connection state returns to IDLE
```

### 6.2 Authentication Flow (Code Login)

```
1. Client sends: {"type": "CODE_LOGIN", "username": "sleep", "code": "12345678", "device_fingerprint": "xyz..."}
   │
2. Server checks RateLimiter
   │  └─> If exceeded: silent close, log RATE_LIMITED
   │
3. Server checks MAC ban
   │  └─> If banned: silent close, log BANNED_DEVICE
   │
4. Server validates username format
   │  └─> If invalid: silent close, log INVALID_USERNAME
   │
5. Server checks user ban
   │  └─> If banned: silent close, log BANNED_USER
   │
6. Server verifies pairing code
   │  └─> If invalid/expired: silent close, log INVALID_CODE
   │
7. Server verifies device fingerprint matches code request
   │  └─> If mismatch: silent close, log DEVICE_MISMATCH
   │
8. Server registers user/device in database
   │
9. Server creates Connection record
   │
10. Server sends: {"type": "LOGIN_OK", "username": "sleep"}
    │
11. Connection state set to IDLE
    │
12. Enter command loop
```

---

## 7. Common Vulnerabilities & Mitigations

### 7.1 Path Traversal

**Attack**:
```python
# Malicious filename
filename = "../../../etc/passwd"
save_path = os.path.join("shared_files", filename)
# Result: "shared_files/../../../etc/passwd" → writes to /etc/passwd!
```

**Mitigation**:
```python
def validate_filename(filename: str) -> Optional[str]:
    # Extract only the filename (removes all path components)
    filename = os.path.basename(filename)
    
    # Check for dangerous patterns
    if any(c in filename for c in ['/', '\\', '..', '\x00']):
        return None
    
    # Length check
    if len(filename) > 255 or len(filename) == 0:
        return None
    
    return filename
```

### 7.2 Command Injection

**Attack** (old text-based protocol):
```python
# Malicious filename
filename = "test\nQUIT\nUPLOAD|malicious|100|hash"
# Could inject commands into the protocol
```

**Mitigation**: JSON protocol treats everything as data, never as commands.

### 7.3 Subprocess Injection

**Attack**:
```python
ip_address = "8.8.8.8; rm -rf /"
subprocess.run(['ping', '-c', '1', ip_address])
# Executes: ping -c 1 8.8.8.8; rm -rf /
```

**Mitigation**:
```python
def validate_ip(ip_string: str) -> bool:
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

# Validate BEFORE using in subprocess
if not validate_ip(ip_address):
    return "unknown"
subprocess.run(['ping', '-c', '1', ip_address])
```

### 7.4 Brute Force

**Attack**: Try all possible pairing codes (10^8 combinations).

**Mitigation**:
- Rate Limiting: 5 attempts per minute per IP
- Code expiration: 5 minutes
- Silent close on failure (no information leakage)

---

## 8. Extension Guide

### 8.1 Adding a New Command

**Step 1**: Create command class
```python
class MyNewCommand(Command):
    def __init__(self, db, event_bus):
        self.db = db
        self.event_bus = event_bus
    
    def execute(self, client, data, context):
        # Your logic here
        JsonProtocol.send_message(client, {"type": "MY_RESPONSE", ...})
```

**Step 2**: Register in CommandFactory
```python
self.commands = {
    # ... existing commands
    "MY_COMMAND": MyNewCommand(self.db, self.event_bus),
}
```

**Step 3**: Use in client
```python
JsonProtocol.send_message(sock, {"type": "MY_COMMAND", "param": "value"})
response = JsonProtocol.recv_message(sock)
```

### 8.2 Adding a New Event

**Step 1**: Publish the event
```python
self.event_bus.publish('my_event', {'data': 'value'})
```

**Step 2**: Subscribe to it
```python
self.event_bus.subscribe('my_event', self._handle_my_event)

def _handle_my_event(self, data):
    # Handle the event
    pass
```

### 8.3 Adding a New Database Table

**Step 1**: Add to `_create_tables`
```python
CREATE TABLE IF NOT EXISTS my_table (
    id INTEGER PRIMARY KEY,
    data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Step 2**: Add accessor methods
```python
def get_my_data(self, id):
    with self.db_lock:
        self.cursor.execute('SELECT * FROM my_table WHERE id = ?', (id,))
        return self.cursor.fetchone()
```

---

## 9. Performance Considerations

### 9.1 Threading Model

- **Main thread**: Accepts new connections
- **Per-client thread**: Handles client communication
- **Admin CLI thread**: Handles admin commands
- **Heartbeat thread**: Monitors connection health
- **Discovery thread**: Broadcasts server presence

### 9.2 Database Performance

- All queries use indexed columns (PRIMARY KEY, UNIQUE)
- Thread-safe access via `db_lock`
- Consider WAL mode for better concurrent read performance:
  ```python
  self.cursor.execute('PRAGMA journal_mode=WAL')
  ```

### 9.3 Memory Management

- Connections are cleaned up automatically by HeartbeatMonitor
- Large files are streamed (not loaded entirely into memory)
- Chunk size: 4096 bytes (balances memory usage vs. network efficiency)

---

## 10. Troubleshooting

### 10.1 Common Issues

**Issue**: "Connection refused"
- **Cause**: Server not running or wrong port
- **Solution**: Check server output for actual port number

**Issue**: "Wrong password"
- **Cause**: Password changes on each server restart
- **Solution**: Copy password from server console

**Issue**: "Pairing code expired"
- **Cause**: Code valid for only 5 minutes
- **Solution**: Request new code from admin

**Issue**: "Max connections reached"
- **Cause**: Too many concurrent clients
- **Solution**: Increase `max_clients` in CONFIG

### 10.2 Debugging Tips

1. **Enable DEBUG logging**:
   ```python
   CONFIG["logging"]["level"] = "DEBUG"
   ```

2. **Check security logs**:
   ```bash
   [Admin] >>> security
   ```

3. **Monitor connections**:
   ```bash
   [Admin] >>> connections
   ```

4. **View active transactions**:
   ```bash
   [Admin] >>> transactions
   ```

---

## 11. Future Improvements

Potential enhancements (not yet implemented):

1. **Resumable Transfers**: Save progress and resume after disconnection
2. **File Compression**: Use gzip for large files
3. **Web Dashboard**: Browser-based admin interface
4. **Push Notifications**: Alert clients when files are available
5. **Bandwidth Throttling**: Limit transfer speeds
6. **File Versioning**: Keep history of file changes
7. **Encrypted File Storage**: Encrypt files at rest
8. **Multi-factor Authentication**: Add TOTP support

---

## 12. References

### Projects That Inspired Julian

- **Magic Wormhole**: SPAKE2 protocol for secure pairing
- **croc**: Rate limiting and relay server design
- **LocalSend**: Service discovery and REST API
- **Syncthing**: Device ID system and mutual authentication
- **OnionShare**: Ephemeral services and stealth mode

### Security Standards Followed

- **TLS 1.3** (RFC 8446): Transport layer security
- **SHA-256** (FIPS 180-4): File integrity verification
- **OWASP Top 10**: Web application security guidelines
- **NIST SP 800-52**: TLS implementation guidelines

---

## Conclusion

Julian demonstrates how to build a secure, production-ready file transfer system by:

1. **Learning from the best**: Applying patterns from established open-source projects
2. **Defense in depth**: Multiple security layers protect against various attack vectors
3. **Clean architecture**: Design patterns make the code maintainable and extensible
4. **Thread safety**: Proper synchronization prevents race conditions
5. **Fail-safe defaults**: Silent drops and input validation prevent common exploits

This architecture serves as a foundation for learning advanced software engineering concepts while building something practical and secure.

---

**Document Version**: 1.0.0  
**Last Updated**: 2026-10-01  
**Author**: Julian Project Team
