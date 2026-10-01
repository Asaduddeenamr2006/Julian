"""
Julian Server - Secure File Transfer System v4.0.0
==================================================

A production-ready, security-hardened file transfer server with advanced
connection management, transaction tracking, and heartbeat monitoring.

New in v4.0.0:
--------------
- Resume Transfers (continue interrupted uploads/downloads)
- File Management (delete, rename, search with wildcards)
- Server Fingerprint (Safety Numbers for spoofing protection)
- Admin Code Generation (generate login codes for registered users)
- Enhanced security with all previous features

Architecture Overview:
----------------------
1. ConnectionManager: Tracks all client connections with state management
2. TransactionManager: Manages file transfers with progress tracking
3. HeartbeatMonitor: Detects zombie connections and cleans up resources
4. EventBus (Observer Pattern): Decouples logging from business logic
5. Command Pattern: Modular command handling for extensibility
6. Singleton Pattern: Single database connection across all threads
7. Factory Pattern: Centralized command instantiation

Security Features:
------------------
- TLS 1.3 encryption
- JSON-based protocol (prevents command injection)
- Rate limiting (prevents brute force attacks)
- Stealth mode (silent drop for unauthorized attempts)
- Input validation and sanitization
- MAC-based device banning
- Pairing authentication with physical verification
- Strong device fingerprinting (UUID + Machine ID)
- Safety Numbers for server identity verification
- Admin code generation for returning users

Design Patterns Applied:
------------------------
- Singleton: DatabaseManager (single connection instance)
- Observer: EventBus (event-driven logging)
- Command: UploadCommand, DownloadCommand, DeleteCommand, etc.
- Factory: CommandFactory (command instantiation)
- Strategy: Connection states (authenticating, idle, transferring)

Author: Julian Project
License: MIT
Version: 4.0.0
"""

import socket
import hashlib
import os
import random
import string
import logging
import threading
import time
import sqlite3
import ssl
import subprocess
import re
import uuid
import json
import ipaddress
import fnmatch
from dataclasses import dataclass, field
from typing import Dict, List, Callable, Optional, Any
from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path
from enum import Enum


# ============================================================================
# CONFIGURATION
# ============================================================================
# Centralized configuration for easy customization

CONFIG = {
    "server": {
        "host": "0.0.0.0",
        "port": 0,  # 0 = random port (10000-60000)
        "shared_folder": "shared_files",
        "max_clients": 10,
        "max_file_size_mb": 0,  # 0 = unlimited
    },
    "security": {
        "auth_timeout": 5,  # seconds before stealth close
        "code_length": 8,  # pairing code digits
        "code_expiry": 300,  # seconds before code expires
        "password_length": 12,  # server password length
        "tls_enabled": True,
        "cert_file": "server.crt",
        "key_file": "server.key",
        "cert_days": 365,
        "max_auth_attempts": 5,  # rate limiting
        "rate_limit_window": 60,  # seconds
    },
    "database": {
        "path": "system.db",
    },
    "logging": {
        "file": "server_logs.txt",
        "level": "INFO",
        "format": "%(asctime)s | %(levelname)s | %(message)s",
    },
    "discovery": {
        "enabled": True,
        "broadcast_port": 37020,
        "interval": 5,  # seconds between broadcasts
    },
    "connections": {
        "heartbeat_interval": 30,  # seconds between heartbeats
        "heartbeat_timeout": 90,  # seconds before considering connection dead
        "idle_timeout": 300,  # seconds before closing idle connection
        "cleanup_interval": 60,  # seconds between cleanup cycles
    },
}


# ============================================================================
# ENUMS (Type Safety)
# ============================================================================

class ConnectionState(Enum):
    """
    Represents the state of a client connection.
    Using Enum ensures type safety and prevents invalid states.
    """
    AUTHENTICATING = "authenticating"  # Initial auth phase
    IDLE = "idle"                      # Connected but not transferring
    TRANSFERRING = "transferring"      # Active file transfer
    CLOSING = "closing"                # Graceful shutdown in progress


class TransactionStatus(Enum):
    """
    Represents the status of a file transfer transaction.
    """
    PENDING = "pending"                # Transaction created but not started
    IN_PROGRESS = "in_progress"        # Transfer actively happening
    COMPLETED = "completed"            # Transfer finished successfully
    FAILED = "failed"                  # Transfer failed
    CANCELLED = "cancelled"            # Transfer cancelled by user


# ============================================================================
# DESIGN PATTERN: Observer (Event Bus)
# ============================================================================

class EventBus:
    """
    Observer Pattern implementation for event-driven architecture.
    
    Purpose:
    --------
    Decouples business logic from side effects (logging, notifications).
    Components can subscribe to events without knowing who publishes them.
    
    Thread Safety:
    --------------
    Uses threading.Lock to protect subscriber list from race conditions.
    """
    
    def __init__(self):
        # Dictionary mapping event types to list of callback functions
        self._subscribers: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()
    
    def subscribe(self, event_type: str, callback: Callable) -> None:
        """Subscribe a callback function to a specific event type."""
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(callback)
    
    def publish(self, event_type: str, data: dict = None) -> None:
        """Publish an event to all subscribers."""
        # Copy subscriber list to avoid holding lock during callbacks
        with self._lock:
            subscribers = self._subscribers.get(event_type, []).copy()
        
        # Call each subscriber (outside lock to prevent deadlocks)
        for callback in subscribers:
            try:
                callback(data or {})
            except Exception as e:
                logging.error(f"Event handler error for {event_type}: {e}")


# ============================================================================
# DESIGN PATTERN: Singleton (Database Manager)
# ============================================================================

class DatabaseManager:
    """
    Singleton Pattern implementation for database connection management.
    
    Purpose:
    --------
    Ensures only ONE database connection exists across all threads.
    Prevents connection leaks and ensures thread-safe operations.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, db_name: str = None):
        """Override __new__ to implement Singleton pattern."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self, db_name: str = None):
        """Initialize database connection and create tables."""
        if self._initialized:
            return
        
        db_name = db_name or CONFIG["database"]["path"]
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.db_lock = threading.Lock()
        self._create_tables()
        self._initialized = True
    
    def _create_tables(self) -> None:
        """Create all required database tables."""
        with self.db_lock:
            self.cursor.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    ip_address TEXT,
                    mac_address TEXT,
                    device_fingerprint TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS stats (
                    username TEXT PRIMARY KEY,
                    uploaded_bytes INTEGER DEFAULT 0,
                    downloaded_bytes INTEGER DEFAULT 0,
                    files_sent INTEGER DEFAULT 0,
                    files_received INTEGER DEFAULT 0
                );
                
                CREATE TABLE IF NOT EXISTS transfer_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT,
                    receiver TEXT,
                    filename TEXT,
                    size INTEGER,
                    status TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS device_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    mac_address TEXT,
                    username TEXT,
                    device_fingerprint TEXT,
                    os_info TEXT,
                    distribution TEXT,
                    device_type TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ip_address, username)
                );
                
                CREATE TABLE IF NOT EXISTS banned_users (
                    username TEXT PRIMARY KEY,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT DEFAULT 'No reason provided'
                );
                
                CREATE TABLE IF NOT EXISTS banned_macs (
                    mac_address TEXT PRIMARY KEY,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT DEFAULT 'No reason provided'
                );
                
                CREATE TABLE IF NOT EXISTS pairing_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    code TEXT UNIQUE,
                    ip_address TEXT,
                    device_fingerprint TEXT,
                    device_info TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    used BOOLEAN DEFAULT 0
                );
                
                CREATE TABLE IF NOT EXISTS security_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    mac_address TEXT,
                    attempt_type TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS transactions (
                    id TEXT PRIMARY KEY,
                    connection_id TEXT,
                    username TEXT,
                    type TEXT,
                    filename TEXT,
                    size INTEGER,
                    status TEXT,
                    bytes_transferred INTEGER DEFAULT 0,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP
                );
            ''')
            self.conn.commit()
    
    # --- User Management ---
    
    def register_user(self, username: str, ip: str, mac: str = "unknown", 
                      fingerprint: str = "unknown") -> None:
        """Register a new user or update existing user's last seen time."""
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO users (username, ip_address, mac_address, device_fingerprint, last_seen) 
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(username) DO UPDATE SET 
                    ip_address=excluded.ip_address, 
                    mac_address=excluded.mac_address,
                    device_fingerprint=excluded.device_fingerprint,
                    last_seen=CURRENT_TIMESTAMP
            ''', (username, ip, mac, fingerprint))
            self.cursor.execute('INSERT OR IGNORE INTO stats (username) VALUES (?)', (username,))
            self.conn.commit()
    
    def register_device(self, ip: str, mac: str, username: str, fingerprint: str,
                        os_info: str, distribution: str, device_type: str) -> None:
        """Register or update device session information."""
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO device_sessions (ip_address, mac_address, username, device_fingerprint,
                    os_info, distribution, device_type, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(ip_address, username) DO UPDATE SET 
                    mac_address=excluded.mac_address,
                    device_fingerprint=excluded.device_fingerprint,
                    os_info=excluded.os_info, distribution=excluded.distribution,
                    device_type=excluded.device_type, last_seen=CURRENT_TIMESTAMP
            ''', (ip, mac, username, fingerprint, os_info, distribution, device_type))
            self.conn.commit()
    
    def update_stats(self, username: str, uploaded: int = 0, downloaded: int = 0,
                     files_sent: int = 0, files_received: int = 0) -> None:
        """Update user statistics atomically."""
        with self.db_lock:
            self.cursor.execute('''
                UPDATE stats 
                SET uploaded_bytes = MAX(0, uploaded_bytes + ?), 
                    downloaded_bytes = MAX(0, downloaded_bytes + ?),
                    files_sent = MAX(0, files_sent + ?), 
                    files_received = MAX(0, files_received + ?)
                WHERE username = ?
            ''', (uploaded, downloaded, files_sent, files_received, username))
            self.conn.commit()
    
    def get_stats(self, username: str) -> Optional[dict]:
        """Retrieve user statistics."""
        with self.db_lock:
            self.cursor.execute('SELECT * FROM stats WHERE username = ?', (username,))
            row = self.cursor.fetchone()
            if row:
                return {'uploaded': row[1], 'downloaded': row[2],
                        'files_sent': row[3], 'files_received': row[4]}
            return None
    
    def log_transfer(self, sender: str, receiver: str, filename: str, 
                     size: int, status: str) -> None:
        """Log a file transfer operation."""
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO transfer_logs (sender, receiver, filename, size, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (sender, receiver, filename, size, status))
            self.conn.commit()
    
    # --- Ban Management ---
    
    def is_user_banned(self, username: str) -> bool:
        """Check if a username is banned."""
        with self.db_lock:
            self.cursor.execute('SELECT 1 FROM banned_users WHERE username = ?', (username,))
            return self.cursor.fetchone() is not None
    
    def ban_user(self, username: str, reason: str = "No reason provided") -> None:
        """Ban a user with optional reason."""
        with self.db_lock:
            self.cursor.execute('''
                INSERT OR REPLACE INTO banned_users (username, reason, banned_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (username, reason))
            self.conn.commit()
    
    def unban_user(self, username: str) -> bool:
        """Unban a user. Returns True if user was banned."""
        with self.db_lock:
            self.cursor.execute('DELETE FROM banned_users WHERE username = ?', (username,))
            self.conn.commit()
            return self.cursor.rowcount > 0
    
    def get_banned_users(self) -> list:
        """Get list of all banned users."""
        with self.db_lock:
            self.cursor.execute('SELECT username, banned_at, reason FROM banned_users ORDER BY banned_at DESC')
            return self.cursor.fetchall()
    
    def is_mac_banned(self, mac_address: str) -> bool:
        """Check if a MAC address is banned."""
        if mac_address == "unknown":
            return False
        with self.db_lock:
            self.cursor.execute('SELECT 1 FROM banned_macs WHERE mac_address = ?', (mac_address,))
            return self.cursor.fetchone() is not None
    
    def ban_mac(self, mac_address: str, reason: str = "No reason provided") -> None:
        """Ban a device by MAC address."""
        with self.db_lock:
            self.cursor.execute('''
                INSERT OR REPLACE INTO banned_macs (mac_address, reason, banned_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (mac_address, reason))
            self.conn.commit()
    
    def unban_mac(self, mac_address: str) -> bool:
        """Unban a MAC address. Returns True if MAC was banned."""
        with self.db_lock:
            self.cursor.execute('DELETE FROM banned_macs WHERE mac_address = ?', (mac_address,))
            self.conn.commit()
            return self.cursor.rowcount > 0
    
    def get_banned_macs(self) -> list:
        """Get list of all banned MAC addresses."""
        with self.db_lock:
            self.cursor.execute('SELECT mac_address, banned_at, reason FROM banned_macs ORDER BY banned_at DESC')
            return self.cursor.fetchall()
    
    # --- Pairing System ---
    
    def create_pairing_request(self, username: str, ip: str, device_fingerprint: str,
                                device_info: str) -> str:
        """Create a new pairing request and return the verification code."""
        code_length = CONFIG["security"]["code_length"]
        code = ''.join([str(random.randint(0, 9)) for _ in range(code_length)])
        
        code_expiry = CONFIG["security"]["code_expiry"]
        expires_at = time.strftime('%Y-%m-%d %H:%M:%S', 
                                    time.localtime(time.time() + code_expiry))
        
        with self.db_lock:
            # Remove any existing pending requests for this device
            self.cursor.execute('''
                DELETE FROM pairing_requests 
                WHERE device_fingerprint = ? AND used = 0
            ''', (device_fingerprint,))
            
            self.cursor.execute('''
                INSERT INTO pairing_requests 
                (username, code, ip_address, device_fingerprint, device_info, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, code, ip, device_fingerprint, device_info, expires_at))
            self.conn.commit()
        
        return code
    
    def verify_pairing_code(self, code: str) -> Optional[dict]:
        """Verify a pairing code and return request info if valid."""
        with self.db_lock:
            self.cursor.execute('''
                SELECT username, ip_address, device_fingerprint, device_info, expires_at
                FROM pairing_requests 
                WHERE code = ? AND used = 0
            ''', (code,))
            row = self.cursor.fetchone()
            
            if not row:
                return None
            
            # Check expiration
            expires_at = time.strptime(row[4], '%Y-%m-%d %H:%M:%S')
            if time.localtime() > expires_at:
                return None
            
            # Mark as used
            self.cursor.execute('UPDATE pairing_requests SET used = 1 WHERE code = ?', (code,))
            self.conn.commit()
            
            return {
                'username': row[0],
                'ip': row[1],
                'device_fingerprint': row[2],
                'device_info': row[3]
            }
    
    def get_pending_pairing_requests(self) -> list:
        """Get all pending (unused and not expired) pairing requests."""
        with self.db_lock:
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute('''
                SELECT username, code, ip_address, device_fingerprint, device_info, expires_at
                FROM pairing_requests 
                WHERE used = 0 AND expires_at > ?
                ORDER BY created_at DESC
            ''', (now,))
            return self.cursor.fetchall()
    
    # --- Transaction Management ---
    
    def create_transaction(self, transaction_id: str, connection_id: str, 
                           username: str, tx_type: str, filename: str, size: int) -> None:
        """Create a new transaction record."""
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO transactions (id, connection_id, username, type, filename, size, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (transaction_id, connection_id, username, tx_type, filename, size, 
                  TransactionStatus.PENDING.value))
            self.conn.commit()
    
    def update_transaction_progress(self, transaction_id: str, bytes_transferred: int) -> None:
        """Update transaction progress."""
        with self.db_lock:
            self.cursor.execute('''
                UPDATE transactions 
                SET bytes_transferred = ?, status = ?
                WHERE id = ?
            ''', (bytes_transferred, TransactionStatus.IN_PROGRESS.value, transaction_id))
            self.conn.commit()
    
    def complete_transaction(self, transaction_id: str, status: str) -> None:
        """Mark transaction as completed or failed."""
        with self.db_lock:
            self.cursor.execute('''
                UPDATE transactions 
                SET status = ?, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (status, transaction_id))
            self.conn.commit()
    
    def get_transaction(self, transaction_id: str) -> Optional[dict]:
        """Get transaction details."""
        with self.db_lock:
            self.cursor.execute('SELECT * FROM transactions WHERE id = ?', (transaction_id,))
            row = self.cursor.fetchone()
            if row:
                return {
                    'id': row[0], 'connection_id': row[1], 'username': row[2],
                    'type': row[3], 'filename': row[4], 'size': row[5],
                    'status': row[6], 'bytes_transferred': row[7],
                    'started_at': row[8], 'completed_at': row[9]
                }
            return None
    
    # --- Security Logs ---
    
    def log_security_event(self, ip: str, mac: str, attempt_type: str, 
                           details: str) -> None:
        """Log a security event."""
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO security_logs (ip_address, mac_address, attempt_type, details)
                VALUES (?, ?, ?, ?)
            ''', (ip, mac, attempt_type, details))
            self.conn.commit()
    
    def get_security_logs(self, limit: int = 50) -> list:
        """Get recent security logs."""
        with self.db_lock:
            self.cursor.execute('''
                SELECT ip_address, mac_address, attempt_type, details, timestamp
                FROM security_logs ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return self.cursor.fetchall()
    
    # --- Query Methods ---
    
    def get_all_users(self) -> list:
        """Get all registered users."""
        with self.db_lock:
            self.cursor.execute('''
                SELECT username, ip_address, mac_address, device_fingerprint, first_seen, last_seen 
                FROM users ORDER BY last_seen DESC
            ''')
            return self.cursor.fetchall()
    
    def get_all_devices(self) -> list:
        """Get all device sessions."""
        with self.db_lock:
            self.cursor.execute('''
                SELECT ip_address, mac_address, username, device_fingerprint, os_info, 
                       distribution, device_type, last_seen 
                FROM device_sessions ORDER BY last_seen DESC
            ''')
            return self.cursor.fetchall()
    
    def get_user_info(self, username: str) -> Optional[dict]:
        """
        Get detailed user information by username.
        
        Returns:
            Dictionary with user info or None if not found
        """
        with self.db_lock:
            self.cursor.execute('''
                SELECT username, ip_address, mac_address, device_fingerprint, first_seen, last_seen 
                FROM users WHERE username = ?
            ''', (username,))
            row = self.cursor.fetchone()
            
            if row:
                return {
                    'username': row[0],
                    'ip': row[1],
                    'mac': row[2],
                    'fingerprint': row[3],
                    'first_seen': row[4],
                    'last_seen': row[5]
                }
            return None


# ============================================================================
# CONNECTION MANAGEMENT
# ============================================================================

@dataclass
class Connection:
    """Represents a single client connection with state tracking."""
    id: str
    username: str
    socket: socket.socket
    address: tuple
    state: ConnectionState = ConnectionState.AUTHENTICATING
    current_transaction: Optional[str] = None
    last_activity: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0
    mac_address: str = "unknown"
    device_fingerprint: str = ""


class ConnectionManager:
    """
    Manages all client connections with thread-safe operations.
    
    Responsibilities:
    -----------------
    1. Track all active connections
    2. Manage connection states
    3. Provide connection lookup by ID or username
    4. Track connection statistics
    5. Detect and clean up zombie connections
    """
    
    def __init__(self, max_connections: int = None):
        self.max_connections = max_connections or CONFIG["server"]["max_clients"]
        self._connections: Dict[str, Connection] = {}
        self._lock = threading.Lock()
        self._start_time = time.time()
    
    def register(self, username: str, client_socket: socket.socket, 
                 address: tuple, mac_address: str = "unknown",
                 device_fingerprint: str = "") -> Optional[Connection]:
        """Register a new connection."""
        with self._lock:
            if len(self._connections) >= self.max_connections:
                logging.warning(f"Max connections reached ({self.max_connections})")
                return None
            
            for conn in self._connections.values():
                if conn.username == username:
                    logging.warning(f"Username '{username}' already connected")
                    return None
            
            connection_id = str(uuid.uuid4())
            connection = Connection(
                id=connection_id,
                username=username,
                socket=client_socket,
                address=address,
                mac_address=mac_address,
                device_fingerprint=device_fingerprint
            )
            
            self._connections[connection_id] = connection
            logging.info(f"Connection registered: {connection_id} for user '{username}'")
            
            return connection
    
    def unregister(self, connection_id: str) -> None:
        """Remove a connection from tracking."""
        with self._lock:
            if connection_id in self._connections:
                conn = self._connections[connection_id]
                del self._connections[connection_id]
                logging.info(f"Connection unregistered: {connection_id}")
    
    def get_connection(self, connection_id: str) -> Optional[Connection]:
        """Get a connection by ID."""
        with self._lock:
            return self._connections.get(connection_id)
    
    def get_by_username(self, username: str) -> Optional[Connection]:
        """Get a connection by username."""
        with self._lock:
            for conn in self._connections.values():
                if conn.username == username:
                    return conn
            return None
    
    def update_state(self, connection_id: str, state: ConnectionState) -> None:
        """Update connection state."""
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].state = state
                self._connections[connection_id].last_activity = time.time()
    
    def set_current_transaction(self, connection_id: str, transaction_id: str) -> None:
        """Associate a transaction with a connection."""
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].current_transaction = transaction_id
                self._connections[connection_id].state = ConnectionState.TRANSFERRING
    
    def clear_current_transaction(self, connection_id: str) -> None:
        """Clear current transaction from connection."""
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].current_transaction = None
                self._connections[connection_id].state = ConnectionState.IDLE
    
    def update_activity(self, connection_id: str) -> None:
        """Update last activity timestamp."""
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].last_activity = time.time()
    
    def update_bytes(self, connection_id: str, sent: int = 0, received: int = 0) -> None:
        """Update byte counters for a connection."""
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].bytes_sent += sent
                self._connections[connection_id].bytes_received += received
    
    def get_all_connections(self) -> List[Connection]:
        """Get list of all active connections."""
        with self._lock:
            return list(self._connections.values())
    
    def get_idle_connections(self, timeout: int = None) -> List[Connection]:
        """Get connections that have been idle for longer than timeout."""
        timeout = timeout or CONFIG["connections"]["idle_timeout"]
        now = time.time()
        
        with self._lock:
            idle = []
            for conn in self._connections.values():
                if conn.state == ConnectionState.IDLE:
                    if now - conn.last_activity > timeout:
                        idle.append(conn)
            return idle
    
    def get_zombie_connections(self, timeout: int = None) -> List[Connection]:
        """Get connections that appear to be dead."""
        timeout = timeout or CONFIG["connections"]["heartbeat_timeout"]
        now = time.time()
        
        with self._lock:
            zombies = []
            for conn in self._connections.values():
                if now - conn.last_activity > timeout:
                    zombies.append(conn)
            return zombies
    
    def get_stats(self) -> dict:
        """Get comprehensive connection statistics."""
        with self._lock:
            total = len(self._connections)
            active = sum(1 for c in self._connections.values() 
                        if c.state != ConnectionState.CLOSING)
            idle = sum(1 for c in self._connections.values() 
                      if c.state == ConnectionState.IDLE)
            transferring = sum(1 for c in self._connections.values() 
                              if c.state == ConnectionState.TRANSFERRING)
            total_sent = sum(c.bytes_sent for c in self._connections.values())
            total_received = sum(c.bytes_received for c in self._connections.values())
            uptime = time.time() - self._start_time
            
            return {
                'total_connections': total,
                'max_connections': self.max_connections,
                'active': active,
                'idle': idle,
                'transferring': transferring,
                'total_bytes_sent': total_sent,
                'total_bytes_received': total_received,
                'uptime': uptime
            }
    
    def cleanup(self) -> int:
        """Clean up zombie connections."""
        zombies = self.get_zombie_connections()
        cleaned = 0
        
        for conn in zombies:
            try:
                conn.socket.close()
            except Exception:
                pass
            self.unregister(conn.id)
            cleaned += 1
            logging.warning(f"Cleaned up zombie connection: {conn.id}")
        
        return cleaned


# ============================================================================
# TRANSACTION MANAGEMENT
# ============================================================================

@dataclass
class Transaction:
    """Represents a file transfer transaction with progress tracking."""
    id: str
    connection_id: str
    username: str
    type: str
    filename: str
    size: int
    status: TransactionStatus = TransactionStatus.PENDING
    bytes_transferred: int = 0
    started_at: float = field(default_factory=time.time)
    
    @property
    def progress_percent(self) -> float:
        """Calculate progress percentage."""
        if self.size == 0:
            return 0.0
        return (self.bytes_transferred / self.size) * 100


class TransactionManager:
    """Manages file transfer transactions with progress tracking."""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
        self._transactions: Dict[str, Transaction] = {}
        self._lock = threading.Lock()
    
    def create_transaction(self, connection_id: str, username: str, 
                           tx_type: str, filename: str, size: int) -> Transaction:
        """Create a new transaction."""
        transaction_id = str(uuid.uuid4())
        
        transaction = Transaction(
            id=transaction_id,
            connection_id=connection_id,
            username=username,
            type=tx_type,
            filename=filename,
            size=size
        )
        
        with self._lock:
            self._transactions[transaction_id] = transaction
        
        self.db.create_transaction(
            transaction_id, connection_id, username, tx_type, filename, size
        )
        
        logging.info(f"Transaction created: {transaction_id} ({tx_type}: {filename})")
        
        return transaction
    
    def get_transaction(self, transaction_id: str) -> Optional[Transaction]:
        """Get a transaction by ID."""
        with self._lock:
            return self._transactions.get(transaction_id)
    
    def update_progress(self, transaction_id: str, bytes_transferred: int) -> None:
        """Update transaction progress."""
        with self._lock:
            if transaction_id in self._transactions:
                self._transactions[transaction_id].bytes_transferred = bytes_transferred
        
        self.db.update_transaction_progress(transaction_id, bytes_transferred)
    
    def complete_transaction(self, transaction_id: str, success: bool = True) -> None:
        """Mark transaction as completed."""
        status = TransactionStatus.COMPLETED if success else TransactionStatus.FAILED
        
        with self._lock:
            if transaction_id in self._transactions:
                self._transactions[transaction_id].status = status
        
        self.db.complete_transaction(transaction_id, status.value)
        logging.info(f"Transaction {transaction_id} {status.value}")
    
    def get_active_transactions(self) -> List[Transaction]:
        """Get all active (in-progress) transactions."""
        with self._lock:
            return [t for t in self._transactions.values() 
                    if t.status == TransactionStatus.IN_PROGRESS]
    
    def get_stats(self) -> dict:
        """Get transaction statistics."""
        with self._lock:
            total = len(self._transactions)
            active = sum(1 for t in self._transactions.values() 
                        if t.status == TransactionStatus.IN_PROGRESS)
            completed = sum(1 for t in self._transactions.values() 
                           if t.status == TransactionStatus.COMPLETED)
            failed = sum(1 for t in self._transactions.values() 
                        if t.status == TransactionStatus.FAILED)
            
            return {
                'total': total,
                'active': active,
                'completed': completed,
                'failed': failed
            }


# ============================================================================
# HEARTBEAT MONITOR
# ============================================================================

class HeartbeatMonitor:
    """Monitors connection health and cleans up dead connections."""
    
    def __init__(self, connection_manager: ConnectionManager):
        self.connection_manager = connection_manager
        self.running = False
        self.thread = None
    
    def start(self) -> None:
        """Start the heartbeat monitor thread."""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logging.info("Heartbeat monitor started")
    
    def stop(self) -> None:
        """Stop the heartbeat monitor thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logging.info("Heartbeat monitor stopped")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        interval = CONFIG["connections"]["heartbeat_interval"]
        cleanup_interval = CONFIG["connections"]["cleanup_interval"]
        last_cleanup = time.time()
        
        while self.running:
            try:
                zombies = self.connection_manager.get_zombie_connections()
                if zombies:
                    logging.warning(f"Detected {len(zombies)} zombie connections")
                
                now = time.time()
                if now - last_cleanup > cleanup_interval:
                    cleaned = self.connection_manager.cleanup()
                    if cleaned > 0:
                        logging.info(f"Cleaned up {cleaned} zombie connections")
                    last_cleanup = now
                
                time.sleep(interval)
            
            except Exception as e:
                logging.error(f"Heartbeat monitor error: {e}")
                time.sleep(interval)


# ============================================================================
# RATE LIMITER
# ============================================================================

class RateLimiter:
    """Prevents brute force attacks by limiting connection attempts."""
    
    def __init__(self, max_attempts: int = None, window_seconds: int = None):
        self.max_attempts = max_attempts or CONFIG["security"]["max_auth_attempts"]
        self.window = window_seconds or CONFIG["security"]["rate_limit_window"]
        self.attempts = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> bool:
        """Check if IP is allowed to connect."""
        now = time.time()
        
        with self.lock:
            self.attempts[ip] = [
                t for t in self.attempts[ip] 
                if now - t < self.window
            ]
            
            if len(self.attempts[ip]) >= self.max_attempts:
                return False
            
            self.attempts[ip].append(now)
            return True
    
    def get_remaining_attempts(self, ip: str) -> int:
        """Get remaining attempts for IP."""
        now = time.time()
        with self.lock:
            self.attempts[ip] = [
                t for t in self.attempts[ip] 
                if now - t < self.window
            ]
            return max(0, self.max_attempts - len(self.attempts[ip]))
    
    def reset(self, ip: str = None):
        """Reset attempts for IP or all IPs."""
        with self.lock:
            if ip:
                self.attempts.pop(ip, None)
            else:
                self.attempts.clear()


# ============================================================================
# INPUT VALIDATOR
# ============================================================================

class InputValidator:
    """Validates all inputs to prevent injection attacks."""
    
    @staticmethod
    def validate_ip(ip_string: str) -> bool:
        """Validate IP address strictly."""
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_filename(filename: str) -> Optional[str]:
        """Validate filename to prevent path traversal."""
        filename = os.path.basename(filename)
        
        if any(c in filename for c in ['/', '\\', '..', '\x00']):
            return None
        
        if len(filename) > 255 or len(filename) == 0:
            return None
        
        return filename
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number."""
        try:
            port = int(port)
            return 1 <= port <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username."""
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False
        
        if not (3 <= len(username) <= 32):
            return False
        
        return True


# ============================================================================
# JSON PROTOCOL
# ============================================================================

class JsonProtocol:
    """JSON-based protocol with length prefix."""
    
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
# DESIGN PATTERN: Command
# ============================================================================

class Command(ABC):
    """Abstract base class for protocol commands."""
    
    @abstractmethod
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        pass


class UploadCommand(Command):
    """Handles file upload operations."""
    
    def __init__(self, event_bus: EventBus, db: DatabaseManager, 
                 shared_folder: str, transaction_manager: TransactionManager,
                 connection_manager: ConnectionManager):
        self.event_bus = event_bus
        self.db = db
        self.shared_folder = shared_folder
        self.transaction_manager = transaction_manager
        self.connection_manager = connection_manager
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        file_name = InputValidator.validate_filename(data.get('filename', ''))
        if not file_name:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid filename"})
            return
        
        file_size = data.get('size', 0)
        file_sha256 = data.get('sha256', '')
        username = context['username']
        connection_id = context['connection_id']
        
        max_size = CONFIG["server"]["max_file_size_mb"] * 1024 * 1024
        if max_size > 0 and file_size > max_size:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "File too large"})
            return
        
        transaction = self.transaction_manager.create_transaction(
            connection_id, username, 'upload', file_name, file_size
        )
        self.connection_manager.set_current_transaction(connection_id, transaction.id)
        
        save_path = os.path.join(self.shared_folder, file_name)
        
        received_size = 0
        try:
            with open(save_path, 'wb') as f:
                while received_size < file_size:
                    chunk_size = min(4096, file_size - received_size)
                    chunk = client.recv(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    received_size += len(chunk)
                    
                    self.transaction_manager.update_progress(transaction.id, received_size)
                    self.connection_manager.update_bytes(connection_id, received=received_size)
            
            if FileTransferUtils.calculate_sha256(save_path) == file_sha256:
                JsonProtocol.send_message(client, {"type": "FILE_OK"})
                self.db.update_stats(username, uploaded=file_size, files_received=1)
                self.db.log_transfer(username, "Server", file_name, file_size, "SUCCESS")
                self.transaction_manager.complete_transaction(transaction.id, success=True)
                self.event_bus.publish('file_uploaded', {
                    'username': username, 'filename': file_name, 'size': file_size
                })
            else:
                JsonProtocol.send_message(client, {"type": "FILE_CORRUPTED"})
                self.db.log_transfer(username, "Server", file_name, file_size, "CORRUPTED")
                self.transaction_manager.complete_transaction(transaction.id, success=False)
        
        except Exception as e:
            logging.error(f"Upload error: {e}")
            self.transaction_manager.complete_transaction(transaction.id, success=False)
        
        finally:
            self.connection_manager.clear_current_transaction(connection_id)


class DownloadCommand(Command):
    """Handles file download operations."""
    
    def __init__(self, event_bus: EventBus, db: DatabaseManager, 
                 shared_folder: str, transaction_manager: TransactionManager,
                 connection_manager: ConnectionManager):
        self.event_bus = event_bus
        self.db = db
        self.shared_folder = shared_folder
        self.transaction_manager = transaction_manager
        self.connection_manager = connection_manager
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        file_name = InputValidator.validate_filename(data.get('filename', ''))
        if not file_name:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid filename"})
            return
        
        file_path = os.path.join(self.shared_folder, file_name)
        username = context['username']
        connection_id = context['connection_id']
        
        if not os.path.isfile(file_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "File not found"})
            return
        
        file_size = os.path.getsize(file_path)
        file_sha256 = FileTransferUtils.calculate_sha256(file_path)
        
        transaction = self.transaction_manager.create_transaction(
            connection_id, username, 'download', file_name, file_size
        )
        self.connection_manager.set_current_transaction(connection_id, transaction.id)
        
        try:
            JsonProtocol.send_message(client, {
                "type": "FILE_META",
                "filename": file_name,
                "size": file_size,
                "sha256": file_sha256
            })
            
            ready_msg = JsonProtocol.recv_message(client)
            if not ready_msg or ready_msg.get('type') != 'READY':
                return
            
            sent_size = 0
            with open(file_path, 'rb') as f:
                while sent_size < file_size:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    client.send(chunk)
                    sent_size += len(chunk)
                    
                    self.transaction_manager.update_progress(transaction.id, sent_size)
                    self.connection_manager.update_bytes(connection_id, sent=sent_size)
            
            self.db.update_stats(username, downloaded=file_size, files_sent=1)
            self.db.log_transfer("Server", username, file_name, file_size, "SUCCESS")
            self.transaction_manager.complete_transaction(transaction.id, success=True)
            self.event_bus.publish('file_downloaded', {
                'username': username, 'filename': file_name, 'size': file_size
            })
        
        except Exception as e:
            logging.error(f"Download error: {e}")
            self.transaction_manager.complete_transaction(transaction.id, success=False)
        
        finally:
            self.connection_manager.clear_current_transaction(connection_id)


class ListCommand(Command):
    """Lists all available files on the server."""
    
    def __init__(self, shared_folder: str):
        self.shared_folder = shared_folder
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        files = []
        for f in os.listdir(self.shared_folder):
            full_path = os.path.join(self.shared_folder, f)
            if os.path.isfile(full_path):
                files.append({
                    "name": f,
                    "size": os.path.getsize(full_path)
                })
        
        JsonProtocol.send_message(client, {"type": "FILE_LIST", "files": files})


class UsersCommand(Command):
    """Returns list of currently connected users."""
    
    def __init__(self, connection_manager: ConnectionManager):
        self.connection_manager = connection_manager
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        connections = self.connection_manager.get_all_connections()
        
        if not connections:
            JsonProtocol.send_message(client, {"type": "USER_LIST", "users": []})
            return
        
        user_list = [
            {
                "username": c.username,
                "ip": c.address[0],
                "mac": c.mac_address,
                "state": c.state.value,
                "uptime": int(time.time() - c.created_at)
            }
            for c in connections
        ]
        
        JsonProtocol.send_message(client, {"type": "USER_LIST", "users": user_list})


class StatsCommand(Command):
    """Returns personal statistics for the requesting user."""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        username = context['username']
        stats = self.db.get_stats(username)
        
        if not stats:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "No stats found"})
            return
        
        JsonProtocol.send_message(client, {
            "type": "STATS",
            "username": username,
            "uploaded": stats['uploaded'],
            "downloaded": stats['downloaded'],
            "files_sent": stats['files_sent'],
            "files_received": stats['files_received']
        })


class QuitCommand(Command):
    """Handles graceful client disconnection."""
    
    def __init__(self, event_bus: EventBus, connection_manager: ConnectionManager):
        self.event_bus = event_bus
        self.connection_manager = connection_manager
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        connection_id = context['connection_id']
        username = context['username']
        
        self.connection_manager.update_state(connection_id, ConnectionState.CLOSING)
        
        self.event_bus.publish('user_disconnected', {
            'username': username, 'ip': context['address'][0]
        })


# ============================================================================
# NEW COMMANDS: File Management (v4.0.0)
# ============================================================================

class DeleteCommand(Command):
    """Handles file deletion requests."""
    
    def __init__(self, event_bus: EventBus, db: DatabaseManager, 
                 shared_folder: str):
        self.event_bus = event_bus
        self.db = db
        self.shared_folder = shared_folder
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        file_name = InputValidator.validate_filename(data.get('filename', ''))
        if not file_name:
            JsonProtocol.send_message(client, {
                "type": "ERROR", 
                "message": "Invalid filename"
            })
            return
        
        file_path = os.path.join(self.shared_folder, file_name)
        username = context['username']
        
        if not os.path.isfile(file_path):
            JsonProtocol.send_message(client, {
                "type": "ERROR", 
                "message": "File not found"
            })
            return
        
        try:
            file_size = os.path.getsize(file_path)
            os.remove(file_path)
            
            JsonProtocol.send_message(client, {
                "type": "DELETE_OK",
                "filename": file_name
            })
            
            self.db.update_stats(username, uploaded=-file_size, files_received=-1)
            self.db.log_transfer(username, "Server", file_name, file_size, "DELETED")
            
            self.event_bus.publish('file_deleted', {
                'username': username,
                'filename': file_name,
                'size': file_size
            })
            
            logging.info(f"File deleted: {file_name} by {username}")
        
        except Exception as e:
            logging.error(f"Delete error: {e}")
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": f"Delete failed: {str(e)}"
            })


class RenameCommand(Command):
    """Handles file rename requests."""
    
    def __init__(self, db: DatabaseManager, shared_folder: str):
        self.db = db
        self.shared_folder = shared_folder
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        old_name = InputValidator.validate_filename(data.get('old_name', ''))
        new_name = InputValidator.validate_filename(data.get('new_name', ''))
        
        if not old_name or not new_name:
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": "Invalid filename(s)"
            })
            return
        
        old_path = os.path.join(self.shared_folder, old_name)
        new_path = os.path.join(self.shared_folder, new_name)
        
        if not os.path.isfile(old_path):
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": "Source file not found"
            })
            return
        
        if os.path.exists(new_path):
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": "Target filename already exists"
            })
            return
        
        try:
            os.rename(old_path, new_path)
            
            JsonProtocol.send_message(client, {
                "type": "RENAME_OK",
                "old_name": old_name,
                "new_name": new_name
            })
            
            self.db.log_transfer(
                context['username'], "Server", 
                f"{old_name} → {new_name}", 0, "RENAMED"
            )
            
            logging.info(f"File renamed: {old_name} → {new_name} by {context['username']}")
        
        except Exception as e:
            logging.error(f"Rename error: {e}")
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": f"Rename failed: {str(e)}"
            })


class SearchCommand(Command):
    """Handles file search requests with pattern matching."""
    
    def __init__(self, shared_folder: str):
        self.shared_folder = shared_folder
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        pattern = data.get('pattern', '').strip()
        
        if not pattern:
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": "Empty search pattern"
            })
            return
        
        regex_pattern = fnmatch.translate(pattern)
        regex = re.compile(regex_pattern, re.IGNORECASE)
        
        matches = []
        try:
            for filename in os.listdir(self.shared_folder):
                full_path = os.path.join(self.shared_folder, filename)
                if os.path.isfile(full_path) and regex.match(filename):
                    matches.append({
                        "name": filename,
                        "size": os.path.getsize(full_path)
                    })
            
            matches.sort(key=lambda x: x['name'].lower())
            
            JsonProtocol.send_message(client, {
                "type": "SEARCH_RESULTS",
                "pattern": pattern,
                "count": len(matches),
                "files": matches
            })
        
        except Exception as e:
            logging.error(f"Search error: {e}")
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": f"Search failed: {str(e)}"
            })


# ============================================================================
# NEW COMMANDS: Resume Transfers (v4.0.0)
# ============================================================================

class ResumeUploadCommand(Command):
    """Handles resumed file uploads."""
    
    def __init__(self, event_bus: EventBus, db: DatabaseManager, 
                 shared_folder: str, transaction_manager: TransactionManager,
                 connection_manager: ConnectionManager):
        self.event_bus = event_bus
        self.db = db
        self.shared_folder = shared_folder
        self.transaction_manager = transaction_manager
        self.connection_manager = connection_manager
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        file_name = InputValidator.validate_filename(data.get('filename', ''))
        if not file_name:
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": "Invalid filename"
            })
            return
        
        file_size = data.get('size', 0)
        file_sha256 = data.get('sha256', '')
        offset = data.get('offset', 0)
        username = context['username']
        connection_id = context['connection_id']
        
        save_path = os.path.join(self.shared_folder, file_name)
        
        if not os.path.isfile(save_path):
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": "No partial file found. Start fresh upload."
            })
            return
        
        existing_size = os.path.getsize(save_path)
        
        if existing_size != offset:
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": f"Offset mismatch. Server has {existing_size} bytes, client sent offset {offset}"
            })
            return
        
        max_size = CONFIG["server"]["max_file_size_mb"] * 1024 * 1024
        if max_size > 0 and file_size > max_size:
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": "File too large"
            })
            return
        
        transaction = self.transaction_manager.create_transaction(
            connection_id, username, 'resume_upload', file_name, file_size - offset
        )
        self.connection_manager.set_current_transaction(connection_id, transaction.id)
        
        JsonProtocol.send_message(client, {
            "type": "RESUME_OK",
            "offset": offset
        })
        
        received_size = offset
        try:
            with open(save_path, 'ab') as f:
                while received_size < file_size:
                    chunk_size = min(4096, file_size - received_size)
                    chunk = client.recv(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    received_size += len(chunk)
                    
                    self.transaction_manager.update_progress(
                        transaction.id, received_size - offset
                    )
                    self.connection_manager.update_bytes(
                        connection_id, received=received_size - offset
                    )
            
            if FileTransferUtils.calculate_sha256(save_path) == file_sha256:
                JsonProtocol.send_message(client, {"type": "FILE_OK"})
                self.db.update_stats(username, uploaded=file_size - offset, files_received=1)
                self.db.log_transfer(username, "Server", file_name, file_size, "RESUMED")
                self.transaction_manager.complete_transaction(transaction.id, success=True)
                self.event_bus.publish('file_uploaded', {
                    'username': username, 'filename': file_name, 
                    'size': file_size, 'resumed': True
                })
            else:
                JsonProtocol.send_message(client, {"type": "FILE_CORRUPTED"})
                self.db.log_transfer(username, "Server", file_name, file_size, "CORRUPTED")
                self.transaction_manager.complete_transaction(transaction.id, success=False)
        
        except Exception as e:
            logging.error(f"Resume upload error: {e}")
            self.transaction_manager.complete_transaction(transaction.id, success=False)
        
        finally:
            self.connection_manager.clear_current_transaction(connection_id)


class ResumeDownloadCommand(Command):
    """Handles resumed file downloads."""
    
    def __init__(self, event_bus: EventBus, db: DatabaseManager, 
                 shared_folder: str, transaction_manager: TransactionManager,
                 connection_manager: ConnectionManager):
        self.event_bus = event_bus
        self.db = db
        self.shared_folder = shared_folder
        self.transaction_manager = transaction_manager
        self.connection_manager = connection_manager
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        file_name = InputValidator.validate_filename(data.get('filename', ''))
        if not file_name:
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": "Invalid filename"
            })
            return
        
        offset = data.get('offset', 0)
        file_path = os.path.join(self.shared_folder, file_name)
        username = context['username']
        connection_id = context['connection_id']
        
        if not os.path.isfile(file_path):
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": "File not found"
            })
            return
        
        file_size = os.path.getsize(file_path)
        
        if offset < 0 or offset >= file_size:
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": f"Invalid offset: {offset}. File size: {file_size}"
            })
            return
        
        file_sha256 = FileTransferUtils.calculate_sha256(file_path)
        remaining_size = file_size - offset
        
        transaction = self.transaction_manager.create_transaction(
            connection_id, username, 'resume_download', file_name, remaining_size
        )
        self.connection_manager.set_current_transaction(connection_id, transaction.id)
        
        JsonProtocol.send_message(client, {
            "type": "RESUME_META",
            "filename": file_name,
            "size": file_size,
            "offset": offset,
            "remaining": remaining_size,
            "sha256": file_sha256
        })
        
        ready_msg = JsonProtocol.recv_message(client)
        if not ready_msg or ready_msg.get('type') != 'READY':
            return
        
        sent_size = 0
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                
                while sent_size < remaining_size:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    client.send(chunk)
                    sent_size += len(chunk)
                    
                    self.transaction_manager.update_progress(transaction.id, sent_size)
                    self.connection_manager.update_bytes(connection_id, sent=sent_size)
            
            self.db.update_stats(username, downloaded=remaining_size, files_sent=1)
            self.db.log_transfer("Server", username, file_name, remaining_size, "RESUMED")
            self.transaction_manager.complete_transaction(transaction.id, success=True)
            self.event_bus.publish('file_downloaded', {
                'username': username, 'filename': file_name,
                'size': remaining_size, 'resumed': True
            })
        
        except Exception as e:
            logging.error(f"Resume download error: {e}")
            self.transaction_manager.complete_transaction(transaction.id, success=False)
        
        finally:
            self.connection_manager.clear_current_transaction(connection_id)


# ============================================================================
# NEW COMMAND: Server Fingerprint (Safety Numbers) - v4.0.0
# ============================================================================

class ServerFingerprintCommand(Command):
    """
    Returns server's certificate fingerprint for Safety Numbers verification.
    
    Purpose:
    --------
    Prevents Server Spoofing attacks. User compares the safety numbers
    shown on client with those shown on server admin console.
    """
    
    def __init__(self, cert_file: str):
        self.cert_file = cert_file
    
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        try:
            if not os.path.exists(self.cert_file):
                JsonProtocol.send_message(client, {
                    "type": "ERROR",
                    "message": "Certificate not available"
                })
                return
            
            with open(self.cert_file, 'rb') as f:
                cert_data = f.read()
            
            fingerprint = hashlib.sha256(cert_data).hexdigest()
            
            safety_numbers = []
            for i in range(0, 25, 5):
                chunk = fingerprint[i:i+5]
                num = int(chunk, 16) % 100000
                safety_numbers.append(f"{num:05d}")
            
            safety_string = "-".join(safety_numbers)
            
            JsonProtocol.send_message(client, {
                "type": "SERVER_FINGERPRINT",
                "safety_numbers": safety_string,
                "fingerprint": fingerprint[:32]
            })
        
        except Exception as e:
            logging.error(f"Fingerprint error: {e}")
            JsonProtocol.send_message(client, {
                "type": "ERROR",
                "message": "Could not generate fingerprint"
            })


# ============================================================================
# DESIGN PATTERN: Factory
# ============================================================================

class CommandFactory:
    """Factory Pattern for creating command instances."""
    
    def __init__(self, event_bus: EventBus, db: DatabaseManager, 
                 connection_manager: ConnectionManager,
                 transaction_manager: TransactionManager,
                 shared_folder: str, cert_file: str):
        self.commands = {
            # Core commands
            "UPLOAD": UploadCommand(event_bus, db, shared_folder, 
                                   transaction_manager, connection_manager),
            "DOWNLOAD": DownloadCommand(event_bus, db, shared_folder,
                                       transaction_manager, connection_manager),
            "LIST": ListCommand(shared_folder),
            "USERS": UsersCommand(connection_manager),
            "STATS": StatsCommand(db),
            "QUIT": QuitCommand(event_bus, connection_manager),
            
            # File management (v4.0.0)
            "DELETE": DeleteCommand(event_bus, db, shared_folder),
            "RENAME": RenameCommand(db, shared_folder),
            "SEARCH": SearchCommand(shared_folder),
            
            # Resume transfers (v4.0.0)
            "RESUME_UPLOAD": ResumeUploadCommand(
                event_bus, db, shared_folder, transaction_manager, connection_manager
            ),
            "RESUME_DOWNLOAD": ResumeDownloadCommand(
                event_bus, db, shared_folder, transaction_manager, connection_manager
            ),
            
            # Security (v4.0.0)
            "SERVER_FINGERPRINT": ServerFingerprintCommand(cert_file),
        }
    
    def get_command(self, command_name: str) -> Optional[Command]:
        """Get a command instance by name."""
        return self.commands.get(command_name)


# ============================================================================
# SUPPORTING CLASSES
# ============================================================================

class SSLManager:
    """Manages SSL certificate generation for TLS encryption."""
    
    @staticmethod
    def generate_self_signed_cert(cert_file: str = None, 
                                   key_file: str = None) -> bool:
        """Generate a self-signed SSL certificate if it doesn't exist."""
        cert_file = cert_file or CONFIG["security"]["cert_file"]
        key_file = key_file or CONFIG["security"]["key_file"]
        
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            print("🔐 Generating SSL certificate...")
            try:
                cert_days = CONFIG["security"]["cert_days"]
                os.system(
                    f'openssl req -x509 -newkey rsa:4096 -keyout {key_file} '
                    f'-out {cert_file} -days {cert_days} -nodes -subj "/CN=Julian Server" 2>/dev/null'
                )
                print("✅ SSL certificate generated successfully")
                return True
            except Exception as e:
                print(f"❌ Failed to generate SSL certificate: {e}")
                return False
        return True


class NetworkUtils:
    """Utility class for network-related operations."""
    
    @staticmethod
    def get_mac_from_ip(ip_address: str) -> str:
        """Resolve MAC address from IP using ARP table."""
        if not InputValidator.validate_ip(ip_address):
            return "unknown"
        
        try:
            subprocess.run(['ping', '-c', '1', '-W', '1', ip_address],
                          capture_output=True, timeout=2)
            result = subprocess.run(['arp', '-n', ip_address],
                                   capture_output=True, text=True, timeout=2)
            mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', result.stdout)
            if mac_match:
                return mac_match.group(0).lower()
        except Exception:
            pass
        return "unknown"
    
    @staticmethod
    def get_local_ip() -> str:
        """Get the local IP address of this machine."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'


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
    def format_size(size: int) -> str:
        """Format file size to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    @staticmethod
    def generate_password(length: int = None) -> str:
        """Generate a random password for authentication."""
        length = length or CONFIG["security"]["password_length"]
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))


# ============================================================================
# SERVICE DISCOVERY
# ============================================================================

class ServiceDiscovery:
    """Broadcasts server information via UDP for automatic client discovery."""
    
    def __init__(self, server_port: int, tls_enabled: bool):
        self.server_port = server_port
        self.tls_enabled = tls_enabled
        self.broadcast_port = CONFIG["discovery"]["broadcast_port"]
        self.interval = CONFIG["discovery"]["interval"]
        self.running = False
        self.thread = None
    
    def start(self) -> None:
        """Start broadcasting server information."""
        self.running = True
        self.thread = threading.Thread(target=self._broadcast_loop, daemon=True)
        self.thread.start()
    
    def stop(self) -> None:
        """Stop broadcasting."""
        self.running = False
    
    def _broadcast_loop(self) -> None:
        """Continuously broadcast server information."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        discovery_data = {
            "service": "julian",
            "version": "4.0.0",
            "port": self.server_port,
            "requires_auth": True,
            "tls": self.tls_enabled
        }
        
        while self.running:
            try:
                message = json.dumps(discovery_data).encode('utf-8')
                sock.sendto(message, ('<broadcast>', self.broadcast_port))
                time.sleep(self.interval)
            except Exception as e:
                logging.error(f"Discovery broadcast error: {e}")
                time.sleep(self.interval)
        
        sock.close()


# ============================================================================
# MAIN SERVER CLASS
# ============================================================================

class SecureServer:
    """
    Main server class orchestrating all components.
    
    Architecture:
    -------------
    - ConnectionManager: Tracks all client connections
    - TransactionManager: Manages file transfers
    - HeartbeatMonitor: Detects dead connections
    - EventBus: Event-driven logging
    - CommandFactory: Command routing
    - DatabaseManager: Persistent storage (Singleton)
    - RateLimiter: Security protection
    """
    
    def __init__(self, config: dict = None):
        """Initialize server with all components."""
        self.config = config or CONFIG
        
        self.host = self.config["server"]["host"]
        self.port = self.config["server"]["port"]
        if self.port == 0:
            self.port = random.randint(10000, 60000)
        
        self.shared_folder = self.config["server"]["shared_folder"]
        self.password = FileTransferUtils.generate_password()
        
        self.server_socket = None
        self.context = None
        
        self.event_bus = EventBus()
        self.db = DatabaseManager()
        self.connection_manager = ConnectionManager()
        self.transaction_manager = TransactionManager(self.db)
        self.rate_limiter = RateLimiter()
        self.heartbeat_monitor = HeartbeatMonitor(self.connection_manager)
        
        os.makedirs(self.shared_folder, exist_ok=True)
        
        self.ssl_enabled = self.config["security"]["tls_enabled"]
        if self.ssl_enabled:
            self.ssl_enabled = SSLManager.generate_self_signed_cert()
            if self.ssl_enabled:
                self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self.context.load_cert_chain(
                    self.config["security"]["cert_file"],
                    self.config["security"]["key_file"]
                )
        
        # Initialize command factory with certificate file for fingerprinting
        self.command_factory = CommandFactory(
            self.event_bus, self.db, self.connection_manager,
            self.transaction_manager, self.shared_folder,
            self.config["security"]["cert_file"]
        )
        
        logging.basicConfig(
            filename=self.config["logging"]["file"],
            filemode='a',
            format=self.config["logging"]["format"],
            datefmt='%Y-%m-%d %H:%M:%S',
            level=getattr(logging, self.config["logging"]["level"])
        )
        
        self._setup_event_handlers()
        
        self.discovery = None
        if self.config["discovery"]["enabled"]:
            self.discovery = ServiceDiscovery(self.port, self.ssl_enabled)
    
    def _setup_event_handlers(self) -> None:
        """Register event handlers for the EventBus."""
        self.event_bus.subscribe('user_connected', self._on_user_connected)
        self.event_bus.subscribe('user_disconnected', self._on_user_disconnected)
        self.event_bus.subscribe('file_uploaded', self._on_file_uploaded)
        self.event_bus.subscribe('file_downloaded', self._on_file_downloaded)
        self.event_bus.subscribe('file_deleted', self._on_file_deleted)
        self.event_bus.subscribe('pairing_requested', self._on_pairing_requested)
        self.event_bus.subscribe('security_event', self._on_security_event)
    
    def _on_user_connected(self, data: dict) -> None:
        logging.info(f"User connected: {data['username']} from {data['ip']}")
    
    def _on_user_disconnected(self, data: dict) -> None:
        logging.info(f"User disconnected: {data['username']}")
    
    def _on_file_uploaded(self, data: dict) -> None:
        resumed = " (resumed)" if data.get('resumed') else ""
        logging.info(f"File uploaded{resumed}: {data['filename']} by {data['username']}")
    
    def _on_file_downloaded(self, data: dict) -> None:
        resumed = " (resumed)" if data.get('resumed') else ""
        logging.info(f"File downloaded{resumed}: {data['filename']} by {data['username']}")
    
    def _on_file_deleted(self, data: dict) -> None:
        logging.info(f"File deleted: {data['filename']} by {data['username']}")
    
    def _on_pairing_requested(self, data: dict) -> None:
        print("\n" + "=" * 60)
        print(f"🔑 NEW PAIRING REQUEST")
        print(f"   Username: {data['username']}")
        print(f"   Device: {data['device_info']}")
        print(f"   IP: {data['ip']}")
        print(f"   Code: \033[1;33m{data['code']}\033[0m")
        print(f"   ⏰  Expires in {self.config['security']['code_expiry']} seconds")
        print("=" * 60 + "\n")
    
    def _on_security_event(self, data: dict) -> None:
        print(f"\n🛡️ SECURITY: {data['type']} from {data['ip']} - {data['details']}")
    
    def start(self) -> None:
        """Start the server and begin accepting connections."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        if self.ssl_enabled and self.context:
            self.server_socket = self.context.wrap_socket(
                self.server_socket, server_side=True
            )
        
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.config["server"]["max_clients"])
        
        ip = NetworkUtils.get_local_ip()
        print("=" * 60)
        print("🔒 Julian Server v4.0.0 (Full File Management)")
        print("=" * 60)
        print(f"📍 IP: {ip} | 📌 Port: {self.port} | 🔑 Pass: {self.password}")
        print(f"🔐 Encryption: {'TLS 1.3 Enabled' if self.ssl_enabled else 'DISABLED'}")
        print(f"🛡️ Stealth Mode: ENABLED ({self.config['security']['auth_timeout']}s timeout)")
        print(f"🔑 Auth: Pairing Code + Rate Limiting")
        print(f"📡 Discovery: {'Enabled' if self.discovery else 'Disabled'}")
        print(f"💓 Heartbeat: {self.config['connections']['heartbeat_interval']}s interval")
        print(f"🗄️ Database: {self.config['database']['path']}")
        print(f"📁 Shared: {os.path.abspath(self.shared_folder)}")
        print("=" * 60)
        print("New in v4.0.0:")
        print("  ✅ Resume Transfers")
        print("  ✅ File Management (delete, rename, search)")
        print("  ✅ Safety Numbers (server verification)")
        print("  ✅ Admin Code Generation (code <username>)")
        print("=" * 60)
        print("Type 'help' for admin commands.\n")
        
        if self.discovery:
            self.discovery.start()
            print(f"📡 Broadcasting on port {self.config['discovery']['broadcast_port']}...")
        
        self.heartbeat_monitor.start()
        
        admin_thread = threading.Thread(target=self._admin_cli, daemon=True)
        admin_thread.start()
        
        try:
            while True:
                client, addr = self.server_socket.accept()
                threading.Thread(
                    target=self._handle_client, args=(client, addr), daemon=True
                ).start()
        except KeyboardInterrupt:
            print("\n🛑 Shutting down...")
        finally:
            if self.discovery:
                self.discovery.stop()
            self.heartbeat_monitor.stop()
            if self.server_socket:
                self.server_socket.close()
    
    def _silent_close(self, client: socket.socket, ip: str, mac: str, 
                       attempt_type: str, details: str) -> None:
        """Stealth mode: close connection silently without any response."""
        self.db.log_security_event(ip, mac, attempt_type, details)
        self.event_bus.publish('security_event', {
            'type': attempt_type, 'ip': ip, 'details': details
        })
        try:
            client.close()
        except Exception:
            pass
    
    def _handle_client(self, client: socket.socket, addr: tuple) -> None:
        """Handle client connection with stealth mode authentication."""
        connection = None
        
        try:
            auth_timeout = self.config["security"]["auth_timeout"]
            client.settimeout(auth_timeout)
            
            try:
                initial_msg = JsonProtocol.recv_message(client, timeout=auth_timeout)
            except socket.timeout:
                self._silent_close(client, addr[0], "unknown",
                                    "TIMEOUT", f"No auth attempt within {auth_timeout}s")
                return
            
            if not initial_msg:
                self._silent_close(client, addr[0], "unknown", 
                                    "EMPTY", "Empty or invalid initial data")
                return
            
            client.settimeout(None)
            
            mac_address = NetworkUtils.get_mac_from_ip(addr[0])
            if self.db.is_mac_banned(mac_address):
                self._silent_close(client, addr[0], mac_address,
                                    "BANNED_DEVICE", "Banned MAC attempted connection")
                return
            
            if not self.rate_limiter.is_allowed(addr[0]):
                remaining = self.rate_limiter.get_remaining_attempts(addr[0])
                self._silent_close(client, addr[0], mac_address,
                                    "RATE_LIMITED", 
                                    f"Too many attempts. {remaining} remaining in window")
                return
            
            msg_type = initial_msg.get('type', '')
            
            if msg_type == "PAIR_REQUEST":
                self._handle_pair_request(client, addr, mac_address, initial_msg)
            elif msg_type == "CODE_LOGIN":
                self._handle_code_login(client, addr, mac_address, initial_msg)
            else:
                self._silent_close(client, addr[0], mac_address,
                                    "INVALID_AUTH", f"Unknown message type: {msg_type}")
        
        except Exception as e:
            logging.error(f"Client handler error: {e}")
        finally:
            if connection:
                self.connection_manager.unregister(connection.id)
            try:
                client.close()
            except Exception:
                pass
    
    def _handle_pair_request(self, client: socket.socket, addr: tuple,
                              mac_address: str, data: dict) -> None:
        """Handle first-time pairing request."""
        username = data.get('username', '').strip()
        device_info = data.get('device_info', '')
        device_fingerprint = data.get('device_fingerprint', '')
        
        if not InputValidator.validate_username(username):
            self._silent_close(client, addr[0], mac_address,
                                "INVALID_USERNAME", f"Invalid username: {username}")
            return
        
        if self.db.is_user_banned(username):
            self._silent_close(client, addr[0], mac_address,
                                "BANNED_USER", f"Banned user '{username}' attempted pairing")
            return
        
        code = self.db.create_pairing_request(username, addr[0], device_fingerprint, device_info)
        
        self.event_bus.publish('pairing_requested', {
            'username': username,
            'device_info': device_info,
            'ip': addr[0],
            'code': code
        })
        
        JsonProtocol.send_message(client, {"type": "PAIR_CODE", "code": code})
        
        code_expiry = self.config["security"]["code_expiry"]
        client.settimeout(code_expiry)
        
        try:
            confirm_msg = JsonProtocol.recv_message(client, timeout=code_expiry)
        except socket.timeout:
            self._silent_close(client, addr[0], mac_address,
                                "PAIR_TIMEOUT", f"Pairing code not confirmed for '{username}'")
            return
        
        if not confirm_msg or confirm_msg.get('type') != 'PAIR_CONFIRM':
            self._silent_close(client, addr[0], mac_address,
                                "INVALID_CONFIRM", "Expected PAIR_CONFIRM")
            return
        
        entered_code = confirm_msg.get('code', '').strip()
        
        request_info = self.db.verify_pairing_code(entered_code)
        if not request_info or request_info['device_fingerprint'] != device_fingerprint:
            self._silent_close(client, addr[0], mac_address,
                                "WRONG_CODE", f"Wrong pairing code for '{username}'")
            return
        
        self.db.register_user(username, addr[0], mac_address, device_fingerprint)
        
        os_info, distribution, device_type = "Unknown", "", "Unknown"
        if "||" in device_info:
            parts = device_info.split("||")
            if len(parts) >= 3:
                os_info, distribution, device_type = parts[0], parts[1], parts[2]
        
        self.db.register_device(addr[0], mac_address, username, device_fingerprint,
                                os_info, distribution, device_type)
        
        connection = self.connection_manager.register(
            username, client, addr, mac_address, device_fingerprint
        )
        
        if not connection:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Max connections reached"})
            return
        
        JsonProtocol.send_message(client, {"type": "PAIRED_OK"})
        
        self.connection_manager.update_state(connection.id, ConnectionState.IDLE)
        
        print(f"✅ Device paired: {username} | {device_type} | {addr[0]}")
        
        self._enter_command_loop(client, addr, mac_address, username, 
                                  device_fingerprint, connection.id)
    
    def _handle_code_login(self, client: socket.socket, addr: tuple,
                            mac_address: str, data: dict) -> None:
        """Handle code-based login (every connection)."""
        username = data.get('username', '').strip()
        code = data.get('code', '').strip()
        device_fingerprint = data.get('device_fingerprint', '')
        
        if not InputValidator.validate_username(username):
            self._silent_close(client, addr[0], mac_address,
                                "INVALID_USERNAME", f"Invalid username: {username}")
            return
        
        if self.db.is_user_banned(username):
            self._silent_close(client, addr[0], mac_address,
                                "BANNED_USER", f"Banned user '{username}'")
            return
        
        request_info = self.db.verify_pairing_code(code)
        if not request_info:
            self._silent_close(client, addr[0], mac_address,
                                "INVALID_CODE", f"Invalid or expired code for '{username}'")
            return
        
        if request_info['device_fingerprint'] != device_fingerprint:
            self._silent_close(client, addr[0], mac_address,
                                "DEVICE_MISMATCH", f"Device fingerprint mismatch for '{username}'")
            return
        
        device_info = request_info.get('device_info', '')
        os_info, distribution, device_type = "Unknown", "", "Unknown"
        if "||" in device_info:
            parts = device_info.split("||")
            if len(parts) >= 3:
                os_info, distribution, device_type = parts[0], parts[1], parts[2]
        
        self.db.register_user(username, addr[0], mac_address, device_fingerprint)
        self.db.register_device(addr[0], mac_address, username, device_fingerprint,
                                os_info, distribution, device_type)
        
        connection = self.connection_manager.register(
            username, client, addr, mac_address, device_fingerprint
        )
        
        if not connection:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Max connections reached"})
            return
        
        JsonProtocol.send_message(client, {"type": "LOGIN_OK", "username": username})
        
        self.connection_manager.update_state(connection.id, ConnectionState.IDLE)
        
        self.event_bus.publish('user_connected', {
            'username': username, 'ip': addr[0], 'mac': mac_address,
            'device': device_type
        })
        
        print(f"✅ {username} | 📍 {addr[0]} | 🔗 {mac_address} (code login)")
        
        self._enter_command_loop(client, addr, mac_address, username,
                                  device_fingerprint, connection.id)
    
    def _enter_command_loop(self, client: socket.socket, addr: tuple,
                             mac_address: str, username: str,
                             device_fingerprint: str, connection_id: str) -> None:
        """Main command loop after successful authentication."""
        try:
            while True:
                try:
                    msg = JsonProtocol.recv_message(client)
                    if not msg:
                        break
                    
                    self.connection_manager.update_activity(connection_id)
                    
                    command_name = msg.get('type', '')
                    command = self.command_factory.get_command(command_name)
                    
                    if command:
                        context = {
                            'username': username,
                            'address': addr,
                            'mac': mac_address,
                            'fingerprint': device_fingerprint,
                            'connection_id': connection_id
                        }
                        command.execute(client, msg, context)
                        
                        if command_name == "QUIT":
                            break
                    else:
                        JsonProtocol.send_message(client, {
                            "type": "ERROR", 
                            "message": "Unknown command"
                        })
                except Exception:
                    break
        finally:
            self.connection_manager.unregister(connection_id)
    
    def _admin_cli(self) -> None:
        """Interactive admin command-line interface."""
        while True:
            try:
                cmd = input("\n[Admin] >>> ").strip()
                
                if cmd.lower() == 'help':
                    print("""
Commands:
  users              - Show active users with connection details
  devices            - Show all registered devices
  pending            - Show pending pairing requests
  security           - Show recent security events
  all_users          - Show all historical users
  banned             - Show banned users
  banned_macs        - Show banned MAC addresses
  connections        - Show detailed connection statistics
  transactions       - Show active transactions
  files              - Show shared files
  code <username>    - Generate login code for registered user
  ban <user> [reason]    - Ban a user
  unban <user>           - Unban a user
  ban_mac <mac> [reason] - Ban a device by MAC
  unban_mac <mac>        - Unban a MAC
  stats <user>           - Show user statistics
  quit                   - Exit server
                    """)
                
                elif cmd.lower() == 'users':
                    connections = self.connection_manager.get_all_connections()
                    print(f"\n👥 Active Users ({len(connections)}):")
                    for c in connections:
                        print(f"  👤 {c.username} | {c.address[0]} | 🔗 {c.mac_address} | State: {c.state.value}")
                
                elif cmd.lower() == 'connections':
                    stats = self.connection_manager.get_stats()
                    print(f"\n🔌 Connection Statistics:")
                    print(f"  Total: {stats['total_connections']}/{stats['max_connections']}")
                    print(f"  Active: {stats['active']}")
                    print(f"  Idle: {stats['idle']}")
                    print(f"  Transferring: {stats['transferring']}")
                    print(f"  Total Sent: {FileTransferUtils.format_size(stats['total_bytes_sent'])}")
                    print(f"  Total Received: {FileTransferUtils.format_size(stats['total_bytes_received'])}")
                    print(f"  Uptime: {int(stats['uptime'])}s")
                
                elif cmd.lower() == 'transactions':
                    stats = self.transaction_manager.get_stats()
                    print(f"\n📊 Transaction Statistics:")
                    print(f"  Total: {stats['total']}")
                    print(f"  Active: {stats['active']}")
                    print(f"  Completed: {stats['completed']}")
                    print(f"  Failed: {stats['failed']}")
                
                elif cmd.lower() == 'devices':
                    devices = self.db.get_all_devices()
                    print(f"\n🖥️ All Registered Devices ({len(devices)}):")
                    for d in devices:
                        print(f"  📍 {d[0]} | 🔗 {d[1]} | 👤 {d[2]} | 🔏 {d[3][:8]}... | 💻 {d[4]} | 📦 {d[5]} | 📱 {d[6]} | Last: {d[7]}")
                
                elif cmd.lower() == 'pending':
                    pending = self.db.get_pending_pairing_requests()
                    if not pending:
                        print("\n📭 No pending pairing requests")
                    else:
                        print(f"\n⏳ Pending Pairing Requests ({len(pending)}):")
                        for p in pending:
                            print(f"  👤 {p[0]} | 🔑 \033[1;33m{p[1]}\033[0m | 📍 {p[2]} | 🔏 {p[3][:8]}... | 🖥️ {p[4]} | Expires: {p[5]}")
                
                elif cmd.lower() == 'security':
                    logs = self.db.get_security_logs(20)
                    if not logs:
                        print("\n🛡️ No security events recorded")
                    else:
                        print(f"\n🛡️ Recent Security Events ({len(logs)}):")
                        for l in logs:
                            print(f"  📍 {l[0]} | 🔗 {l[1]} | ⚠️ {l[2]} | {l[3]} | {l[4]}")
                
                elif cmd.lower() == 'all_users':
                    users = self.db.get_all_users()
                    print(f"\n📜 All Registered Users ({len(users)}):")
                    for u in users:
                        print(f"  👤 {u[0]} | Last IP: {u[1]} | MAC: {u[2]} | 🔏 {u[3][:8]}... | Last Seen: {u[5]}")
                
                elif cmd.lower() == 'banned':
                    banned = self.db.get_banned_users()
                    print(f"\n🚫 Banned Users ({len(banned)}):")
                    for b in banned:
                        print(f"  ❌ {b[0]} | Banned: {b[1]} | Reason: {b[2]}")
                
                elif cmd.lower() == 'banned_macs':
                    banned = self.db.get_banned_macs()
                    print(f"\n🚫 Banned MAC Addresses ({len(banned)}):")
                    for b in banned:
                        print(f"  ❌ {b[0]} | Banned: {b[1]} | Reason: {b[2]}")
                
                # ====================================================================
                # NEW: Generate login code for registered user
                # ====================================================================
                elif cmd.lower().startswith('code '):
                    parts = cmd.split(' ', 1)
                    if len(parts) == 2:
                        username = parts[1].strip()
                        
                        # Validate username format
                        if not InputValidator.validate_username(username):
                            print(f"❌ Invalid username format: '{username}'")
                            print("💡 Username must be 3-32 chars, alphanumeric + underscore only")
                            continue
                        
                        # Check if user exists in database
                        user_info = self.db.get_user_info(username)
                        
                        if not user_info:
                            print(f"❌ User '{username}' not found.")
                            print(f"💡 User must complete 'setup' first to be registered.")
                            print(f"💡 Run 'all_users' to see all registered users.")
                        else:
                            # Check if user is banned
                            if self.db.is_user_banned(username):
                                print(f"❌ User '{username}' is banned.")
                                print(f"💡 Unban the user first with 'unban {username}'")
                                continue
                            
                            # Generate new pairing code for the user
                            ip = user_info['ip']
                            fingerprint = user_info['fingerprint']
                            
                            code = self.db.create_pairing_request(
                                username, ip, fingerprint, "Admin code generation"
                            )
                            
                            print(f"\n" + "=" * 60)
                            print(f"🔑 LOGIN CODE GENERATED")
                            print(f"=" * 60)
                            print(f"   👤 User: {username}")
                            print(f"   🔑 Code: \033[1;33m{code}\033[0m")
                            print(f"   📍 IP: {ip}")
                            print(f"   🔏 Fingerprint: {fingerprint[:16]}...")
                            print(f"   ⏰  Expires in: {self.config['security']['code_expiry']} seconds")
                            print(f"=" * 60)
                            print(f"💡 Share this code with the user")
                            print(f"💡 The code is one-time use only")
                            print(f"💡 The user's device fingerprint must match")
                            print("=" * 60 + "\n")
                            
                            logging.info(f"Login code generated for user '{username}': {code}")
                    else:
                        print("❌ Usage: code <username>")
                        print("💡 Example: code sleep")
                
                elif cmd.lower().startswith('ban '):
                    parts = cmd.split(' ', 2)
                    if len(parts) >= 2:
                        username = parts[1]
                        reason = parts[2] if len(parts) > 2 else "No reason provided"
                        self.db.ban_user(username, reason)
                        print(f"✅ User '{username}' banned. Reason: {reason}")
                
                elif cmd.lower().startswith('unban '):
                    parts = cmd.split(' ', 1)
                    if len(parts) == 2:
                        username = parts[1]
                        if self.db.unban_user(username):
                            print(f"✅ User '{username}' unbanned.")
                        else:
                            print(f"⚠️  User '{username}' was not banned.")
                
                elif cmd.lower().startswith('ban_mac '):
                    parts = cmd.split(' ', 2)
                    if len(parts) >= 2:
                        mac = parts[1].lower()
                        reason = parts[2] if len(parts) > 2 else "No reason provided"
                        self.db.ban_mac(mac, reason)
                        print(f"✅ MAC '{mac}' banned. Reason: {reason}")
                
                elif cmd.lower().startswith('unban_mac '):
                    parts = cmd.split(' ', 1)
                    if len(parts) == 2:
                        mac = parts[1].lower()
                        if self.db.unban_mac(mac):
                            print(f"✅ MAC '{mac}' unbanned.")
                        else:
                            print(f"⚠️  MAC '{mac}' was not banned.")
                
                elif cmd.lower().startswith('stats '):
                    stats = self.db.get_stats(cmd.split(' ', 1)[1].strip())
                    if stats:
                        print(f"\n📊 Uploaded: {FileTransferUtils.format_size(stats['uploaded'])} | "
                              f"Downloaded: {FileTransferUtils.format_size(stats['downloaded'])}")
                    else:
                        print("User not found.")
                
                elif cmd.lower() == 'files':
                    files = os.listdir(self.shared_folder)
                    if not files:
                        print("\n📭 No files in shared folder")
                    else:
                        print(f"\n📁 Shared Files ({len(files)}):")
                        for f in files:
                            path = os.path.join(self.shared_folder, f)
                            if os.path.isfile(path):
                                size = os.path.getsize(path)
                                print(f"  📄 {f} ({FileTransferUtils.format_size(size)})")
                
                elif cmd.lower() == 'quit':
                    os._exit(0)
                
                elif cmd.strip():
                    print(f"❌ Unknown command: '{cmd}'")
                    print("💡 Type 'help' for available commands")
            
            except KeyboardInterrupt:
                print("\n\n🛑 Use 'quit' to exit the server")
            except Exception as e:
                print(f"❌ Error: {e}")


def main():
    """Application entry point."""
    SecureServer().start()


if __name__ == "__main__":
    main()