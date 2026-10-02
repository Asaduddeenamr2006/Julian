"""
Julian Server - Secure File Transfer System v4.4.0
==================================================

Production-ready, security-hardened file transfer server.

Features:
- TLS 1.3 encryption with self-signed certificates
- JSON protocol with length-prefix (TCP-safe)
- Pairing authentication with one-time codes
- Device fingerprinting (UUID + Machine ID)
- Transfer requests (user-to-user with approval)
- Resume transfers (upload/download)
- File management (delete, rename, search)
- Admin code generation + admin push
- Live System Monitor (CPU/RAM/Network from /proc/)
- TUI Admin Dashboard (curses-based)
- Zero external dependencies

Design Patterns:
- Singleton: DatabaseManager
- Observer: EventBus
- Command: Protocol commands
- Factory: CommandFactory
- Strategy: Connection states

Author: Julian Project
License: MIT
Version: 4.4.0
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
import argparse
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Callable, Optional, Any
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from pathlib import Path
from enum import Enum


# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    "server": {
        "host": "0.0.0.0",
        "port": 0,
        "shared_folder": "shared_files",
        "max_clients": 10,
        "max_file_size_mb": 0,
    },
    "security": {
        "auth_timeout": 5,
        "code_length": 8,
        "code_expiry": 300,
        "password_length": 12,
        "tls_enabled": True,
        "cert_file": "server.crt",
        "key_file": "server.key",
        "cert_days": 365,
        "max_auth_attempts": 5,
        "rate_limit_window": 60,
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
        "interval": 5,
    },
    "connections": {
        "heartbeat_interval": 30,
        "heartbeat_timeout": 90,
        "idle_timeout": 300,
        "cleanup_interval": 60,
    },
    "transfers": {
        "request_expiry": 3600,
        "max_pending_requests": 10,
    },
    "dashboard": {
        "refresh_interval": 2,
    },
}


# ============================================================================
# ENUMS
# ============================================================================

class ConnectionState(Enum):
    AUTHENTICATING = "authenticating"
    IDLE = "idle"
    TRANSFERRING = "transferring"
    CLOSING = "closing"


class TransactionStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TransferRequestStatus(Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    COMPLETED = "completed"
    EXPIRED = "expired"


# ============================================================================
# EVENT BUS (Observer Pattern)
# ============================================================================

class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()
    
    def subscribe(self, event_type: str, callback: Callable) -> None:
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(callback)
    
    def publish(self, event_type: str, data: dict = None) -> None:
        with self._lock:
            subscribers = self._subscribers.get(event_type, []).copy()
        for callback in subscribers:
            try:
                callback(data or {})
            except Exception as e:
                logging.error(f"Event handler error for {event_type}: {e}")


# ============================================================================
# DATABASE MANAGER (Singleton Pattern)
# ============================================================================

class DatabaseManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, db_name: str = None):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self, db_name: str = None):
        if self._initialized:
            return
        db_name = db_name or CONFIG["database"]["path"]
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.db_lock = threading.Lock()
        self._create_tables()
        self._initialized = True
    
    def _create_tables(self) -> None:
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
                
                CREATE TABLE IF NOT EXISTS transfer_requests (
                    id TEXT PRIMARY KEY,
                    from_user TEXT,
                    to_user TEXT,
                    filename TEXT,
                    file_size INTEGER,
                    file_sha256 TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    accepted_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    rejection_reason TEXT
                );
                
                CREATE TABLE IF NOT EXISTS admin_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT,
                    target TEXT,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            self.conn.commit()
    
    def register_user(self, username: str, ip: str, mac: str = "unknown", 
                      fingerprint: str = "unknown") -> None:
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
        with self.db_lock:
            self.cursor.execute('SELECT * FROM stats WHERE username = ?', (username,))
            row = self.cursor.fetchone()
            if row:
                return {'uploaded': row[1], 'downloaded': row[2],
                        'files_sent': row[3], 'files_received': row[4]}
            return None
    
    def log_transfer(self, sender: str, receiver: str, filename: str, 
                     size: int, status: str) -> None:
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO transfer_logs (sender, receiver, filename, size, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (sender, receiver, filename, size, status))
            self.conn.commit()
    
    def is_user_banned(self, username: str) -> bool:
        with self.db_lock:
            self.cursor.execute('SELECT 1 FROM banned_users WHERE username = ?', (username,))
            return self.cursor.fetchone() is not None
    
    def ban_user(self, username: str, reason: str = "No reason provided") -> None:
        with self.db_lock:
            self.cursor.execute('''
                INSERT OR REPLACE INTO banned_users (username, reason, banned_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (username, reason))
            self.conn.commit()
    
    def unban_user(self, username: str) -> bool:
        with self.db_lock:
            self.cursor.execute('DELETE FROM banned_users WHERE username = ?', (username,))
            self.conn.commit()
            return self.cursor.rowcount > 0
    
    def get_banned_users(self) -> list:
        with self.db_lock:
            self.cursor.execute('SELECT username, banned_at, reason FROM banned_users ORDER BY banned_at DESC')
            return self.cursor.fetchall()
    
    def is_mac_banned(self, mac_address: str) -> bool:
        if mac_address == "unknown":
            return False
        with self.db_lock:
            self.cursor.execute('SELECT 1 FROM banned_macs WHERE mac_address = ?', (mac_address,))
            return self.cursor.fetchone() is not None
    
    def ban_mac(self, mac_address: str, reason: str = "No reason provided") -> None:
        with self.db_lock:
            self.cursor.execute('''
                INSERT OR REPLACE INTO banned_macs (mac_address, reason, banned_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (mac_address, reason))
            self.conn.commit()
    
    def unban_mac(self, mac_address: str) -> bool:
        with self.db_lock:
            self.cursor.execute('DELETE FROM banned_macs WHERE mac_address = ?', (mac_address,))
            self.conn.commit()
            return self.cursor.rowcount > 0
    
    def get_banned_macs(self) -> list:
        with self.db_lock:
            self.cursor.execute('SELECT mac_address, banned_at, reason FROM banned_macs ORDER BY banned_at DESC')
            return self.cursor.fetchall()
    
    def create_pairing_request(self, username: str, ip: str, device_fingerprint: str,
                                device_info: str) -> str:
        code_length = CONFIG["security"]["code_length"]
        code = ''.join([str(random.randint(0, 9)) for _ in range(code_length)])
        code_expiry = CONFIG["security"]["code_expiry"]
        expires_at = time.strftime('%Y-%m-%d %H:%M:%S', 
                                    time.localtime(time.time() + code_expiry))
        with self.db_lock:
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
        with self.db_lock:
            self.cursor.execute('''
                SELECT username, ip_address, device_fingerprint, device_info, expires_at
                FROM pairing_requests 
                WHERE code = ? AND used = 0
            ''', (code,))
            row = self.cursor.fetchone()
            if not row:
                return None
            expires_at = time.strptime(row[4], '%Y-%m-%d %H:%M:%S')
            if time.localtime() > expires_at:
                return None
            self.cursor.execute('UPDATE pairing_requests SET used = 1 WHERE code = ?', (code,))
            self.conn.commit()
            return {
                'username': row[0], 'ip': row[1],
                'device_fingerprint': row[2], 'device_info': row[3]
            }
    
    def get_pending_pairing_requests(self) -> list:
        with self.db_lock:
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute('''
                SELECT username, code, ip_address, device_fingerprint, device_info, expires_at
                FROM pairing_requests 
                WHERE used = 0 AND expires_at > ?
                ORDER BY created_at DESC
            ''', (now,))
            return self.cursor.fetchall()
    
    def create_transaction(self, transaction_id: str, connection_id: str, 
                           username: str, tx_type: str, filename: str, size: int) -> None:
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO transactions (id, connection_id, username, type, filename, size, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (transaction_id, connection_id, username, tx_type, filename, size, 
                  TransactionStatus.PENDING.value))
            self.conn.commit()
    
    def update_transaction_progress(self, transaction_id: str, bytes_transferred: int) -> None:
        with self.db_lock:
            self.cursor.execute('''
                UPDATE transactions 
                SET bytes_transferred = ?, status = ?
                WHERE id = ?
            ''', (bytes_transferred, TransactionStatus.IN_PROGRESS.value, transaction_id))
            self.conn.commit()
    
    def complete_transaction(self, transaction_id: str, status: str) -> None:
        with self.db_lock:
            self.cursor.execute('''
                UPDATE transactions 
                SET status = ?, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (status, transaction_id))
            self.conn.commit()
    
    def log_security_event(self, ip: str, mac: str, attempt_type: str, details: str) -> None:
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO security_logs (ip_address, mac_address, attempt_type, details)
                VALUES (?, ?, ?, ?)
            ''', (ip, mac, attempt_type, details))
            self.conn.commit()
    
    def get_security_logs(self, limit: int = 50) -> list:
        with self.db_lock:
            self.cursor.execute('''
                SELECT ip_address, mac_address, attempt_type, details, timestamp
                FROM security_logs ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return self.cursor.fetchall()
    
    def log_admin_action(self, action: str, target: str, details: str = "") -> None:
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO admin_audit_log (action, target, details)
                VALUES (?, ?, ?)
            ''', (action, target, details))
            self.conn.commit()
    
    def get_admin_audit_log(self, limit: int = 50) -> list:
        with self.db_lock:
            self.cursor.execute('''
                SELECT action, target, details, timestamp
                FROM admin_audit_log ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return self.cursor.fetchall()
    
    def get_all_users(self) -> list:
        with self.db_lock:
            self.cursor.execute('''
                SELECT username, ip_address, mac_address, device_fingerprint, first_seen, last_seen 
                FROM users ORDER BY last_seen DESC
            ''')
            return self.cursor.fetchall()
    
    def get_all_devices(self) -> list:
        with self.db_lock:
            self.cursor.execute('''
                SELECT ip_address, mac_address, username, device_fingerprint, os_info, 
                       distribution, device_type, last_seen 
                FROM device_sessions ORDER BY last_seen DESC
            ''')
            return self.cursor.fetchall()
    
    def get_user_info(self, username: str) -> Optional[dict]:
        with self.db_lock:
            self.cursor.execute('''
                SELECT username, ip_address, mac_address, device_fingerprint, first_seen, last_seen 
                FROM users WHERE username = ?
            ''', (username,))
            row = self.cursor.fetchone()
            if row:
                return {
                    'username': row[0], 'ip': row[1], 'mac': row[2],
                    'fingerprint': row[3], 'first_seen': row[4], 'last_seen': row[5]
                }
            return None
    
    def create_transfer_request(self, from_user: str, to_user: str, 
                                 filename: str, file_size: int, file_sha256: str) -> str:
        request_id = str(uuid.uuid4())
        request_expiry = CONFIG["transfers"]["request_expiry"]
        expires_at = time.strftime('%Y-%m-%d %H:%M:%S', 
                                    time.localtime(time.time() + request_expiry))
        with self.db_lock:
            try:
                self.cursor.execute('''
                    INSERT INTO transfer_requests 
                    (id, from_user, to_user, filename, file_size, file_sha256, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (request_id, from_user, to_user, filename, file_size, file_sha256, expires_at))
                self.conn.commit()
                return request_id
            except Exception as e:
                logging.error(f"Failed to create transfer request: {e}")
                return None
    
    def get_transfer_request(self, request_id: str) -> Optional[dict]:
        with self.db_lock:
            self.cursor.execute('''
                SELECT id, from_user, to_user, filename, file_size, file_sha256, 
                       status, created_at, expires_at, accepted_at, completed_at, rejection_reason
                FROM transfer_requests WHERE id = ?
            ''', (request_id,))
            row = self.cursor.fetchone()
            if row:
                return {
                    'id': row[0], 'from_user': row[1], 'to_user': row[2],
                    'filename': row[3], 'file_size': row[4], 'file_sha256': row[5],
                    'status': row[6], 'created_at': row[7], 'expires_at': row[8],
                    'accepted_at': row[9], 'completed_at': row[10], 'rejection_reason': row[11]
                }
            return None
    
    def get_pending_requests_for_user(self, username: str) -> List[dict]:
        with self.db_lock:
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute('''
                SELECT id, from_user, filename, file_size, created_at, expires_at
                FROM transfer_requests 
                WHERE to_user = ? AND status = 'pending' AND expires_at > ?
                ORDER BY created_at DESC
            ''', (username, now))
            return [{'id': r[0], 'from_user': r[1], 'filename': r[2],
                     'file_size': r[3], 'created_at': r[4], 'expires_at': r[5]}
                    for r in self.cursor.fetchall()]
    
    def get_pending_requests_from_user(self, username: str) -> List[dict]:
        with self.db_lock:
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute('''
                SELECT id, to_user, filename, file_size, created_at, expires_at, status
                FROM transfer_requests 
                WHERE from_user = ? AND status IN ('pending', 'accepted') AND expires_at > ?
                ORDER BY created_at DESC
            ''', (username, now))
            return [{'id': r[0], 'to_user': r[1], 'filename': r[2],
                     'file_size': r[3], 'created_at': r[4], 'expires_at': r[5], 'status': r[6]}
                    for r in self.cursor.fetchall()]
    
    def accept_transfer_request(self, request_id: str) -> bool:
        with self.db_lock:
            try:
                self.cursor.execute('''
                    UPDATE transfer_requests 
                    SET status = ?, accepted_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND status = 'pending'
                ''', (TransferRequestStatus.ACCEPTED.value, request_id))
                self.conn.commit()
                return self.cursor.rowcount > 0
            except Exception as e:
                logging.error(f"Failed to accept transfer request: {e}")
                return False
    
    def reject_transfer_request(self, request_id: str, reason: str = "") -> bool:
        with self.db_lock:
            try:
                self.cursor.execute('''
                    UPDATE transfer_requests 
                    SET status = ?, rejection_reason = ?
                    WHERE id = ? AND status = 'pending'
                ''', (TransferRequestStatus.REJECTED.value, reason, request_id))
                self.conn.commit()
                return self.cursor.rowcount > 0
            except Exception as e:
                logging.error(f"Failed to reject transfer request: {e}")
                return False
    
    def cancel_transfer_request(self, request_id: str, username: str) -> bool:
        with self.db_lock:
            try:
                self.cursor.execute('''
                    UPDATE transfer_requests 
                    SET status = ?
                    WHERE id = ? AND from_user = ? AND status = 'pending'
                ''', (TransferRequestStatus.CANCELLED.value, request_id, username))
                self.conn.commit()
                return self.cursor.rowcount > 0
            except Exception as e:
                logging.error(f"Failed to cancel transfer request: {e}")
                return False
    
    def complete_transfer_request(self, request_id: str) -> bool:
        with self.db_lock:
            try:
                self.cursor.execute('''
                    UPDATE transfer_requests 
                    SET status = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE id = ? AND status = 'accepted'
                ''', (TransferRequestStatus.COMPLETED.value, request_id))
                self.conn.commit()
                return self.cursor.rowcount > 0
            except Exception as e:
                logging.error(f"Failed to complete transfer request: {e}")
                return False
    
    def cleanup_expired_requests(self) -> int:
        with self.db_lock:
            try:
                now = time.strftime('%Y-%m-%d %H:%M:%S')
                self.cursor.execute('''
                    UPDATE transfer_requests 
                    SET status = ?
                    WHERE status = 'pending' AND expires_at < ?
                ''', (TransferRequestStatus.EXPIRED.value, now))
                self.conn.commit()
                return self.cursor.rowcount
            except Exception as e:
                logging.error(f"Failed to cleanup expired requests: {e}")
                return 0
    
    def get_all_transfer_requests(self, limit: int = 50) -> list:
        with self.db_lock:
            self.cursor.execute('''
                SELECT id, from_user, to_user, filename, file_size, status, created_at, expires_at
                FROM transfer_requests 
                ORDER BY created_at DESC
                LIMIT ?
            ''', (limit,))
            return self.cursor.fetchall()


# ============================================================================
# CONNECTION MANAGEMENT
# ============================================================================

@dataclass
class Connection:
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
    device_type: str = "Unknown"
    os_info: str = "Unknown"


class ConnectionManager:
    def __init__(self, max_connections: int = None):
        self.max_connections = max_connections or CONFIG["server"]["max_clients"]
        self._connections: Dict[str, Connection] = {}
        self._lock = threading.Lock()
        self._start_time = time.time()
    
    def register(self, username: str, client_socket: socket.socket, 
                 address: tuple, mac_address: str = "unknown",
                 device_fingerprint: str = "",
                 device_type: str = "Unknown",
                 os_info: str = "Unknown") -> Optional[Connection]:
        with self._lock:
            if len(self._connections) >= self.max_connections:
                return None
            for conn in self._connections.values():
                if conn.username == username:
                    return None
            connection_id = str(uuid.uuid4())
            connection = Connection(
                id=connection_id, username=username, socket=client_socket,
                address=address, mac_address=mac_address,
                device_fingerprint=device_fingerprint,
                device_type=device_type, os_info=os_info
            )
            self._connections[connection_id] = connection
            return connection
    
    def unregister(self, connection_id: str) -> None:
        with self._lock:
            if connection_id in self._connections:
                del self._connections[connection_id]
    
    def get_by_username(self, username: str) -> Optional[Connection]:
        with self._lock:
            for conn in self._connections.values():
                if conn.username == username:
                    return conn
            return None
    
    def update_state(self, connection_id: str, state: ConnectionState) -> None:
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].state = state
                self._connections[connection_id].last_activity = time.time()
    
    def set_current_transaction(self, connection_id: str, transaction_id: str) -> None:
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].current_transaction = transaction_id
                self._connections[connection_id].state = ConnectionState.TRANSFERRING
    
    def clear_current_transaction(self, connection_id: str) -> None:
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].current_transaction = None
                self._connections[connection_id].state = ConnectionState.IDLE
    
    def update_activity(self, connection_id: str) -> None:
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].last_activity = time.time()
    
    def update_bytes(self, connection_id: str, sent: int = 0, received: int = 0) -> None:
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].bytes_sent += sent
                self._connections[connection_id].bytes_received += received
    
    def get_all_connections(self) -> List[Connection]:
        with self._lock:
            return list(self._connections.values())
    
    def get_zombie_connections(self, timeout: int = None) -> List[Connection]:
        timeout = timeout or CONFIG["connections"]["heartbeat_timeout"]
        now = time.time()
        with self._lock:
            return [conn for conn in self._connections.values()
                    if now - conn.last_activity > timeout]
    
    def get_stats(self) -> dict:
        with self._lock:
            total = len(self._connections)
            active = sum(1 for c in self._connections.values() if c.state != ConnectionState.CLOSING)
            idle = sum(1 for c in self._connections.values() if c.state == ConnectionState.IDLE)
            transferring = sum(1 for c in self._connections.values() if c.state == ConnectionState.TRANSFERRING)
            total_sent = sum(c.bytes_sent for c in self._connections.values())
            total_received = sum(c.bytes_received for c in self._connections.values())
            uptime = time.time() - self._start_time
            return {
                'total_connections': total, 'max_connections': self.max_connections,
                'active': active, 'idle': idle, 'transferring': transferring,
                'total_bytes_sent': total_sent, 'total_bytes_received': total_received,
                'uptime': uptime
            }
    
    def cleanup(self) -> int:
        zombies = self.get_zombie_connections()
        cleaned = 0
        for conn in zombies:
            try:
                conn.socket.close()
            except Exception:
                pass
            self.unregister(conn.id)
            cleaned += 1
        return cleaned
    
    def kick_user(self, username: str, reason: str = "Kicked by admin") -> bool:
        with self._lock:
            conn = None
            for c in self._connections.values():
                if c.username == username:
                    conn = c
                    break
            if not conn:
                return False
            try:
                JsonProtocol.send_message(conn.socket, {
                    "type": "KICKED", "reason": reason
                })
                conn.socket.close()
            except Exception:
                pass
            self.unregister(conn.id)
            return True


# ============================================================================
# TRANSACTION MANAGEMENT
# ============================================================================

@dataclass
class Transaction:
    id: str
    connection_id: str
    username: str
    type: str
    filename: str
    size: int
    status: TransactionStatus = TransactionStatus.PENDING
    bytes_transferred: int = 0
    started_at: float = field(default_factory=time.time)


class TransactionManager:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self._transactions: Dict[str, Transaction] = {}
        self._lock = threading.Lock()
    
    def create_transaction(self, connection_id: str, username: str, 
                           tx_type: str, filename: str, size: int) -> Transaction:
        transaction_id = str(uuid.uuid4())
        transaction = Transaction(
            id=transaction_id, connection_id=connection_id, username=username,
            type=tx_type, filename=filename, size=size
        )
        with self._lock:
            self._transactions[transaction_id] = transaction
        self.db.create_transaction(transaction_id, connection_id, username, tx_type, filename, size)
        return transaction
    
    def update_progress(self, transaction_id: str, bytes_transferred: int) -> None:
        with self._lock:
            if transaction_id in self._transactions:
                self._transactions[transaction_id].bytes_transferred = bytes_transferred
        self.db.update_transaction_progress(transaction_id, bytes_transferred)
    
    def complete_transaction(self, transaction_id: str, success: bool = True) -> None:
        status = TransactionStatus.COMPLETED if success else TransactionStatus.FAILED
        with self._lock:
            if transaction_id in self._transactions:
                self._transactions[transaction_id].status = status
        self.db.complete_transaction(transaction_id, status.value)
    
    def get_stats(self) -> dict:
        with self._lock:
            total = len(self._transactions)
            active = sum(1 for t in self._transactions.values() if t.status == TransactionStatus.IN_PROGRESS)
            completed = sum(1 for t in self._transactions.values() if t.status == TransactionStatus.COMPLETED)
            failed = sum(1 for t in self._transactions.values() if t.status == TransactionStatus.FAILED)
            return {'total': total, 'active': active, 'completed': completed, 'failed': failed}


# ============================================================================
# HEARTBEAT MONITOR
# ============================================================================

class HeartbeatMonitor:
    def __init__(self, connection_manager: ConnectionManager, db: DatabaseManager):
        self.connection_manager = connection_manager
        self.db = db
        self.running = False
        self.thread = None
    
    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    
    def stop(self) -> None:
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def _monitor_loop(self) -> None:
        interval = CONFIG["connections"]["heartbeat_interval"]
        cleanup_interval = CONFIG["connections"]["cleanup_interval"]
        last_cleanup = time.time()
        while self.running:
            try:
                zombies = self.connection_manager.get_zombie_connections()
                now = time.time()
                if now - last_cleanup > cleanup_interval:
                    cleaned = self.connection_manager.cleanup()
                    expired = self.db.cleanup_expired_requests()
                    last_cleanup = now
                time.sleep(interval)
            except Exception as e:
                logging.error(f"Heartbeat monitor error: {e}")
                time.sleep(interval)


# ============================================================================
# RATE LIMITER
# ============================================================================

class RateLimiter:
    def __init__(self, max_attempts: int = None, window_seconds: int = None):
        self.max_attempts = max_attempts or CONFIG["security"]["max_auth_attempts"]
        self.window = window_seconds or CONFIG["security"]["rate_limit_window"]
        self.attempts = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        with self.lock:
            self.attempts[ip] = [t for t in self.attempts[ip] if now - t < self.window]
            if len(self.attempts[ip]) >= self.max_attempts:
                return False
            self.attempts[ip].append(now)
            return True
    
    def get_remaining_attempts(self, ip: str) -> int:
        now = time.time()
        with self.lock:
            self.attempts[ip] = [t for t in self.attempts[ip] if now - t < self.window]
            return max(0, self.max_attempts - len(self.attempts[ip]))


# ============================================================================
# INPUT VALIDATOR
# ============================================================================

class InputValidator:
    @staticmethod
    def validate_ip(ip_string: str) -> bool:
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_filename(filename: str) -> Optional[str]:
        filename = os.path.basename(filename)
        if any(c in filename for c in ['/', '\\', '..', '\x00']):
            return None
        if len(filename) > 255 or len(filename) == 0:
            return None
        return filename
    
    @staticmethod
    def validate_username(username: str) -> bool:
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False
        if not (3 <= len(username) <= 32):
            return False
        return True


# ============================================================================
# JSON PROTOCOL
# ============================================================================

class JsonProtocol:
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
                return None
            message_bytes = b""
            while len(message_bytes) < length:
                chunk = sock.recv(min(4096, length - len(message_bytes)))
                if not chunk:
                    return None
                message_bytes += chunk
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
    @staticmethod
    def calculate_sha256(file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def format_size(size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    @staticmethod
    def generate_password(length: int = None) -> str:
        length = length or CONFIG["security"]["password_length"]
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))
    
    @staticmethod
    def format_uptime(seconds: float) -> str:
        hours, remainder = divmod(int(seconds), 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"


# ============================================================================
# COMMANDS
# ============================================================================

class Command(ABC):
    @abstractmethod
    def execute(self, client: socket.socket, data: dict, context: dict) -> None:
        pass


class UploadCommand(Command):
    def __init__(self, event_bus, db, shared_folder, transaction_manager, connection_manager):
        self.event_bus = event_bus
        self.db = db
        self.shared_folder = shared_folder
        self.transaction_manager = transaction_manager
        self.connection_manager = connection_manager
    
    def execute(self, client, data, context):
        file_name = InputValidator.validate_filename(data.get('filename', ''))
        if not file_name:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid filename"})
            return
        file_size = data.get('size', 0)
        file_sha256 = data.get('sha256', '')
        username = context['username']
        connection_id = context['connection_id']
        
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
                self.transaction_manager.complete_transaction(transaction.id, success=False)
        except Exception as e:
            logging.error(f"Upload error: {e}")
            self.transaction_manager.complete_transaction(transaction.id, success=False)
        finally:
            self.connection_manager.clear_current_transaction(connection_id)


class DownloadCommand(Command):
    def __init__(self, event_bus, db, shared_folder, transaction_manager, connection_manager):
        self.event_bus = event_bus
        self.db = db
        self.shared_folder = shared_folder
        self.transaction_manager = transaction_manager
        self.connection_manager = connection_manager
    
    def execute(self, client, data, context):
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
                "type": "FILE_META", "filename": file_name,
                "size": file_size, "sha256": file_sha256
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
    def __init__(self, shared_folder):
        self.shared_folder = shared_folder
    
    def execute(self, client, data, context):
        files = []
        for f in os.listdir(self.shared_folder):
            full_path = os.path.join(self.shared_folder, f)
            if os.path.isfile(full_path):
                files.append({"name": f, "size": os.path.getsize(full_path)})
        JsonProtocol.send_message(client, {"type": "FILE_LIST", "files": files})


class UsersCommand(Command):
    def __init__(self, connection_manager):
        self.connection_manager = connection_manager
    
    def execute(self, client, data, context):
        connections = self.connection_manager.get_all_connections()
        user_list = [
            {"username": c.username, "ip": c.address[0], "mac": c.mac_address,
             "state": c.state.value, "uptime": int(time.time() - c.created_at)}
            for c in connections
        ]
        JsonProtocol.send_message(client, {"type": "USER_LIST", "users": user_list})


class StatsCommand(Command):
    def __init__(self, db):
        self.db = db
    
    def execute(self, client, data, context):
        username = context['username']
        stats = self.db.get_stats(username)
        if not stats:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "No stats found"})
            return
        JsonProtocol.send_message(client, {
            "type": "STATS", "username": username,
            "uploaded": stats['uploaded'], "downloaded": stats['downloaded'],
            "files_sent": stats['files_sent'], "files_received": stats['files_received']
        })


class QuitCommand(Command):
    def __init__(self, event_bus, connection_manager):
        self.event_bus = event_bus
        self.connection_manager = connection_manager
    
    def execute(self, client, data, context):
        connection_id = context['connection_id']
        username = context['username']
        self.connection_manager.update_state(connection_id, ConnectionState.CLOSING)
        self.event_bus.publish('user_disconnected', {
            'username': username, 'ip': context['address'][0]
        })


class DeleteCommand(Command):
    def __init__(self, event_bus, db, shared_folder):
        self.event_bus = event_bus
        self.db = db
        self.shared_folder = shared_folder
    
    def execute(self, client, data, context):
        file_name = InputValidator.validate_filename(data.get('filename', ''))
        if not file_name:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid filename"})
            return
        file_path = os.path.join(self.shared_folder, file_name)
        username = context['username']
        if not os.path.isfile(file_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "File not found"})
            return
        try:
            file_size = os.path.getsize(file_path)
            os.remove(file_path)
            JsonProtocol.send_message(client, {"type": "DELETE_OK", "filename": file_name})
            self.db.update_stats(username, uploaded=-file_size, files_received=-1)
            self.db.log_transfer(username, "Server", file_name, file_size, "DELETED")
            self.event_bus.publish('file_deleted', {
                'username': username, 'filename': file_name, 'size': file_size
            })
        except Exception as e:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": f"Delete failed: {e}"})


class RenameCommand(Command):
    def __init__(self, db, shared_folder):
        self.db = db
        self.shared_folder = shared_folder
    
    def execute(self, client, data, context):
        old_name = InputValidator.validate_filename(data.get('old_name', ''))
        new_name = InputValidator.validate_filename(data.get('new_name', ''))
        if not old_name or not new_name:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid filename(s)"})
            return
        old_path = os.path.join(self.shared_folder, old_name)
        new_path = os.path.join(self.shared_folder, new_name)
        if not os.path.isfile(old_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Source file not found"})
            return
        if os.path.exists(new_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Target exists"})
            return
        try:
            os.rename(old_path, new_path)
            JsonProtocol.send_message(client, {
                "type": "RENAME_OK", "old_name": old_name, "new_name": new_name
            })
            self.db.log_transfer(context['username'], "Server", 
                                 f"{old_name} → {new_name}", 0, "RENAMED")
        except Exception as e:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": f"Rename failed: {e}"})


class SearchCommand(Command):
    def __init__(self, shared_folder):
        self.shared_folder = shared_folder
    
    def execute(self, client, data, context):
        pattern = data.get('pattern', '').strip()
        if not pattern:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Empty pattern"})
            return
        regex = re.compile(fnmatch.translate(pattern), re.IGNORECASE)
        matches = []
        for filename in os.listdir(self.shared_folder):
            full_path = os.path.join(self.shared_folder, filename)
            if os.path.isfile(full_path) and regex.match(filename):
                matches.append({"name": filename, "size": os.path.getsize(full_path)})
        matches.sort(key=lambda x: x['name'].lower())
        JsonProtocol.send_message(client, {
            "type": "SEARCH_RESULTS", "pattern": pattern,
            "count": len(matches), "files": matches
        })


class ResumeUploadCommand(Command):
    def __init__(self, event_bus, db, shared_folder, transaction_manager, connection_manager):
        self.event_bus = event_bus
        self.db = db
        self.shared_folder = shared_folder
        self.transaction_manager = transaction_manager
        self.connection_manager = connection_manager
    
    def execute(self, client, data, context):
        file_name = InputValidator.validate_filename(data.get('filename', ''))
        if not file_name:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid filename"})
            return
        file_size = data.get('size', 0)
        file_sha256 = data.get('sha256', '')
        offset = data.get('offset', 0)
        username = context['username']
        connection_id = context['connection_id']
        save_path = os.path.join(self.shared_folder, file_name)
        if not os.path.isfile(save_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "No partial file"})
            return
        existing_size = os.path.getsize(save_path)
        if existing_size != offset:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Offset mismatch"})
            return
        transaction = self.transaction_manager.create_transaction(
            connection_id, username, 'resume_upload', file_name, file_size - offset
        )
        self.connection_manager.set_current_transaction(connection_id, transaction.id)
        JsonProtocol.send_message(client, {"type": "RESUME_OK", "offset": offset})
        received_size = offset
        try:
            with open(save_path, 'ab') as f:
                while received_size < file_size:
                    chunk = client.recv(min(4096, file_size - received_size))
                    if not chunk:
                        break
                    f.write(chunk)
                    received_size += len(chunk)
                    self.transaction_manager.update_progress(transaction.id, received_size - offset)
            if FileTransferUtils.calculate_sha256(save_path) == file_sha256:
                JsonProtocol.send_message(client, {"type": "FILE_OK"})
                self.db.update_stats(username, uploaded=file_size - offset, files_received=1)
                self.transaction_manager.complete_transaction(transaction.id, success=True)
            else:
                JsonProtocol.send_message(client, {"type": "FILE_CORRUPTED"})
                self.transaction_manager.complete_transaction(transaction.id, success=False)
        except Exception as e:
            logging.error(f"Resume upload error: {e}")
            self.transaction_manager.complete_transaction(transaction.id, success=False)
        finally:
            self.connection_manager.clear_current_transaction(connection_id)


class ResumeDownloadCommand(Command):
    def __init__(self, event_bus, db, shared_folder, transaction_manager, connection_manager):
        self.event_bus = event_bus
        self.db = db
        self.shared_folder = shared_folder
        self.transaction_manager = transaction_manager
        self.connection_manager = connection_manager
    
    def execute(self, client, data, context):
        file_name = InputValidator.validate_filename(data.get('filename', ''))
        if not file_name:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid filename"})
            return
        offset = data.get('offset', 0)
        file_path = os.path.join(self.shared_folder, file_name)
        username = context['username']
        connection_id = context['connection_id']
        if not os.path.isfile(file_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "File not found"})
            return
        file_size = os.path.getsize(file_path)
        if offset < 0 or offset >= file_size:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid offset"})
            return
        file_sha256 = FileTransferUtils.calculate_sha256(file_path)
        remaining_size = file_size - offset
        transaction = self.transaction_manager.create_transaction(
            connection_id, username, 'resume_download', file_name, remaining_size
        )
        self.connection_manager.set_current_transaction(connection_id, transaction.id)
        JsonProtocol.send_message(client, {
            "type": "RESUME_META", "filename": file_name,
            "size": file_size, "offset": offset,
            "remaining": remaining_size, "sha256": file_sha256
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
            self.db.update_stats(username, downloaded=remaining_size, files_sent=1)
            self.transaction_manager.complete_transaction(transaction.id, success=True)
        except Exception as e:
            logging.error(f"Resume download error: {e}")
            self.transaction_manager.complete_transaction(transaction.id, success=False)
        finally:
            self.connection_manager.clear_current_transaction(connection_id)


class ServerFingerprintCommand(Command):
    def __init__(self, cert_file):
        self.cert_file = cert_file
    
    def execute(self, client, data, context):
        try:
            if not os.path.exists(self.cert_file):
                JsonProtocol.send_message(client, {"type": "ERROR", "message": "No certificate"})
                return
            with open(self.cert_file, 'rb') as f:
                cert_data = f.read()
            fingerprint = hashlib.sha256(cert_data).hexdigest()
            safety_numbers = []
            for i in range(0, 25, 5):
                chunk = fingerprint[i:i+5]
                num = int(chunk, 16) % 100000
                safety_numbers.append(f"{num:05d}")
            JsonProtocol.send_message(client, {
                "type": "SERVER_FINGERPRINT",
                "safety_numbers": "-".join(safety_numbers),
                "fingerprint": fingerprint[:32]
            })
        except Exception as e:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Fingerprint error"})


class RequestTransferCommand(Command):
    def __init__(self, db, shared_folder, connection_manager, event_bus):
        self.db = db
        self.shared_folder = shared_folder
        self.connection_manager = connection_manager
        self.event_bus = event_bus
    
    def execute(self, client, data, context):
        from_user = context['username']
        to_user = data.get('to_user', '').strip()
        filename = data.get('filename', '').strip()
        if not InputValidator.validate_username(to_user):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid recipient"})
            return
        filename = InputValidator.validate_filename(filename)
        if not filename:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid filename"})
            return
        recipient_info = self.db.get_user_info(to_user)
        if not recipient_info:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "User not found"})
            return
        if from_user == to_user:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Cannot send to self"})
            return
        file_path = os.path.join(self.shared_folder, filename)
        if not os.path.isfile(file_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "File not found"})
            return
        file_size = os.path.getsize(file_path)
        file_sha256 = FileTransferUtils.calculate_sha256(file_path)
        request_id = self.db.create_transfer_request(
            from_user, to_user, filename, file_size, file_sha256
        )
        if not request_id:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Failed to create"})
            return
        JsonProtocol.send_message(client, {
            "type": "REQUEST_CREATED", "request_id": request_id,
            "to_user": to_user, "filename": filename, "file_size": file_size
        })
        recipient_conn = self.connection_manager.get_by_username(to_user)
        if recipient_conn:
            try:
                JsonProtocol.send_message(recipient_conn.socket, {
                    "type": "INCOMING_TRANSFER_REQUEST",
                    "request_id": request_id, "from_user": from_user,
                    "filename": filename, "file_size": file_size
                })
            except Exception:
                pass


class ListPendingRequestsCommand(Command):
    def __init__(self, db):
        self.db = db
    
    def execute(self, client, data, context):
        username = context['username']
        incoming = self.db.get_pending_requests_for_user(username)
        outgoing = self.db.get_pending_requests_from_user(username)
        JsonProtocol.send_message(client, {
            "type": "PENDING_REQUESTS", "incoming": incoming, "outgoing": outgoing
        })


class AcceptTransferCommand(Command):
    def __init__(self, db, shared_folder, connection_manager, event_bus):
        self.db = db
        self.shared_folder = shared_folder
        self.connection_manager = connection_manager
        self.event_bus = event_bus
    
    def execute(self, client, data, context):
        request_id = data.get('request_id', '').strip()
        username = context['username']
        request = self.db.get_transfer_request(request_id)
        if not request:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Not found"})
            return
        if request['to_user'] != username:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Not recipient"})
            return
        if request['status'] != 'pending':
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Already processed"})
            return
        if not self.db.accept_transfer_request(request_id):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Failed"})
            return
        JsonProtocol.send_message(client, {
            "type": "REQUEST_ACCEPTED", "request_id": request_id,
            "filename": request['filename'], "file_size": request['file_size']
        })
        sender_conn = self.connection_manager.get_by_username(request['from_user'])
        if sender_conn:
            try:
                JsonProtocol.send_message(sender_conn.socket, {
                    "type": "TRANSFER_REQUEST_ACCEPTED",
                    "request_id": request_id, "to_user": username
                })
            except Exception:
                pass


class RejectTransferCommand(Command):
    def __init__(self, db, connection_manager, event_bus):
        self.db = db
        self.connection_manager = connection_manager
        self.event_bus = event_bus
    
    def execute(self, client, data, context):
        request_id = data.get('request_id', '').strip()
        reason = data.get('reason', '').strip()
        username = context['username']
        request = self.db.get_transfer_request(request_id)
        if not request or request['to_user'] != username or request['status'] != 'pending':
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid"})
            return
        self.db.reject_transfer_request(request_id, reason)
        JsonProtocol.send_message(client, {"type": "REQUEST_REJECTED", "request_id": request_id})
        sender_conn = self.connection_manager.get_by_username(request['from_user'])
        if sender_conn:
            try:
                JsonProtocol.send_message(sender_conn.socket, {
                    "type": "TRANSFER_REQUEST_REJECTED",
                    "request_id": request_id, "to_user": username, "reason": reason
                })
            except Exception:
                pass


class CancelTransferCommand(Command):
    def __init__(self, db, connection_manager, event_bus):
        self.db = db
        self.connection_manager = connection_manager
        self.event_bus = event_bus
    
    def execute(self, client, data, context):
        request_id = data.get('request_id', '').strip()
        username = context['username']
        request = self.db.get_transfer_request(request_id)
        if not request or request['from_user'] != username or request['status'] != 'pending':
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid"})
            return
        self.db.cancel_transfer_request(request_id, username)
        JsonProtocol.send_message(client, {"type": "REQUEST_CANCELLED", "request_id": request_id})


# ============================================================================
# COMMAND FACTORY
# ============================================================================

class CommandFactory:
    def __init__(self, event_bus, db, connection_manager,
                 transaction_manager, shared_folder, cert_file):
        self.commands = {
            "UPLOAD": UploadCommand(event_bus, db, shared_folder, transaction_manager, connection_manager),
            "DOWNLOAD": DownloadCommand(event_bus, db, shared_folder, transaction_manager, connection_manager),
            "LIST": ListCommand(shared_folder),
            "USERS": UsersCommand(connection_manager),
            "STATS": StatsCommand(db),
            "QUIT": QuitCommand(event_bus, connection_manager),
            "DELETE": DeleteCommand(event_bus, db, shared_folder),
            "RENAME": RenameCommand(db, shared_folder),
            "SEARCH": SearchCommand(shared_folder),
            "RESUME_UPLOAD": ResumeUploadCommand(event_bus, db, shared_folder, transaction_manager, connection_manager),
            "RESUME_DOWNLOAD": ResumeDownloadCommand(event_bus, db, shared_folder, transaction_manager, connection_manager),
            "SERVER_FINGERPRINT": ServerFingerprintCommand(cert_file),
            "REQUEST_TRANSFER": RequestTransferCommand(db, shared_folder, connection_manager, event_bus),
            "LIST_PENDING_REQUESTS": ListPendingRequestsCommand(db),
            "ACCEPT_TRANSFER": AcceptTransferCommand(db, shared_folder, connection_manager, event_bus),
            "REJECT_TRANSFER": RejectTransferCommand(db, connection_manager, event_bus),
            "CANCEL_TRANSFER": CancelTransferCommand(db, connection_manager, event_bus),
        }
    
    def get_command(self, command_name: str) -> Optional[Command]:
        return self.commands.get(command_name)


# ============================================================================
# SUPPORTING CLASSES
# ============================================================================

class SSLManager:
    @staticmethod
    def generate_self_signed_cert(cert_file=None, key_file=None):
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
                return True
            except Exception:
                return False
        return True


class NetworkUtils:
    @staticmethod
    def get_mac_from_ip(ip_address):
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
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'


class ServiceDiscovery:
    def __init__(self, server_port, tls_enabled):
        self.server_port = server_port
        self.tls_enabled = tls_enabled
        self.broadcast_port = CONFIG["discovery"]["broadcast_port"]
        self.interval = CONFIG["discovery"]["interval"]
        self.running = False
        self.thread = None
    
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._broadcast_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.running = False
    
    def _broadcast_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        discovery_data = {
            "service": "julian", "version": "4.4.0",
            "port": self.server_port, "requires_auth": True, "tls": self.tls_enabled
        }
        while self.running:
            try:
                message = json.dumps(discovery_data).encode('utf-8')
                sock.sendto(message, ('<broadcast>', self.broadcast_port))
                time.sleep(self.interval)
            except Exception:
                time.sleep(self.interval)
        sock.close()


# ============================================================================
# SYSTEM MONITOR (Zero Dependencies - reads from /proc/)
# ============================================================================

class SystemMonitor:
    """Monitor system resources using only Python standard library."""
    
    def __init__(self, history_size=60):
        self.history_size = history_size
        self.cpu_history = deque(maxlen=history_size)
        self.ram_history = deque(maxlen=history_size)
        self.net_upload_history = deque(maxlen=history_size)
        self.net_download_history = deque(maxlen=history_size)
        
        self._prev_cpu = self._read_cpu_raw()
        self._prev_net = self._read_net_raw()
        self._prev_time = time.time()
        
        self.active_connections = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
    
    def _read_cpu_raw(self):
        try:
            with open('/proc/stat', 'r') as f:
                line = f.readline()
                parts = line.split()
                idle = int(parts[4]) + int(parts[5])
                total = sum(int(x) for x in parts[1:8])
                return idle, total
        except Exception:
            return 0, 0
    
    def _read_ram_info(self):
        try:
            info = {}
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0].rstrip(':')
                        value = int(parts[1])
                        info[key] = value
                    if len(info) >= 5:
                        break
            
            total_kb = info.get('MemTotal', 0)
            available_kb = info.get('MemAvailable', info.get('MemFree', 0))
            used_kb = total_kb - available_kb
            
            total_gb = total_kb / (1024 * 1024)
            used_gb = used_kb / (1024 * 1024)
            percent = (used_kb / total_kb * 100) if total_kb > 0 else 0
            
            return total_gb, used_gb, percent
        except Exception:
            return 0, 0, 0
    
    def _read_net_raw(self):
        try:
            total_recv = 0
            total_sent = 0
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if ':' in line:
                        parts = line.split()
                        iface = parts[0].rstrip(':')
                        if iface == 'lo':
                            continue
                        total_recv += int(parts[1])
                        total_sent += int(parts[9])
            return total_recv, total_sent
        except Exception:
            return 0, 0
    
    def update(self, connection_manager=None):
        now = time.time()
        time_delta = now - self._prev_time
        if time_delta <= 0:
            time_delta = 1
        
        curr_cpu = self._read_cpu_raw()
        if self._prev_cpu[1] > 0 and curr_cpu[1] > 0:
            idle_delta = curr_cpu[0] - self._prev_cpu[0]
            total_delta = curr_cpu[1] - self._prev_cpu[1]
            if total_delta > 0:
                cpu_percent = (1 - idle_delta / total_delta) * 100
            else:
                cpu_percent = 0
        else:
            cpu_percent = 0
        self.cpu_history.append(max(0, min(100, cpu_percent)))
        self._prev_cpu = curr_cpu
        
        total_gb, used_gb, ram_percent = self._read_ram_info()
        self.ram_history.append(ram_percent)
        
        curr_net = self._read_net_raw()
        recv_delta = curr_net[0] - self._prev_net[0]
        sent_delta = curr_net[1] - self._prev_net[1]
        
        upload_mbps = (sent_delta / time_delta) / (1024 * 1024)
        download_mbps = (recv_delta / time_delta) / (1024 * 1024)
        
        self.net_upload_history.append(max(0, upload_mbps))
        self.net_download_history.append(max(0, download_mbps))
        self._prev_net = curr_net
        self._prev_time = now
        
        if connection_manager:
            stats = connection_manager.get_stats()
            self.active_connections = stats['total_connections']
            self.total_bytes_sent = stats['total_bytes_sent']
            self.total_bytes_received = stats['total_bytes_received']
    
    def _make_chart(self, data, width=40, height=5, max_val=None):
        if not data:
            return [" " * width] * height
        
        values = list(data)[-width:]
        if max_val is None:
            max_val = max(values) if values else 1
        if max_val == 0:
            max_val = 1
        
        lines = []
        for row in range(height):
            threshold = max_val * (height - row) / height
            line = ""
            for v in values:
                if v >= threshold:
                    line += "█"
                elif v >= threshold * 0.5:
                    line += "▄"
                else:
                    line += " "
            line = line.ljust(width)
            lines.append(line)
        return lines
    
    def generate_dashboard(self, server_uptime=0):
        self.update()
        
        cpu_now = self.cpu_history[-1] if self.cpu_history else 0
        ram_now = self.ram_history[-1] if self.ram_history else 0
        total_gb, used_gb, _ = self._read_ram_info()
        up_now = self.net_upload_history[-1] if self.net_upload_history else 0
        down_now = self.net_download_history[-1] if self.net_download_history else 0
        
        cpu_chart = self._make_chart(self.cpu_history, width=40, height=4, max_val=100)
        ram_chart = self._make_chart(self.ram_history, width=40, height=4, max_val=100)
        up_chart = self._make_chart(self.net_upload_history, width=40, height=3)
        down_chart = self._make_chart(self.net_download_history, width=40, height=3)
        
        G = "\033[92m"
        Y = "\033[93m"
        R = "\033[91m"
        C = "\033[96m"
        B = "\033[94m"
        W = "\033[97m"
        D = "\033[90m"
        N = "\033[0m"
        
        cpu_color = G if cpu_now < 50 else (Y if cpu_now < 80 else R)
        ram_color = G if ram_now < 60 else (Y if ram_now < 85 else R)
        
        lines = []
        lines.append(f"{C}╔{'═'*72}╗{N}")
        lines.append(f"{C}║{W}              📊 Julian Server - Live System Monitor{N}              {C}║{N}")
        lines.append(f"{C}╠{'═'*72}╣{N}")
        lines.append(f"{C}║{N}                                                                      {C}║{N}")
        lines.append(f"{C}║{W}  🖥️  CPU: {cpu_color}{cpu_now:5.1f}%{N}          🧠 RAM: {ram_color}{used_gb:.2f} / {total_gb:.2f} GB ({ram_now:.1f}%){N}    {C}║{N}")
        lines.append(f"{C}║{D}  {'─'*32}        {'─'*32}{N}  {C}║{N}")
        
        for i in range(4):
            cpu_line = cpu_chart[i] if i < len(cpu_chart) else " " * 40
            ram_line = ram_chart[i] if i < len(ram_chart) else " " * 40
            lines.append(f"{C}║{N}  {G}{cpu_line}{N}  {B}{ram_line}{N}  {C}║{N}")
        
        lines.append(f"{C}║{N}                                                                      {C}║{N}")
        lines.append(f"{C}║{W}  📤 Upload: {G}{up_now:7.2f} MB/s{N}       📥 Download: {B}{down_now:7.2f} MB/s{N}        {C}║{N}")
        lines.append(f"{C}║{D}  {'─'*32}        {'─'*32}{N}  {C}║{N}")
        
        for i in range(3):
            up_line = up_chart[i] if i < len(up_chart) else " " * 40
            down_line = down_chart[i] if i < len(down_chart) else " " * 40
            lines.append(f"{C}║{N}  {G}{up_line}{N}  {B}{down_line}{N}  {C}║{N}")
        
        lines.append(f"{C}║{N}                                                                      {C}║{N}")
        lines.append(f"{C}║{W}  🔗 Connections: {G}{self.active_connections}{N}   "
                      f"📤 Total Sent: {G}{self.format_size(self.total_bytes_sent)}{N}   "
                      f"📥 Recv: {B}{self.format_size(self.total_bytes_received)}{N}  {C}║{N}")
        lines.append(f"{C}║{W}  ⏱️  Uptime: {G}{FileTransferUtils.format_uptime(server_uptime)}{N}   "
                      f"🔄 Refresh: {G}2s{N}   "
                      f"📊 History: {G}{len(self.cpu_history)}/{self.history_size}{N} pts{N}          {C}║{N}")
        lines.append(f"{C}║{N}                                                                      {C}║{N}")
        lines.append(f"{C}║{D}  Press Ctrl+C to return to CLI admin{N}                                 {C}║{N}")
        lines.append(f"{C}╚{'═'*72}╝{N}")
        
        return "\n".join(lines)


class LiveMonitor:
    def __init__(self, server):
        self.server = server
        self.monitor = SystemMonitor(history_size=60)
        self.running = False
    
    def start(self):
        self.running = True
        print("\033[2J\033[H")
        
        try:
            while self.running:
                print("\033[H", end="")
                uptime = time.time() - self.server.connection_manager._start_time
                dashboard = self.monitor.generate_dashboard(server_uptime=uptime)
                print(dashboard)
                sys.stdout.flush()
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            print("\033[2J\033[H")
            print("🔙 Returned to CLI admin\n")


# ============================================================================
# TUI ADMIN DASHBOARD (Using curses - Zero Dependencies)
# ============================================================================

class CursesDashboard:
    def __init__(self, server):
        self.server = server
        self.monitor = SystemMonitor(history_size=40)
        self.selected_user = 0
        self.selected_banned = 0
        self.active_panel = "users"
        self.running = False
    
    def start(self):
        import curses
        
        def _main(stdscr):
            self.running = True
            curses.curs_set(0)
            stdscr.nodelay(True)
            stdscr.timeout(2000)
            
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
            curses.init_pair(3, curses.COLOR_RED, -1)
            curses.init_pair(4, curses.COLOR_CYAN, -1)
            curses.init_pair(5, curses.COLOR_BLUE, -1)
            curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_BLUE)
            curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_GREEN)
            curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_RED)
            
            while self.running:
                try:
                    self._draw(stdscr)
                    key = stdscr.getch()
                    
                    if key == ord('q') or key == 27:
                        break
                    elif key == ord('j') or key == curses.KEY_DOWN:
                        self._move_down()
                    elif key == ord('k') or key == curses.KEY_UP:
                        self._move_up()
                    elif key == ord('\t'):
                        self.active_panel = "banned" if self.active_panel == "users" else "users"
                    elif key == ord('K'):
                        self._kick_user(stdscr)
                    elif key == ord('B'):
                        self._ban_user(stdscr)
                    elif key == ord('U'):
                        self._unban_user(stdscr)
                    elif key == ord('G'):
                        self._generate_code(stdscr)
                    elif key == ord('?'):
                        self._show_help(stdscr)
                
                except curses.error:
                    pass
                except Exception:
                    pass
        
        try:
            curses.wrapper(_main)
        except Exception as e:
            print(f"❌ Dashboard error: {e}")
        finally:
            print("\n🔙 Returned to CLI admin\n")
    
    def _draw(self, stdscr):
        import curses
        
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        
        if h < 20 or w < 80:
            stdscr.addstr(0, 0, "Terminal too small! Need at least 80x20")
            stdscr.refresh()
            return
        
        self.monitor.update(self.server.connection_manager)
        connections = self.server.connection_manager.get_all_connections()
        banned = self.server.db.get_banned_users()
        
        header = f" Julian Admin Dashboard v4.4.0 "
        stdscr.attron(curses.color_pair(6))
        stdscr.addstr(0, 0, header.center(w))
        stdscr.attroff(curses.color_pair(6))
        
        panel_w = w // 2 - 1
        y = 2
        
        users_title = f" Active Users ({len(connections)}/{self.server.connection_manager.max_connections}) "
        if self.active_panel == "users":
            stdscr.attron(curses.color_pair(7))
        else:
            stdscr.attron(curses.color_pair(4))
        stdscr.addstr(y, 1, users_title.center(panel_w))
        stdscr.attroff(curses.color_pair(7) if self.active_panel == "users" else curses.color_pair(4))
        
        y += 1
        
        for i, conn in enumerate(connections[:h-8]):
            state_icon = {
                'authenticating': '?', 'idle': 'z',
                'transferring': '>', 'closing': 'x'
            }.get(conn.state.value, '?')
            
            line = f"  [{state_icon}] {conn.username:<12} {conn.address[0]:<15} {conn.state.value}"
            line = line[:panel_w-2]
            
            if i == self.selected_user and self.active_panel == "users":
                stdscr.attron(curses.A_REVERSE)
            
            try:
                stdscr.addstr(y + i, 1, line.ljust(panel_w))
            except curses.error:
                pass
            
            if i == self.selected_user and self.active_panel == "users":
                stdscr.attroff(curses.A_REVERSE)
        
        if not connections:
            try:
                stdscr.addstr(y, 1, "  (no active users)")
            except curses.error:
                pass
        
        rx = panel_w + 2
        stdscr.attron(curses.color_pair(5))
        stdscr.addstr(2, rx, " Details ".center(panel_w))
        stdscr.attroff(curses.color_pair(5))
        
        if connections and self.selected_user < len(connections):
            conn = connections[self.selected_user]
            stats = self.server.db.get_stats(conn.username) or {
                'uploaded': 0, 'downloaded': 0,
                'files_sent': 0, 'files_received': 0
            }
            uptime = int(time.time() - conn.created_at)
            
            details = [
                f"User: {conn.username}",
                f"IP: {conn.address[0]}",
                f"MAC: {conn.mac_address}",
                f"Device: {conn.device_type}",
                f"State: {conn.state.value.upper()}",
                f"Uptime: {uptime//3600:02d}:{(uptime%3600)//60:02d}:{uptime%60:02d}",
                "",
                f"Uploaded: {FileTransferUtils.format_size(stats['uploaded'])}",
                f"Downloaded: {FileTransferUtils.format_size(stats['downloaded'])}",
                f"Files Sent: {stats['files_sent']}",
                f"Files Recv: {stats['files_received']}",
            ]
            
            for i, line in enumerate(details):
                try:
                    stdscr.addstr(3 + i, rx, line[:panel_w-2])
                except curses.error:
                    pass
        
        by = h - 7
        banned_title = f" Banned Users ({len(banned)}) "
        if self.active_panel == "banned":
            stdscr.attron(curses.color_pair(8))
        else:
            stdscr.attron(curses.color_pair(3))
        stdscr.addstr(by, 0, banned_title.center(w))
        stdscr.attroff(curses.color_pair(8) if self.active_panel == "banned" else curses.color_pair(3))
        
        for i, b in enumerate(banned[:3]):
            line = f"  [X] {b[0]:<15} {b[1][:10]} | {b[2]}"
            line = line[:w-2]
            
            if i == self.selected_banned and self.active_panel == "banned":
                stdscr.attron(curses.A_REVERSE)
            
            try:
                stdscr.addstr(by + 1 + i, 0, line.ljust(w))
            except curses.error:
                pass
            
            if i == self.selected_banned and self.active_panel == "banned":
                stdscr.attroff(curses.A_REVERSE)
        
        cpu_now = self.monitor.cpu_history[-1] if self.monitor.cpu_history else 0
        ram_now = self.monitor.ram_history[-1] if self.monitor.ram_history else 0
        up_now = self.monitor.net_upload_history[-1] if self.monitor.net_upload_history else 0
        down_now = self.monitor.net_download_history[-1] if self.monitor.net_download_history else 0
        
        status = (
            f" CPU:{cpu_now:.0f}% | RAM:{ram_now:.0f}% | "
            f"Up:{up_now:.1f}MB/s | Dn:{down_now:.1f}MB/s | "
            f"Conn:{len(connections)} | "
            f"[K]ick [B]an [U]nban [G]enCode [?]Help [q]uit"
        )
        
        stdscr.attron(curses.color_pair(6))
        try:
            stdscr.addstr(h - 1, 0, status[:w].ljust(w))
        except curses.error:
            pass
        stdscr.attroff(curses.color_pair(6))
        
        stdscr.refresh()
    
    def _move_down(self):
        if self.active_panel == "users":
            connections = self.server.connection_manager.get_all_connections()
            if connections:
                self.selected_user = min(self.selected_user + 1, len(connections) - 1)
        else:
            banned = self.server.db.get_banned_users()
            if banned:
                self.selected_banned = min(self.selected_banned + 1, len(banned) - 1)
    
    def _move_up(self):
        if self.active_panel == "users":
            self.selected_user = max(0, self.selected_user - 1)
        else:
            self.selected_banned = max(0, self.selected_banned - 1)
    
    def _kick_user(self, stdscr):
        import curses
        connections = self.server.connection_manager.get_all_connections()
        if not connections or self.selected_user >= len(connections):
            return
        conn = connections[self.selected_user]
        
        stdscr.nodelay(False)
        stdscr.addstr(stdscr.getmaxyx()[0] - 2, 0, 
                      f" Kick {conn.username}? (y/n): ")
        stdscr.refresh()
        key = stdscr.getch()
        stdscr.nodelay(True)
        
        if key == ord('y'):
            self.server.connection_manager.kick_user(conn.username, "Kicked from dashboard")
            self.server.db.log_admin_action("KICK", conn.username, "Dashboard")
    
    def _ban_user(self, stdscr):
        import curses
        connections = self.server.connection_manager.get_all_connections()
        if not connections or self.selected_user >= len(connections):
            return
        conn = connections[self.selected_user]
        
        stdscr.nodelay(False)
        stdscr.addstr(stdscr.getmaxyx()[0] - 2, 0, 
                      f" Ban {conn.username}? (y/n): ")
        stdscr.refresh()
        key = stdscr.getch()
        stdscr.nodelay(True)
        
        if key == ord('y'):
            self.server.db.ban_user(conn.username, "Banned from dashboard")
            self.server.connection_manager.kick_user(conn.username, "Banned")
            self.server.db.log_admin_action("BAN", conn.username, "Dashboard")
    
    def _unban_user(self, stdscr):
        import curses
        banned = self.server.db.get_banned_users()
        if not banned or self.selected_banned >= len(banned):
            return
        
        stdscr.nodelay(False)
        stdscr.addstr(stdscr.getmaxyx()[0] - 2, 0, 
                      f" Unban {banned[self.selected_banned][0]}? (y/n): ")
        stdscr.refresh()
        key = stdscr.getch()
        stdscr.nodelay(True)
        
        if key == ord('y'):
            self.server.db.unban_user(banned[self.selected_banned][0])
            self.server.db.log_admin_action("UNBAN", banned[self.selected_banned][0], "Dashboard")
    
    def _generate_code(self, stdscr):
        import curses
        connections = self.server.connection_manager.get_all_connections()
        if not connections or self.selected_user >= len(connections):
            return
        conn = connections[self.selected_user]
        
        user_info = self.server.db.get_user_info(conn.username)
        if user_info:
            code = self.server.db.create_pairing_request(
                conn.username, user_info['ip'], 
                user_info['fingerprint'], "Dashboard"
            )
            self.server.db.log_admin_action("GEN_CODE", conn.username, f"Code: {code}")
            
            stdscr.nodelay(False)
            stdscr.addstr(stdscr.getmaxyx()[0] - 2, 0, 
                          f" Code for {conn.username}: {code} | Press any key...")
            stdscr.refresh()
            stdscr.getch()
            stdscr.nodelay(True)
    
    def _show_help(self, stdscr):
        import curses
        stdscr.nodelay(False)
        stdscr.erase()
        
        help_text = [
            "=== Julian Admin Dashboard - Help ===",
            "",
            "NAVIGATION:",
            "  j / Down    Move down",
            "  k / Up      Move up",
            "  Tab         Switch panels (Users/Banned)",
            "",
            "ACTIONS:",
            "  K           Kick selected user",
            "  B           Ban selected user",
            "  U           Unban selected user",
            "  G           Generate login code",
            "  r           Refresh data",
            "",
            "OTHER:",
            "  ?           Show this help",
            "  q / ESC     Quit dashboard",
            "",
            "Press any key to continue..."
        ]
        
        for i, line in enumerate(help_text):
            try:
                stdscr.addstr(i, 2, line)
            except curses.error:
                pass
        
        stdscr.refresh()
        stdscr.getch()
        stdscr.nodelay(True)


# ============================================================================
# CLI ADMIN
# ============================================================================

class AdminCLI:
    def __init__(self, server):
        self.server = server
    
    def run(self):
        while True:
            try:
                cmd = input("\n[Admin] >>> ").strip()
                
                if cmd.lower() == 'help':
                    print("""
Commands:
  users              - Show active users
  devices            - Show all registered devices
  pending            - Show pending pairing requests
  security           - Show recent security events
  all_users          - Show all historical users
  banned             - Show banned users
  banned_macs        - Show banned MAC addresses
  connections        - Show connection statistics
  transactions       - Show active transactions
  files              - Show shared files
  requests           - Show transfer requests
  audit              - Show admin audit log
  code <username>    - Generate login code
  push <user> <file> - Send file to user
  kick <user> [reason] - Kick user
  ban <user> [reason]    - Ban a user
  unban <user>           - Unban a user
  ban_mac <mac> [reason] - Ban a device by MAC
  unban_mac <mac>        - Unban a MAC
  stats <user>           - Show user statistics
  monitor              - Launch live system monitor
  dashboard            - Launch TUI dashboard
  quit                   - Exit server
                    """)
                
                elif cmd.lower() == 'users':
                    connections = self.server.connection_manager.get_all_connections()
                    print(f"\n👥 Active Users ({len(connections)}):")
                    for c in connections:
                        print(f"  👤 {c.username} | {c.address[0]} | 🔗 {c.mac_address} | State: {c.state.value}")
                
                elif cmd.lower() == 'connections':
                    stats = self.server.connection_manager.get_stats()
                    print(f"\n🔌 Connection Statistics:")
                    print(f"  Total: {stats['total_connections']}/{stats['max_connections']}")
                    print(f"  Active: {stats['active']}")
                    print(f"  Idle: {stats['idle']}")
                    print(f"  Transferring: {stats['transferring']}")
                    print(f"  Total Sent: {FileTransferUtils.format_size(stats['total_bytes_sent'])}")
                    print(f"  Total Received: {FileTransferUtils.format_size(stats['total_bytes_received'])}")
                    print(f"  Uptime: {FileTransferUtils.format_uptime(stats['uptime'])}")
                
                elif cmd.lower() == 'transactions':
                    stats = self.server.transaction_manager.get_stats()
                    print(f"\n📊 Transaction Statistics:")
                    print(f"  Total: {stats['total']}")
                    print(f"  Active: {stats['active']}")
                    print(f"  Completed: {stats['completed']}")
                    print(f"  Failed: {stats['failed']}")
                
                elif cmd.lower() == 'devices':
                    devices = self.server.db.get_all_devices()
                    print(f"\n🖥️ All Registered Devices ({len(devices)}):")
                    for d in devices:
                        print(f"  📍 {d[0]} | 🔗 {d[1]} | 👤 {d[2]} | 🔏 {d[3][:8]}... | 💻 {d[4]} | 📦 {d[5]} | 📱 {d[6]} | Last: {d[7]}")
                
                elif cmd.lower() == 'pending':
                    pending = self.server.db.get_pending_pairing_requests()
                    if not pending:
                        print("\n📭 No pending pairing requests")
                    else:
                        print(f"\n⏳ Pending Pairing Requests ({len(pending)}):")
                        for p in pending:
                            print(f"  👤 {p[0]} | 🔑 \033[1;33m{p[1]}\033[0m | 📍 {p[2]} | 🔏 {p[3][:8]}... | 🖥️ {p[4]} | Expires: {p[5]}")
                
                elif cmd.lower() == 'security':
                    logs = self.server.db.get_security_logs(20)
                    if not logs:
                        print("\n🛡️ No security events recorded")
                    else:
                        print(f"\n🛡️ Recent Security Events ({len(logs)}):")
                        for l in logs:
                            print(f"  📍 {l[0]} | 🔗 {l[1]} | ⚠️ {l[2]} | {l[3]} | {l[4]}")
                
                elif cmd.lower() == 'audit':
                    logs = self.server.db.get_admin_audit_log(20)
                    if not logs:
                        print("\n📜 No admin actions recorded")
                    else:
                        print(f"\n📜 Recent Admin Actions ({len(logs)}):")
                        for l in logs:
                            print(f"  ⚡ {l[0]} | 🎯 {l[1]} | 📝 {l[2]} | 📅 {l[3]}")
                
                elif cmd.lower() == 'all_users':
                    users = self.server.db.get_all_users()
                    print(f"\n📜 All Registered Users ({len(users)}):")
                    for u in users:
                        print(f"  👤 {u[0]} | Last IP: {u[1]} | MAC: {u[2]} | 🔏 {u[3][:8]}... | Last Seen: {u[5]}")
                
                elif cmd.lower() == 'banned':
                    banned = self.server.db.get_banned_users()
                    print(f"\n🚫 Banned Users ({len(banned)}):")
                    for b in banned:
                        print(f"  ❌ {b[0]} | Banned: {b[1]} | Reason: {b[2]}")
                
                elif cmd.lower() == 'banned_macs':
                    banned = self.server.db.get_banned_macs()
                    print(f"\n🚫 Banned MAC Addresses ({len(banned)}):")
                    for b in banned:
                        print(f"  ❌ {b[0]} | Banned: {b[1]} | Reason: {b[2]}")
                
                elif cmd.lower() == 'requests':
                    requests = self.server.db.get_all_transfer_requests(20)
                    if not requests:
                        print("\n📭 No transfer requests")
                    else:
                        print(f"\n📬 Recent Transfer Requests ({len(requests)}):")
                        print("=" * 100)
                        for r in requests:
                            status_icon = {
                                'pending': '⏳', 'accepted': '✅', 'rejected': '❌',
                                'cancelled': '🚫', 'completed': '✓', 'expired': '⌛'
                            }.get(r[5], '?')
                            print(f"  {status_icon} {r[0][:8]}... | {r[1]} → {r[2]} | {r[3]} ({FileTransferUtils.format_size(r[4])}) | {r[5]} | {r[6]}")
                        print("=" * 100)
                
                elif cmd.lower().startswith('code '):
                    parts = cmd.split(' ', 1)
                    if len(parts) == 2:
                        username = parts[1].strip()
                        if not InputValidator.validate_username(username):
                            print(f"❌ Invalid username format: '{username}'")
                            continue
                        user_info = self.server.db.get_user_info(username)
                        if not user_info:
                            print(f"❌ User '{username}' not found.")
                        else:
                            if self.server.db.is_user_banned(username):
                                print(f"❌ User '{username}' is banned.")
                                continue
                            code = self.server.db.create_pairing_request(
                                username, user_info['ip'], user_info['fingerprint'], "Admin CLI"
                            )
                            self.server.db.log_admin_action("GEN_CODE", username, f"Code: {code}")
                            print(f"\n" + "=" * 60)
                            print(f"🔑 LOGIN CODE GENERATED")
                            print(f"=" * 60)
                            print(f"   👤 User: {username}")
                            print(f"   🔑 Code: \033[1;33m{code}\033[0m")
                            print(f"   ⏰  Expires in: {self.server.config['security']['code_expiry']} seconds")
                            print(f"=" * 60 + "\n")
                    else:
                        print("❌ Usage: code <username>")
                
                elif cmd.lower().startswith('kick '):
                    parts = cmd.split(' ', 2)
                    if len(parts) >= 2:
                        username = parts[1]
                        reason = parts[2] if len(parts) > 2 else "Kicked by admin"
                        if self.server.connection_manager.kick_user(username, reason):
                            self.server.db.log_admin_action("KICK", username, reason)
                            print(f"✅ User '{username}' kicked. Reason: {reason}")
                        else:
                            print(f"❌ User '{username}' not found or not connected")
                    else:
                        print("❌ Usage: kick <username> [reason]")
                
                elif cmd.lower().startswith('push '):
                    parts = cmd.split(' ', 2)
                    if len(parts) == 3:
                        username = parts[1].strip()
                        filename = parts[2].strip()
                        if not InputValidator.validate_username(username):
                            print(f"❌ Invalid username: '{username}'")
                            continue
                        filename = InputValidator.validate_filename(filename)
                        if not filename:
                            print(f"❌ Invalid filename: '{filename}'")
                            continue
                        user_info = self.server.db.get_user_info(username)
                        if not user_info:
                            print(f"❌ User '{username}' not found")
                            continue
                        file_path = os.path.join(self.server.shared_folder, filename)
                        if not os.path.isfile(file_path):
                            print(f"❌ File '{filename}' not found on server")
                            continue
                        file_size = os.path.getsize(file_path)
                        file_sha256 = FileTransferUtils.calculate_sha256(file_path)
                        request_id = self.server.db.create_transfer_request(
                            "SERVER", username, filename, file_size, file_sha256
                        )
                        if not request_id:
                            print(f"❌ Failed to create transfer request")
                            continue
                        self.server.db.log_admin_action("PUSH", username, f"File: {filename}")
                        print(f"\n" + "=" * 60)
                        print(f"📤 FILE PUSH REQUEST CREATED")
                        print(f"=" * 60)
                        print(f"   👤 To: {username}")
                        print(f"   📄 File: {filename} ({FileTransferUtils.format_size(file_size)})")
                        print(f"   🆔 Request ID: {request_id}")
                        print(f"=" * 60 + "\n")
                        user_conn = self.server.connection_manager.get_by_username(username)
                        if user_conn:
                            try:
                                JsonProtocol.send_message(user_conn.socket, {
                                    "type": "INCOMING_TRANSFER_REQUEST",
                                    "request_id": request_id, "from_user": "SERVER",
                                    "filename": filename, "file_size": file_size
                                })
                                print(f"✅ User '{username}' is online and has been notified")
                            except Exception:
                                pass
                        else:
                            print(f"⚠️  User '{username}' is offline, will be notified on next login")
                    else:
                        print("❌ Usage: push <username> <filename>")
                
                elif cmd.lower().startswith('ban '):
                    parts = cmd.split(' ', 2)
                    if len(parts) >= 2:
                        username = parts[1]
                        reason = parts[2] if len(parts) > 2 else "No reason provided"
                        self.server.db.ban_user(username, reason)
                        self.server.db.log_admin_action("BAN", username, reason)
                        print(f"✅ User '{username}' banned. Reason: {reason}")
                
                elif cmd.lower().startswith('unban '):
                    parts = cmd.split(' ', 1)
                    if len(parts) == 2:
                        username = parts[1]
                        if self.server.db.unban_user(username):
                            self.server.db.log_admin_action("UNBAN", username)
                            print(f"✅ User '{username}' unbanned.")
                        else:
                            print(f"⚠️  User '{username}' was not banned.")
                
                elif cmd.lower().startswith('ban_mac '):
                    parts = cmd.split(' ', 2)
                    if len(parts) >= 2:
                        mac = parts[1].lower()
                        reason = parts[2] if len(parts) > 2 else "No reason provided"
                        self.server.db.ban_mac(mac, reason)
                        self.server.db.log_admin_action("BAN_MAC", mac, reason)
                        print(f"✅ MAC '{mac}' banned. Reason: {reason}")
                
                elif cmd.lower().startswith('unban_mac '):
                    parts = cmd.split(' ', 1)
                    if len(parts) == 2:
                        mac = parts[1].lower()
                        if self.server.db.unban_mac(mac):
                            self.server.db.log_admin_action("UNBAN_MAC", mac)
                            print(f"✅ MAC '{mac}' unbanned.")
                        else:
                            print(f"⚠️  MAC '{mac}' was not banned.")
                
                elif cmd.lower().startswith('stats '):
                    stats = self.server.db.get_stats(cmd.split(' ', 1)[1].strip())
                    if stats:
                        print(f"\n📊 Uploaded: {FileTransferUtils.format_size(stats['uploaded'])} | "
                              f"Downloaded: {FileTransferUtils.format_size(stats['downloaded'])}")
                    else:
                        print("User not found.")
                
                elif cmd.lower() == 'files':
                    files = os.listdir(self.server.shared_folder)
                    if not files:
                        print("\n📭 No files in shared folder")
                    else:
                        print(f"\n📁 Shared Files ({len(files)}):")
                        for f in files:
                            path = os.path.join(self.server.shared_folder, f)
                            if os.path.isfile(path):
                                size = os.path.getsize(path)
                                print(f"  📄 {f} ({FileTransferUtils.format_size(size)})")
                
                elif cmd.lower() == 'monitor':
                    print("📊 Launching live system monitor...")
                    print("💡 Press Ctrl+C to return to admin CLI\n")
                    monitor = LiveMonitor(self.server)
                    monitor.start()
                
                elif cmd.lower() == 'dashboard':
                    try:
                        import curses
                        print("🎛️  Launching TUI dashboard...")
                        dashboard = CursesDashboard(self.server)
                        dashboard.start()
                    except ImportError:
                        print("❌ curses not available")
                    except Exception as e:
                        print(f"❌ Dashboard error: {e}")
                
                elif cmd.lower() == 'quit':
                    os._exit(0)
                
                elif cmd.strip():
                    print(f"❌ Unknown command: '{cmd}'")
                    print("💡 Type 'help' for available commands")
            
            except KeyboardInterrupt:
                print("\n\n🛑 Use 'quit' to exit the server")
            except Exception as e:
                print(f"❌ Error: {e}")


# ============================================================================
# MAIN SERVER CLASS
# ============================================================================

class SecureServer:
    def __init__(self, config=None):
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
        self.heartbeat_monitor = HeartbeatMonitor(self.connection_manager, self.db)
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
        self.discovery = None
        if self.config["discovery"]["enabled"]:
            self.discovery = ServiceDiscovery(self.port, self.ssl_enabled)
    
    def start(self, dashboard_mode=False) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.ssl_enabled and self.context:
            self.server_socket = self.context.wrap_socket(
                self.server_socket, server_side=True
            )
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.config["server"]["max_clients"])
        ip = NetworkUtils.get_local_ip()
        print("=" * 70)
        print("🔒 Julian Server v4.4.0 (with Admin Dashboard)")
        print("=" * 70)
        print(f"📍 IP: {ip} | 📌 Port: {self.port} | 🔑 Pass: {self.password}")
        print(f"🔐 Encryption: {'TLS 1.3 Enabled' if self.ssl_enabled else 'DISABLED'}")
        print(f"🛡️  Stealth Mode: ENABLED")
        print(f"📡 Discovery: {'Enabled' if self.discovery else 'Disabled'}")
        print(f"📁 Shared: {os.path.abspath(self.shared_folder)}")
        print("-" * 70)
        print("🎨 Admin Interface:")
        if dashboard_mode:
            print("   🎛️  TUI Dashboard Mode (active)")
        else:
            print("   💻 CLI Admin Mode (type 'dashboard' to switch to TUI)")
            print("   📊 Type 'monitor' for live system stats")
        print("-" * 70)
        print("=" * 70)
        print("Type 'help' for admin commands.\n")
        
        if self.discovery:
            self.discovery.start()
        self.heartbeat_monitor.start()
        
        if dashboard_mode:
            dashboard = CursesDashboard(self)
            admin_thread = threading.Thread(target=dashboard.start, daemon=True)
            admin_thread.start()
        else:
            admin_cli = AdminCLI(self)
            admin_thread = threading.Thread(target=admin_cli.run, daemon=True)
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
    
    def _silent_close(self, client, ip, mac, attempt_type, details):
        self.db.log_security_event(ip, mac, attempt_type, details)
        try:
            client.close()
        except Exception:
            pass
    
    def _handle_client(self, client, addr):
        connection = None
        try:
            auth_timeout = self.config["security"]["auth_timeout"]
            client.settimeout(auth_timeout)
            try:
                initial_msg = JsonProtocol.recv_message(client, timeout=auth_timeout)
            except socket.timeout:
                self._silent_close(client, addr[0], "unknown",
                                    "TIMEOUT", f"No auth within {auth_timeout}s")
                return
            if not initial_msg:
                self._silent_close(client, addr[0], "unknown", "EMPTY", "Empty data")
                return
            client.settimeout(None)
            mac_address = NetworkUtils.get_mac_from_ip(addr[0])
            if self.db.is_mac_banned(mac_address):
                self._silent_close(client, addr[0], mac_address,
                                    "BANNED_DEVICE", "Banned MAC")
                return
            if not self.rate_limiter.is_allowed(addr[0]):
                self._silent_close(client, addr[0], mac_address,
                                    "RATE_LIMITED", "Too many attempts")
                return
            msg_type = initial_msg.get('type', '')
            if msg_type == "PAIR_REQUEST":
                self._handle_pair_request(client, addr, mac_address, initial_msg)
            elif msg_type == "CODE_LOGIN":
                self._handle_code_login(client, addr, mac_address, initial_msg)
            else:
                self._silent_close(client, addr[0], mac_address,
                                    "INVALID_AUTH", f"Unknown type: {msg_type}")
        except Exception as e:
            logging.error(f"Client handler error: {e}")
        finally:
            if connection:
                self.connection_manager.unregister(connection.id)
            try:
                client.close()
            except Exception:
                pass
    
    def _handle_pair_request(self, client, addr, mac_address, data):
        username = data.get('username', '').strip()
        device_info = data.get('device_info', '')
        device_fingerprint = data.get('device_fingerprint', '')
        if not InputValidator.validate_username(username):
            self._silent_close(client, addr[0], mac_address, "INVALID_USERNAME", f"Invalid: {username}")
            return
        if self.db.is_user_banned(username):
            self._silent_close(client, addr[0], mac_address, "BANNED_USER", f"Banned: {username}")
            return
        code = self.db.create_pairing_request(username, addr[0], device_fingerprint, device_info)
        self.event_bus.publish('pairing_requested', {
            'username': username, 'device_info': device_info,
            'ip': addr[0], 'code': code
        })
        JsonProtocol.send_message(client, {"type": "PAIR_CODE", "code": code})
        code_expiry = self.config["security"]["code_expiry"]
        client.settimeout(code_expiry)
        try:
            confirm_msg = JsonProtocol.recv_message(client, timeout=code_expiry)
        except socket.timeout:
            self._silent_close(client, addr[0], mac_address, "PAIR_TIMEOUT", f"Timeout: {username}")
            return
        if not confirm_msg or confirm_msg.get('type') != 'PAIR_CONFIRM':
            self._silent_close(client, addr[0], mac_address, "INVALID_CONFIRM", "Expected PAIR_CONFIRM")
            return
        entered_code = confirm_msg.get('code', '').strip()
        request_info = self.db.verify_pairing_code(entered_code)
        if not request_info or request_info['device_fingerprint'] != device_fingerprint:
            self._silent_close(client, addr[0], mac_address, "WRONG_CODE", f"Wrong code: {username}")
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
            username, client, addr, mac_address, device_fingerprint,
            device_type=device_type, os_info=os_info
        )
        if not connection:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Max connections"})
            return
        JsonProtocol.send_message(client, {"type": "PAIRED_OK"})
        self.connection_manager.update_state(connection.id, ConnectionState.IDLE)
        print(f"✅ Device paired: {username} | {device_type} | {addr[0]}")
        self._enter_command_loop(client, addr, mac_address, username, 
                                  device_fingerprint, connection.id)
    
    def _handle_code_login(self, client, addr, mac_address, data):
        username = data.get('username', '').strip()
        code = data.get('code', '').strip()
        device_fingerprint = data.get('device_fingerprint', '')
        if not InputValidator.validate_username(username):
            self._silent_close(client, addr[0], mac_address, "INVALID_USERNAME", f"Invalid: {username}")
            return
        if self.db.is_user_banned(username):
            self._silent_close(client, addr[0], mac_address, "BANNED_USER", f"Banned: {username}")
            return
        request_info = self.db.verify_pairing_code(code)
        if not request_info:
            self._silent_close(client, addr[0], mac_address, "INVALID_CODE", f"Invalid code: {username}")
            return
        if request_info['device_fingerprint'] != device_fingerprint:
            self._silent_close(client, addr[0], mac_address, "DEVICE_MISMATCH", f"Mismatch: {username}")
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
            username, client, addr, mac_address, device_fingerprint,
            device_type=device_type, os_info=os_info
        )
        if not connection:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Max connections"})
            return
        JsonProtocol.send_message(client, {"type": "LOGIN_OK", "username": username})
        self.connection_manager.update_state(connection.id, ConnectionState.IDLE)
        self.event_bus.publish('user_connected', {
            'username': username, 'ip': addr[0], 'mac': mac_address, 'device': device_type
        })
        print(f"✅ {username} | 📍 {addr[0]} | 🔗 {mac_address} (code login)")
        try:
            pending_requests = self.db.get_pending_requests_for_user(username)
            if pending_requests:
                JsonProtocol.send_message(connection.socket, {
                    "type": "PENDING_REQUESTS",
                    "incoming": pending_requests, "outgoing": []
                })
        except Exception:
            pass
        self._enter_command_loop(client, addr, mac_address, username,
                                  device_fingerprint, connection.id)
    
    def _enter_command_loop(self, client, addr, mac_address, username,
                             device_fingerprint, connection_id):
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
                            'username': username, 'address': addr,
                            'mac': mac_address, 'fingerprint': device_fingerprint,
                            'connection_id': connection_id
                        }
                        command.execute(client, msg, context)
                        if command_name == "QUIT":
                            break
                    else:
                        JsonProtocol.send_message(client, {"type": "ERROR", "message": "Unknown command"})
                except Exception:
                    break
        finally:
            self.connection_manager.unregister(connection_id)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Julian Server - Secure File Transfer System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ju_server                    Start server with CLI admin
  ju_server --dashboard        Start server with TUI dashboard
  ju_server --port 5000        Start on specific port
        """
    )
    parser.add_argument('--dashboard', action='store_true',
                       help='Launch TUI dashboard instead of CLI admin')
    parser.add_argument('--port', type=int, default=0,
                       help='Specific port (0 = random)')
    parser.add_argument('--no-tls', action='store_true',
                       help='Disable TLS encryption')
    
    args = parser.parse_args()
    
    if args.port != 0:
        CONFIG["server"]["port"] = args.port
    if args.no_tls:
        CONFIG["security"]["tls_enabled"] = False
    
    server = SecureServer()
    server.start(dashboard_mode=args.dashboard)


if __name__ == "__main__":
    main()