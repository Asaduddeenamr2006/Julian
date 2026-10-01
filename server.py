"""
Julian Server - Secure File Transfer System v4.2.0
==================================================

A production-ready, security-hardened file transfer server.

Version History:
----------------
v3.0.0: Core architecture with Design Patterns
v4.0.0: Resume Transfers, File Management, Safety Numbers
v4.1.0: Transfer Requests, Admin Push, Code Generation
v4.2.0: Local folder sync support, TUI browser integration

Author: Julian Project
License: MIT
Version: 4.2.0
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
    """Observer Pattern for event-driven architecture."""
    
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
    """Singleton Pattern for thread-safe database access."""
    
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
            ''')
            self.conn.commit()
    
    def register_user(self, username, ip, mac="unknown", fingerprint="unknown"):
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
    
    def register_device(self, ip, mac, username, fingerprint, os_info, distribution, device_type):
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
    
    def update_stats(self, username, uploaded=0, downloaded=0, files_sent=0, files_received=0):
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
    
    def get_stats(self, username):
        with self.db_lock:
            self.cursor.execute('SELECT * FROM stats WHERE username = ?', (username,))
            row = self.cursor.fetchone()
            if row:
                return {'uploaded': row[1], 'downloaded': row[2],
                        'files_sent': row[3], 'files_received': row[4]}
            return None
    
    def log_transfer(self, sender, receiver, filename, size, status):
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO transfer_logs (sender, receiver, filename, size, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (sender, receiver, filename, size, status))
            self.conn.commit()
    
    def is_user_banned(self, username):
        with self.db_lock:
            self.cursor.execute('SELECT 1 FROM banned_users WHERE username = ?', (username,))
            return self.cursor.fetchone() is not None
    
    def ban_user(self, username, reason="No reason provided"):
        with self.db_lock:
            self.cursor.execute('''
                INSERT OR REPLACE INTO banned_users (username, reason, banned_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (username, reason))
            self.conn.commit()
    
    def unban_user(self, username):
        with self.db_lock:
            self.cursor.execute('DELETE FROM banned_users WHERE username = ?', (username,))
            self.conn.commit()
            return self.cursor.rowcount > 0
    
    def get_banned_users(self):
        with self.db_lock:
            self.cursor.execute('SELECT username, banned_at, reason FROM banned_users ORDER BY banned_at DESC')
            return self.cursor.fetchall()
    
    def is_mac_banned(self, mac_address):
        if mac_address == "unknown":
            return False
        with self.db_lock:
            self.cursor.execute('SELECT 1 FROM banned_macs WHERE mac_address = ?', (mac_address,))
            return self.cursor.fetchone() is not None
    
    def ban_mac(self, mac_address, reason="No reason provided"):
        with self.db_lock:
            self.cursor.execute('''
                INSERT OR REPLACE INTO banned_macs (mac_address, reason, banned_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (mac_address, reason))
            self.conn.commit()
    
    def unban_mac(self, mac_address):
        with self.db_lock:
            self.cursor.execute('DELETE FROM banned_macs WHERE mac_address = ?', (mac_address,))
            self.conn.commit()
            return self.cursor.rowcount > 0
    
    def get_banned_macs(self):
        with self.db_lock:
            self.cursor.execute('SELECT mac_address, banned_at, reason FROM banned_macs ORDER BY banned_at DESC')
            return self.cursor.fetchall()
    
    def create_pairing_request(self, username, ip, device_fingerprint, device_info):
        code_length = CONFIG["security"]["code_length"]
        code = ''.join([str(random.randint(0, 9)) for _ in range(code_length)])
        code_expiry = CONFIG["security"]["code_expiry"]
        expires_at = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + code_expiry))
        with self.db_lock:
            self.cursor.execute('DELETE FROM pairing_requests WHERE device_fingerprint = ? AND used = 0', (device_fingerprint,))
            self.cursor.execute('''
                INSERT INTO pairing_requests 
                (username, code, ip_address, device_fingerprint, device_info, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, code, ip, device_fingerprint, device_info, expires_at))
            self.conn.commit()
        return code
    
    def verify_pairing_code(self, code):
        with self.db_lock:
            self.cursor.execute('''
                SELECT username, ip_address, device_fingerprint, device_info, expires_at
                FROM pairing_requests WHERE code = ? AND used = 0
            ''', (code,))
            row = self.cursor.fetchone()
            if not row:
                return None
            expires_at = time.strptime(row[4], '%Y-%m-%d %H:%M:%S')
            if time.localtime() > expires_at:
                return None
            self.cursor.execute('UPDATE pairing_requests SET used = 1 WHERE code = ?', (code,))
            self.conn.commit()
            return {'username': row[0], 'ip': row[1],
                    'device_fingerprint': row[2], 'device_info': row[3]}
    
    def get_pending_pairing_requests(self):
        with self.db_lock:
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute('''
                SELECT username, code, ip_address, device_fingerprint, device_info, expires_at
                FROM pairing_requests WHERE used = 0 AND expires_at > ?
                ORDER BY created_at DESC
            ''', (now,))
            return self.cursor.fetchall()
    
    def create_transaction(self, transaction_id, connection_id, username, tx_type, filename, size):
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO transactions (id, connection_id, username, type, filename, size, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (transaction_id, connection_id, username, tx_type, filename, size, TransactionStatus.PENDING.value))
            self.conn.commit()
    
    def update_transaction_progress(self, transaction_id, bytes_transferred):
        with self.db_lock:
            self.cursor.execute('''
                UPDATE transactions SET bytes_transferred = ?, status = ? WHERE id = ?
            ''', (bytes_transferred, TransactionStatus.IN_PROGRESS.value, transaction_id))
            self.conn.commit()
    
    def complete_transaction(self, transaction_id, status):
        with self.db_lock:
            self.cursor.execute('''
                UPDATE transactions SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?
            ''', (status, transaction_id))
            self.conn.commit()
    
    def log_security_event(self, ip, mac, attempt_type, details):
        with self.db_lock:
            self.cursor.execute('''
                INSERT INTO security_logs (ip_address, mac_address, attempt_type, details)
                VALUES (?, ?, ?, ?)
            ''', (ip, mac, attempt_type, details))
            self.conn.commit()
    
    def get_security_logs(self, limit=50):
        with self.db_lock:
            self.cursor.execute('''
                SELECT ip_address, mac_address, attempt_type, details, timestamp
                FROM security_logs ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return self.cursor.fetchall()
    
    def get_all_users(self):
        with self.db_lock:
            self.cursor.execute('''
                SELECT username, ip_address, mac_address, device_fingerprint, first_seen, last_seen 
                FROM users ORDER BY last_seen DESC
            ''')
            return self.cursor.fetchall()
    
    def get_all_devices(self):
        with self.db_lock:
            self.cursor.execute('''
                SELECT ip_address, mac_address, username, device_fingerprint, os_info, 
                       distribution, device_type, last_seen 
                FROM device_sessions ORDER BY last_seen DESC
            ''')
            return self.cursor.fetchall()
    
    def get_user_info(self, username):
        with self.db_lock:
            self.cursor.execute('''
                SELECT username, ip_address, mac_address, device_fingerprint, first_seen, last_seen 
                FROM users WHERE username = ?
            ''', (username,))
            row = self.cursor.fetchone()
            if row:
                return {'username': row[0], 'ip': row[1], 'mac': row[2],
                        'fingerprint': row[3], 'first_seen': row[4], 'last_seen': row[5]}
            return None
    
    def create_transfer_request(self, from_user, to_user, filename, file_size, file_sha256):
        request_id = str(uuid.uuid4())
        request_expiry = CONFIG["transfers"]["request_expiry"]
        expires_at = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() + request_expiry))
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
    
    def get_transfer_request(self, request_id):
        with self.db_lock:
            self.cursor.execute('''
                SELECT id, from_user, to_user, filename, file_size, file_sha256, 
                       status, created_at, expires_at, accepted_at, completed_at, rejection_reason
                FROM transfer_requests WHERE id = ?
            ''', (request_id,))
            row = self.cursor.fetchone()
            if row:
                return {'id': row[0], 'from_user': row[1], 'to_user': row[2],
                        'filename': row[3], 'file_size': row[4], 'file_sha256': row[5],
                        'status': row[6], 'created_at': row[7], 'expires_at': row[8],
                        'accepted_at': row[9], 'completed_at': row[10], 'rejection_reason': row[11]}
            return None
    
    def get_pending_requests_for_user(self, username):
        with self.db_lock:
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute('''
                SELECT id, from_user, filename, file_size, created_at, expires_at
                FROM transfer_requests 
                WHERE to_user = ? AND status = 'pending' AND expires_at > ?
                ORDER BY created_at DESC
            ''', (username, now))
            requests = []
            for row in self.cursor.fetchall():
                requests.append({'id': row[0], 'from_user': row[1], 'filename': row[2],
                                 'file_size': row[3], 'created_at': row[4], 'expires_at': row[5]})
            return requests
    
    def get_pending_requests_from_user(self, username):
        with self.db_lock:
            now = time.strftime('%Y-%m-%d %H:%M:%S')
            self.cursor.execute('''
                SELECT id, to_user, filename, file_size, created_at, expires_at, status
                FROM transfer_requests 
                WHERE from_user = ? AND status IN ('pending', 'accepted') AND expires_at > ?
                ORDER BY created_at DESC
            ''', (username, now))
            requests = []
            for row in self.cursor.fetchall():
                requests.append({'id': row[0], 'to_user': row[1], 'filename': row[2],
                                 'file_size': row[3], 'created_at': row[4], 'expires_at': row[5],
                                 'status': row[6]})
            return requests
    
    def accept_transfer_request(self, request_id):
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
    
    def reject_transfer_request(self, request_id, reason=""):
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
    
    def cancel_transfer_request(self, request_id, username):
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
    
    def cleanup_expired_requests(self):
        with self.db_lock:
            try:
                now = time.strftime('%Y-%m-%d %H:%M:%S')
                self.cursor.execute('''
                    UPDATE transfer_requests SET status = ?
                    WHERE status = 'pending' AND expires_at < ?
                ''', (TransferRequestStatus.EXPIRED.value, now))
                self.conn.commit()
                return self.cursor.rowcount
            except Exception as e:
                logging.error(f"Failed to cleanup expired requests: {e}")
                return 0


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


class ConnectionManager:
    def __init__(self, max_connections=None):
        self.max_connections = max_connections or CONFIG["server"]["max_clients"]
        self._connections: Dict[str, Connection] = {}
        self._lock = threading.Lock()
        self._start_time = time.time()
    
    def register(self, username, client_socket, address, mac_address="unknown", device_fingerprint=""):
        with self._lock:
            if len(self._connections) >= self.max_connections:
                return None
            for conn in self._connections.values():
                if conn.username == username:
                    return None
            connection_id = str(uuid.uuid4())
            connection = Connection(id=connection_id, username=username, socket=client_socket,
                                    address=address, mac_address=mac_address,
                                    device_fingerprint=device_fingerprint)
            self._connections[connection_id] = connection
            return connection
    
    def unregister(self, connection_id):
        with self._lock:
            if connection_id in self._connections:
                del self._connections[connection_id]
    
    def get_by_username(self, username):
        with self._lock:
            for conn in self._connections.values():
                if conn.username == username:
                    return conn
            return None
    
    def update_state(self, connection_id, state):
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].state = state
                self._connections[connection_id].last_activity = time.time()
    
    def set_current_transaction(self, connection_id, transaction_id):
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].current_transaction = transaction_id
                self._connections[connection_id].state = ConnectionState.TRANSFERRING
    
    def clear_current_transaction(self, connection_id):
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].current_transaction = None
                self._connections[connection_id].state = ConnectionState.IDLE
    
    def update_activity(self, connection_id):
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].last_activity = time.time()
    
    def update_bytes(self, connection_id, sent=0, received=0):
        with self._lock:
            if connection_id in self._connections:
                self._connections[connection_id].bytes_sent += sent
                self._connections[connection_id].bytes_received += received
    
    def get_all_connections(self):
        with self._lock:
            return list(self._connections.values())
    
    def get_zombie_connections(self, timeout=None):
        timeout = timeout or CONFIG["connections"]["heartbeat_timeout"]
        now = time.time()
        with self._lock:
            return [conn for conn in self._connections.values()
                    if now - conn.last_activity > timeout]
    
    def get_stats(self):
        with self._lock:
            total = len(self._connections)
            active = sum(1 for c in self._connections.values() if c.state != ConnectionState.CLOSING)
            idle = sum(1 for c in self._connections.values() if c.state == ConnectionState.IDLE)
            transferring = sum(1 for c in self._connections.values() if c.state == ConnectionState.TRANSFERRING)
            total_sent = sum(c.bytes_sent for c in self._connections.values())
            total_received = sum(c.bytes_received for c in self._connections.values())
            return {'total_connections': total, 'max_connections': self.max_connections,
                    'active': active, 'idle': idle, 'transferring': transferring,
                    'total_bytes_sent': total_sent, 'total_bytes_received': total_received,
                    'uptime': time.time() - self._start_time}
    
    def cleanup(self):
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
    def __init__(self, db):
        self.db = db
        self._transactions: Dict[str, Transaction] = {}
        self._lock = threading.Lock()
    
    def create_transaction(self, connection_id, username, tx_type, filename, size):
        transaction_id = str(uuid.uuid4())
        transaction = Transaction(id=transaction_id, connection_id=connection_id,
                                  username=username, type=tx_type, filename=filename, size=size)
        with self._lock:
            self._transactions[transaction_id] = transaction
        self.db.create_transaction(transaction_id, connection_id, username, tx_type, filename, size)
        return transaction
    
    def update_progress(self, transaction_id, bytes_transferred):
        with self._lock:
            if transaction_id in self._transactions:
                self._transactions[transaction_id].bytes_transferred = bytes_transferred
        self.db.update_transaction_progress(transaction_id, bytes_transferred)
    
    def complete_transaction(self, transaction_id, success=True):
        status = TransactionStatus.COMPLETED if success else TransactionStatus.FAILED
        with self._lock:
            if transaction_id in self._transactions:
                self._transactions[transaction_id].status = status
        self.db.complete_transaction(transaction_id, status.value)
    
    def get_stats(self):
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
    def __init__(self, connection_manager, db):
        self.connection_manager = connection_manager
        self.db = db
        self.running = False
        self.thread = None
    
    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def _monitor_loop(self):
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
                    expired = self.db.cleanup_expired_requests()
                    if expired > 0:
                        logging.info(f"Cleaned up {expired} expired transfer requests")
                    last_cleanup = now
                time.sleep(interval)
            except Exception as e:
                logging.error(f"Heartbeat monitor error: {e}")
                time.sleep(interval)


# ============================================================================
# RATE LIMITER
# ============================================================================

class RateLimiter:
    def __init__(self, max_attempts=None, window_seconds=None):
        self.max_attempts = max_attempts or CONFIG["security"]["max_auth_attempts"]
        self.window = window_seconds or CONFIG["security"]["rate_limit_window"]
        self.attempts = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, ip):
        now = time.time()
        with self.lock:
            self.attempts[ip] = [t for t in self.attempts[ip] if now - t < self.window]
            if len(self.attempts[ip]) >= self.max_attempts:
                return False
            self.attempts[ip].append(now)
            return True
    
    def get_remaining_attempts(self, ip):
        now = time.time()
        with self.lock:
            self.attempts[ip] = [t for t in self.attempts[ip] if now - t < self.window]
            return max(0, self.max_attempts - len(self.attempts[ip]))


# ============================================================================
# INPUT VALIDATOR
# ============================================================================

class InputValidator:
    @staticmethod
    def validate_ip(ip_string):
        try:
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_filename(filename):
        filename = os.path.basename(filename)
        if any(c in filename for c in ['/', '\\', '..', '\x00']):
            return None
        if len(filename) > 255 or len(filename) == 0:
            return None
        return filename
    
    @staticmethod
    def validate_username(username):
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
    def send_message(sock, data):
        message = json.dumps(data)
        encoded = message.encode('utf-8')
        length = len(encoded).to_bytes(4, 'big')
        sock.send(length + encoded)
    
    @staticmethod
    def recv_message(sock, timeout=None):
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
# FILE TRANSFER UTILITIES
# ============================================================================

class FileTransferUtils:
    @staticmethod
    def calculate_sha256(file_path):
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    @staticmethod
    def format_size(size):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} TB"
    
    @staticmethod
    def generate_password(length=None):
        length = length or CONFIG["security"]["password_length"]
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))


# ============================================================================
# COMMANDS (Command Pattern)
# ============================================================================

class Command(ABC):
    @abstractmethod
    def execute(self, client, data, context):
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
        transaction = self.transaction_manager.create_transaction(connection_id, username, 'upload', file_name, file_size)
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
                self.event_bus.publish('file_uploaded', {'username': username, 'filename': file_name, 'size': file_size})
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
        transaction = self.transaction_manager.create_transaction(connection_id, username, 'download', file_name, file_size)
        self.connection_manager.set_current_transaction(connection_id, transaction.id)
        try:
            JsonProtocol.send_message(client, {"type": "FILE_META", "filename": file_name,
                                                "size": file_size, "sha256": file_sha256})
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
            self.transaction_manager.complete_transaction(transaction.id, success=True)
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
        user_list = [{"username": c.username, "ip": c.address[0], "mac": c.mac_address,
                      "state": c.state.value, "uptime": int(time.time() - c.created_at)}
                     for c in connections]
        JsonProtocol.send_message(client, {"type": "USER_LIST", "users": user_list})


class StatsCommand(Command):
    def __init__(self, db):
        self.db = db
    
    def execute(self, client, data, context):
        stats = self.db.get_stats(context['username'])
        if not stats:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "No stats found"})
            return
        JsonProtocol.send_message(client, {"type": "STATS", "username": context['username'],
                                            "uploaded": stats['uploaded'], "downloaded": stats['downloaded'],
                                            "files_sent": stats['files_sent'], "files_received": stats['files_received']})


class QuitCommand(Command):
    def __init__(self, event_bus, connection_manager):
        self.event_bus = event_bus
        self.connection_manager = connection_manager
    
    def execute(self, client, data, context):
        self.connection_manager.update_state(context['connection_id'], ConnectionState.CLOSING)
        self.event_bus.publish('user_disconnected', {'username': context['username'], 'ip': context['address'][0]})


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
        if not os.path.isfile(file_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "File not found"})
            return
        try:
            file_size = os.path.getsize(file_path)
            os.remove(file_path)
            JsonProtocol.send_message(client, {"type": "DELETE_OK", "filename": file_name})
            self.db.update_stats(context['username'], uploaded=-file_size, files_received=-1)
            self.event_bus.publish('file_deleted', {'username': context['username'], 'filename': file_name})
        except Exception as e:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": f"Delete failed: {str(e)}"})


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
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Source not found"})
            return
        if os.path.exists(new_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Target exists"})
            return
        try:
            os.rename(old_path, new_path)
            JsonProtocol.send_message(client, {"type": "RENAME_OK", "old_name": old_name, "new_name": new_name})
        except Exception as e:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": f"Rename failed: {str(e)}"})


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
        JsonProtocol.send_message(client, {"type": "SEARCH_RESULTS", "pattern": pattern,
                                            "count": len(matches), "files": matches})


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
        save_path = os.path.join(self.shared_folder, file_name)
        if not os.path.isfile(save_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "No partial file"})
            return
        existing_size = os.path.getsize(save_path)
        if existing_size != offset:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Offset mismatch"})
            return
        transaction = self.transaction_manager.create_transaction(context['connection_id'], context['username'], 'resume_upload', file_name, file_size - offset)
        JsonProtocol.send_message(client, {"type": "RESUME_OK", "offset": offset})
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
                    self.transaction_manager.update_progress(transaction.id, received_size - offset)
            if FileTransferUtils.calculate_sha256(save_path) == file_sha256:
                JsonProtocol.send_message(client, {"type": "FILE_OK"})
                self.db.update_stats(context['username'], uploaded=file_size - offset, files_received=1)
                self.transaction_manager.complete_transaction(transaction.id, success=True)
            else:
                JsonProtocol.send_message(client, {"type": "FILE_CORRUPTED"})
                self.transaction_manager.complete_transaction(transaction.id, success=False)
        except Exception as e:
            logging.error(f"Resume upload error: {e}")
            self.transaction_manager.complete_transaction(transaction.id, success=False)


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
        if not os.path.isfile(file_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "File not found"})
            return
        file_size = os.path.getsize(file_path)
        if offset < 0 or offset >= file_size:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": f"Invalid offset"})
            return
        file_sha256 = FileTransferUtils.calculate_sha256(file_path)
        remaining_size = file_size - offset
        transaction = self.transaction_manager.create_transaction(context['connection_id'], context['username'], 'resume_download', file_name, remaining_size)
        JsonProtocol.send_message(client, {"type": "RESUME_META", "filename": file_name,
                                            "size": file_size, "offset": offset,
                                            "remaining": remaining_size, "sha256": file_sha256})
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
            self.db.update_stats(context['username'], downloaded=remaining_size, files_sent=1)
            self.transaction_manager.complete_transaction(transaction.id, success=True)
        except Exception as e:
            logging.error(f"Resume download error: {e}")
            self.transaction_manager.complete_transaction(transaction.id, success=False)


class ServerFingerprintCommand(Command):
    def __init__(self, cert_file):
        self.cert_file = cert_file
    
    def execute(self, client, data, context):
        try:
            if not os.path.exists(self.cert_file):
                JsonProtocol.send_message(client, {"type": "ERROR", "message": "Cert not available"})
                return
            with open(self.cert_file, 'rb') as f:
                cert_data = f.read()
            fingerprint = hashlib.sha256(cert_data).hexdigest()
            safety_numbers = []
            for i in range(0, 25, 5):
                chunk = fingerprint[i:i+5]
                num = int(chunk, 16) % 100000
                safety_numbers.append(f"{num:05d}")
            JsonProtocol.send_message(client, {"type": "SERVER_FINGERPRINT",
                                                "safety_numbers": "-".join(safety_numbers),
                                                "fingerprint": fingerprint[:32]})
        except Exception as e:
            logging.error(f"Fingerprint error: {e}")


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
            JsonProtocol.send_message(client, {"type": "ERROR", "message": f"User not found"})
            return
        if from_user == to_user:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Cannot send to yourself"})
            return
        file_path = os.path.join(self.shared_folder, filename)
        if not os.path.isfile(file_path):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": f"File not found"})
            return
        file_size = os.path.getsize(file_path)
        file_sha256 = FileTransferUtils.calculate_sha256(file_path)
        request_id = self.db.create_transfer_request(from_user, to_user, filename, file_size, file_sha256)
        if not request_id:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Failed to create request"})
            return
        JsonProtocol.send_message(client, {"type": "REQUEST_CREATED", "request_id": request_id,
                                            "to_user": to_user, "filename": filename, "file_size": file_size})
        recipient_conn = self.connection_manager.get_by_username(to_user)
        if recipient_conn:
            try:
                JsonProtocol.send_message(recipient_conn.socket, {"type": "INCOMING_TRANSFER_REQUEST",
                                                                    "request_id": request_id, "from_user": from_user,
                                                                    "filename": filename, "file_size": file_size})
            except Exception as e:
                logging.error(f"Failed to notify recipient: {e}")


class ListPendingRequestsCommand(Command):
    def __init__(self, db):
        self.db = db
    
    def execute(self, client, data, context):
        incoming = self.db.get_pending_requests_for_user(context['username'])
        outgoing = self.db.get_pending_requests_from_user(context['username'])
        JsonProtocol.send_message(client, {"type": "PENDING_REQUESTS", "incoming": incoming, "outgoing": outgoing})


class AcceptTransferCommand(Command):
    def __init__(self, db, shared_folder, connection_manager, event_bus):
        self.db = db
        self.shared_folder = shared_folder
        self.connection_manager = connection_manager
        self.event_bus = event_bus
    
    def execute(self, client, data, context):
        request_id = data.get('request_id', '').strip()
        username = context['username']
        if not request_id:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Missing request_id"})
            return
        request = self.db.get_transfer_request(request_id)
        if not request or request['to_user'] != username or request['status'] != 'pending':
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid request"})
            return
        if not self.db.accept_transfer_request(request_id):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Failed to accept"})
            return
        JsonProtocol.send_message(client, {"type": "REQUEST_ACCEPTED", "request_id": request_id,
                                            "filename": request['filename'], "file_size": request['file_size']})
        sender_conn = self.connection_manager.get_by_username(request['from_user'])
        if sender_conn:
            try:
                JsonProtocol.send_message(sender_conn.socket, {"type": "TRANSFER_REQUEST_ACCEPTED",
                                                                "request_id": request_id, "to_user": username})
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
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid request"})
            return
        if not self.db.reject_transfer_request(request_id, reason):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Failed to reject"})
            return
        JsonProtocol.send_message(client, {"type": "REQUEST_REJECTED", "request_id": request_id})
        sender_conn = self.connection_manager.get_by_username(request['from_user'])
        if sender_conn:
            try:
                JsonProtocol.send_message(sender_conn.socket, {"type": "TRANSFER_REQUEST_REJECTED",
                                                                "request_id": request_id, "to_user": username,
                                                                "reason": reason})
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
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Invalid request"})
            return
        if not self.db.cancel_transfer_request(request_id, username):
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Failed to cancel"})
            return
        JsonProtocol.send_message(client, {"type": "REQUEST_CANCELLED", "request_id": request_id})
        recipient_conn = self.connection_manager.get_by_username(request['to_user'])
        if recipient_conn:
            try:
                JsonProtocol.send_message(recipient_conn.socket, {"type": "TRANSFER_REQUEST_CANCELLED",
                                                                    "request_id": request_id, "from_user": username})
            except Exception:
                pass


# ============================================================================
# COMMAND FACTORY (Factory Pattern)
# ============================================================================

class CommandFactory:
    def __init__(self, event_bus, db, connection_manager, transaction_manager, shared_folder, cert_file):
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
    
    def get_command(self, command_name):
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
                os.system(f'openssl req -x509 -newkey rsa:4096 -keyout {key_file} '
                          f'-out {cert_file} -days {cert_days} -nodes -subj "/CN=Julian Server" 2>/dev/null')
                print("✅ SSL certificate generated successfully")
                return True
            except Exception as e:
                print(f"❌ Failed to generate SSL certificate: {e}")
                return False
        return True


class NetworkUtils:
    @staticmethod
    def get_mac_from_ip(ip_address):
        if not InputValidator.validate_ip(ip_address):
            return "unknown"
        try:
            subprocess.run(['ping', '-c', '1', '-W', '1', ip_address], capture_output=True, timeout=2)
            result = subprocess.run(['arp', '-n', ip_address], capture_output=True, text=True, timeout=2)
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
        discovery_data = {"service": "julian", "version": "4.2.0", "port": self.server_port,
                          "requires_auth": True, "tls": self.tls_enabled}
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
# MAIN SERVER
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
                self.context.load_cert_chain(self.config["security"]["cert_file"],
                                              self.config["security"]["key_file"])
        self.command_factory = CommandFactory(self.event_bus, self.db, self.connection_manager,
                                                self.transaction_manager, self.shared_folder,
                                                self.config["security"]["cert_file"])
        logging.basicConfig(filename=self.config["logging"]["file"], filemode='a',
                            format=self.config["logging"]["format"], datefmt='%Y-%m-%d %H:%M:%S',
                            level=getattr(logging, self.config["logging"]["level"]))
        self._setup_event_handlers()
        self.discovery = None
        if self.config["discovery"]["enabled"]:
            self.discovery = ServiceDiscovery(self.port, self.ssl_enabled)
    
    def _setup_event_handlers(self):
        self.event_bus.subscribe('user_connected', lambda d: logging.info(f"User connected: {d.get('username')}"))
        self.event_bus.subscribe('file_uploaded', lambda d: logging.info(f"File uploaded: {d.get('filename')}"))
        self.event_bus.subscribe('file_downloaded', lambda d: logging.info(f"File downloaded: {d.get('filename')}"))
        self.event_bus.subscribe('pairing_requested', self._on_pairing_requested)
        self.event_bus.subscribe('security_event', self._on_security_event)
    
    def _on_pairing_requested(self, data):
        print("\n" + "=" * 60)
        print(f"🔑 NEW PAIRING REQUEST")
        print(f"   Username: {data['username']}")
        print(f"   Device: {data['device_info']}")
        print(f"   IP: {data['ip']}")
        print(f"   Code: \033[1;33m{data['code']}\033[0m")
        print(f"   ⏰  Expires in {self.config['security']['code_expiry']} seconds")
        print("=" * 60 + "\n")
    
    def _on_security_event(self, data):
        print(f"\n🛡️ SECURITY: {data['type']} from {data['ip']} - {data['details']}")
    
    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.ssl_enabled and self.context:
            self.server_socket = self.context.wrap_socket(self.server_socket, server_side=True)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.config["server"]["max_clients"])
        ip = NetworkUtils.get_local_ip()
        print("=" * 60)
        print("🔒 Julian Server v4.2.0")
        print("=" * 60)
        print(f"📍 IP: {ip} | 📌 Port: {self.port} | 🔑 Pass: {self.password}")
        print(f"🔐 Encryption: {'TLS 1.3 Enabled' if self.ssl_enabled else 'DISABLED'}")
        print(f"📡 Discovery: {'Enabled' if self.discovery else 'Disabled'}")
        print(f"📁 Shared: {os.path.abspath(self.shared_folder)}")
        print("=" * 60)
        print("Type 'help' for admin commands.\n")
        if self.discovery:
            self.discovery.start()
        self.heartbeat_monitor.start()
        admin_thread = threading.Thread(target=self._admin_cli, daemon=True)
        admin_thread.start()
        try:
            while True:
                client, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()
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
        try:
            auth_timeout = self.config["security"]["auth_timeout"]
            client.settimeout(auth_timeout)
            try:
                initial_msg = JsonProtocol.recv_message(client, timeout=auth_timeout)
            except socket.timeout:
                self._silent_close(client, addr[0], "unknown", "TIMEOUT", "No auth")
                return
            if not initial_msg:
                self._silent_close(client, addr[0], "unknown", "EMPTY", "Empty data")
                return
            client.settimeout(None)
            mac_address = NetworkUtils.get_mac_from_ip(addr[0])
            if self.db.is_mac_banned(mac_address):
                self._silent_close(client, addr[0], mac_address, "BANNED_DEVICE", "Banned MAC")
                return
            if not self.rate_limiter.is_allowed(addr[0]):
                self._silent_close(client, addr[0], mac_address, "RATE_LIMITED", "Too many attempts")
                return
            msg_type = initial_msg.get('type', '')
            if msg_type == "PAIR_REQUEST":
                self._handle_pair_request(client, addr, mac_address, initial_msg)
            elif msg_type == "CODE_LOGIN":
                self._handle_code_login(client, addr, mac_address, initial_msg)
            else:
                self._silent_close(client, addr[0], mac_address, "INVALID_AUTH", f"Unknown: {msg_type}")
        except Exception as e:
            logging.error(f"Client handler error: {e}")
        finally:
            try:
                client.close()
            except Exception:
                pass
    
    def _handle_pair_request(self, client, addr, mac_address, data):
        username = data.get('username', '').strip()
        device_info = data.get('device_info', '')
        device_fingerprint = data.get('device_fingerprint', '')
        if not InputValidator.validate_username(username):
            self._silent_close(client, addr[0], mac_address, "INVALID_USERNAME", f"Invalid")
            return
        if self.db.is_user_banned(username):
            self._silent_close(client, addr[0], mac_address, "BANNED_USER", f"Banned")
            return
        code = self.db.create_pairing_request(username, addr[0], device_fingerprint, device_info)
        self.event_bus.publish('pairing_requested', {'username': username, 'device_info': device_info,
                                                       'ip': addr[0], 'code': code})
        JsonProtocol.send_message(client, {"type": "PAIR_CODE", "code": code})
        code_expiry = self.config["security"]["code_expiry"]
        client.settimeout(code_expiry)
        try:
            confirm_msg = JsonProtocol.recv_message(client, timeout=code_expiry)
        except socket.timeout:
            self._silent_close(client, addr[0], mac_address, "PAIR_TIMEOUT", "Not confirmed")
            return
        if not confirm_msg or confirm_msg.get('type') != 'PAIR_CONFIRM':
            self._silent_close(client, addr[0], mac_address, "INVALID_CONFIRM", "Expected PAIR_CONFIRM")
            return
        entered_code = confirm_msg.get('code', '').strip()
        request_info = self.db.verify_pairing_code(entered_code)
        if not request_info or request_info['device_fingerprint'] != device_fingerprint:
            self._silent_close(client, addr[0], mac_address, "WRONG_CODE", "Wrong code")
            return
        self.db.register_user(username, addr[0], mac_address, device_fingerprint)
        os_info, distribution, device_type = "Unknown", "", "Unknown"
        if "||" in device_info:
            parts = device_info.split("||")
            if len(parts) >= 3:
                os_info, distribution, device_type = parts[0], parts[1], parts[2]
        self.db.register_device(addr[0], mac_address, username, device_fingerprint, os_info, distribution, device_type)
        connection = self.connection_manager.register(username, client, addr, mac_address, device_fingerprint)
        if not connection:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Max connections reached"})
            return
        JsonProtocol.send_message(client, {"type": "PAIRED_OK"})
        self.connection_manager.update_state(connection.id, ConnectionState.IDLE)
        print(f"✅ Device paired: {username} | {device_type} | {addr[0]}")
        self._enter_command_loop(client, addr, mac_address, username, device_fingerprint, connection.id)
    
    def _handle_code_login(self, client, addr, mac_address, data):
        username = data.get('username', '').strip()
        code = data.get('code', '').strip()
        device_fingerprint = data.get('device_fingerprint', '')
        if not InputValidator.validate_username(username):
            self._silent_close(client, addr[0], mac_address, "INVALID_USERNAME", "Invalid")
            return
        if self.db.is_user_banned(username):
            self._silent_close(client, addr[0], mac_address, "BANNED_USER", "Banned")
            return
        request_info = self.db.verify_pairing_code(code)
        if not request_info or request_info['device_fingerprint'] != device_fingerprint:
            self._silent_close(client, addr[0], mac_address, "INVALID_CODE", "Invalid code")
            return
        device_info = request_info.get('device_info', '')
        os_info, distribution, device_type = "Unknown", "", "Unknown"
        if "||" in device_info:
            parts = device_info.split("||")
            if len(parts) >= 3:
                os_info, distribution, device_type = parts[0], parts[1], parts[2]
        self.db.register_user(username, addr[0], mac_address, device_fingerprint)
        self.db.register_device(addr[0], mac_address, username, device_fingerprint, os_info, distribution, device_type)
        connection = self.connection_manager.register(username, client, addr, mac_address, device_fingerprint)
        if not connection:
            JsonProtocol.send_message(client, {"type": "ERROR", "message": "Max connections reached"})
            return
        JsonProtocol.send_message(client, {"type": "LOGIN_OK", "username": username})
        self.connection_manager.update_state(connection.id, ConnectionState.IDLE)
        self.event_bus.publish('user_connected', {'username': username, 'ip': addr[0], 'mac': mac_address, 'device': device_type})
        print(f"✅ {username} | 📍 {addr[0]} | 🔗 {mac_address} (code login)")
        self._enter_command_loop(client, addr, mac_address, username, device_fingerprint, connection.id)
    
    def _enter_command_loop(self, client, addr, mac_address, username, device_fingerprint, connection_id):
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
                        context = {'username': username, 'address': addr, 'mac': mac_address,
                                   'fingerprint': device_fingerprint, 'connection_id': connection_id}
                        command.execute(client, msg, context)
                        if command_name == "QUIT":
                            break
                    else:
                        JsonProtocol.send_message(client, {"type": "ERROR", "message": "Unknown command"})
                except Exception:
                    break
        finally:
            self.connection_manager.unregister(connection_id)
    
    def _admin_cli(self):
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
  code <username>    - Generate login code
  ban <user> [reason]    - Ban a user
  unban <user>           - Unban a user
  ban_mac <mac> [reason] - Ban a device
  unban_mac <mac>        - Unban a MAC
  stats <user>           - Show user statistics
  quit                   - Exit server
                    """)
                elif cmd.lower() == 'users':
                    connections = self.connection_manager.get_all_connections()
                    print(f"\n👥 Active Users ({len(connections)}):")
                    for c in connections:
                        print(f"  👤 {c.username} | {c.address[0]} | State: {c.state.value}")
                elif cmd.lower() == 'connections':
                    stats = self.connection_manager.get_stats()
                    print(f"\n🔌 Total: {stats['total_connections']}/{stats['max_connections']}")
                    print(f"  Active: {stats['active']} | Idle: {stats['idle']} | Transferring: {stats['transferring']}")
                elif cmd.lower() == 'transactions':
                    stats = self.transaction_manager.get_stats()
                    print(f"\n📊 Total={stats['total']} | Active={stats['active']} | Completed={stats['completed']}")
                elif cmd.lower() == 'devices':
                    devices = self.db.get_all_devices()
                    print(f"\n🖥️ All Registered Devices ({len(devices)}):")
                    for d in devices:
                        print(f"  📍 {d[0]} | 👤 {d[2]} | 💻 {d[4]} | 📱 {d[6]}")
                elif cmd.lower() == 'pending':
                    pending = self.db.get_pending_pairing_requests()
                    if not pending:
                        print("\n📭 No pending pairing requests")
                    else:
                        print(f"\n⏳ Pending ({len(pending)}):")
                        for p in pending:
                            print(f"  👤 {p[0]} | 🔑 {p[1]} | 📍 {p[2]}")
                elif cmd.lower() == 'security':
                    logs = self.db.get_security_logs(20)
                    if not logs:
                        print("\n🛡️ No security events")
                    else:
                        print(f"\n🛡️ Recent Security Events ({len(logs)}):")
                        for l in logs:
                            print(f"  📍 {l[0]} | ⚠️ {l[2]} | {l[3]}")
                elif cmd.lower() == 'all_users':
                    users = self.db.get_all_users()
                    print(f"\n📜 All Users ({len(users)}):")
                    for u in users:
                        print(f"  👤 {u[0]} | Last IP: {u[1]} | Last Seen: {u[5]}")
                elif cmd.lower() == 'banned':
                    banned = self.db.get_banned_users()
                    print(f"\n🚫 Banned Users ({len(banned)}):")
                    for b in banned:
                        print(f"  ❌ {b[0]} | Reason: {b[2]}")
                elif cmd.lower() == 'banned_macs':
                    banned = self.db.get_banned_macs()
                    print(f"\n🚫 Banned MACs ({len(banned)}):")
                    for b in banned:
                        print(f"  ❌ {b[0]} | Reason: {b[2]}")
                elif cmd.lower().startswith('code '):
                    username = cmd.split(' ', 1)[1].strip()
                    if not InputValidator.validate_username(username):
                        print(f"❌ Invalid username")
                        continue
                    user_info = self.db.get_user_info(username)
                    if not user_info:
                        print(f"❌ User '{username}' not found")
                    else:
                        code = self.db.create_pairing_request(username, user_info['ip'], user_info['fingerprint'], "Admin code")
                        print(f"\n🔑 Code for '{username}': \033[1;33m{code}\033[0m")
                        print(f"⏰  Expires in {self.config['security']['code_expiry']} seconds\n")
                elif cmd.lower().startswith('ban '):
                    parts = cmd.split(' ', 2)
                    if len(parts) >= 2:
                        self.db.ban_user(parts[1], parts[2] if len(parts) > 2 else "No reason")
                        print(f"✅ User '{parts[1]}' banned.")
                elif cmd.lower().startswith('unban '):
                    if self.db.unban_user(cmd.split(' ', 1)[1]):
                        print(f"✅ User unbanned.")
                    else:
                        print(f"⚠️ User was not banned.")
                elif cmd.lower().startswith('ban_mac '):
                    parts = cmd.split(' ', 2)
                    if len(parts) >= 2:
                        self.db.ban_mac(parts[1].lower(), parts[2] if len(parts) > 2 else "No reason")
                        print(f"✅ MAC banned.")
                elif cmd.lower().startswith('unban_mac '):
                    if self.db.unban_mac(cmd.split(' ', 1)[1].lower()):
                        print(f"✅ MAC unbanned.")
                    else:
                        print(f"⚠️ MAC was not banned.")
                elif cmd.lower().startswith('stats '):
                    stats = self.db.get_stats(cmd.split(' ', 1)[1].strip())
                    if stats:
                        print(f"\n📊 Uploaded: {FileTransferUtils.format_size(stats['uploaded'])} | Downloaded: {FileTransferUtils.format_size(stats['downloaded'])}")
                    else:
                        print("User not found.")
                elif cmd.lower() == 'files':
                    files = os.listdir(self.shared_folder)
                    if not files:
                        print("\n📭 No files")
                    else:
                        print(f"\n📁 Files ({len(files)}):")
                        for f in files:
                            path = os.path.join(self.shared_folder, f)
                            if os.path.isfile(path):
                                print(f"  📄 {f} ({FileTransferUtils.format_size(os.path.getsize(path))})")
                elif cmd.lower() == 'quit':
                    os._exit(0)
                elif cmd.strip():
                    print(f"❌ Unknown: '{cmd}'. Type 'help'.")
            except KeyboardInterrupt:
                print("\n\n🛑 Use 'quit' to exit")
            except Exception as e:
                print(f"❌ Error: {e}")


def main():
    SecureServer().start()


if __name__ == "__main__":
    main()