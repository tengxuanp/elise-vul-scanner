#!/usr/bin/env python3
"""
Database initialization script for the vulnerable lab app.
Creates tables and seeds with test data.
"""

import sqlite3
import os

DB_PATH = 'lab.db'

def init_database():
    """Initialize database with tables and seed data"""
    
    # Ensure current directory exists (no need to create lab subdirectory)
    
    # Remove existing database if it exists
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            balance REAL DEFAULT 0.0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            price REAL NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL
        )
    ''')
    
    # Seed data
    # Users with simple passwords
    users_data = [
        ('alice', 'alice', 100.0),
        ('bob', 'bob', 50.0)
    ]
    
    cursor.executemany(
        "INSERT INTO users (username, password, balance) VALUES (?, ?, ?)",
        users_data
    )
    
    # Products including one with XSS payload
    products_data = [
        (1, 'apple', 1.99),
        (2, 'banana', 0.99),
        (3, '<b>xssable</b>', 9.99)
    ]
    
    cursor.executemany(
        "INSERT INTO products (id, name, price) VALUES (?, ?, ?)",
        products_data
    )
    
    # Commit and close
    conn.commit()
    conn.close()
    
    print(f"Database initialized at {DB_PATH}")
    print("Seeded with:")
    print("- Users: alice/alice (balance: 100.0), bob/bob (balance: 50.0)")
    print("- Products: apple ($1.99), banana ($0.99), <b>xssable</b> ($9.99)")

if __name__ == '__main__':
    init_database()
