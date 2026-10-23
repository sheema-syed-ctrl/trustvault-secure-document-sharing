#!/usr/bin/env python3
"""
Data Migration Script: SQLite -> Neon PostgreSQL
Preserves primary keys, foreign keys, timestamps, and hashes without re-hashing passwords.
Synchronizes sequences and verifies data parity.
"""

import os
import sys
import json
import sqlite3
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

def migrate():
    load_dotenv()
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        print("ERROR: DATABASE_URL not found in environment.")
        sys.exit(1)

    print("Opening SQLite database (read-only)...")
    sqlite_conn = sqlite3.connect('file:db.sqlite3?mode=ro', uri=True)
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_cur = sqlite_conn.cursor()

    print("Connecting to Neon PostgreSQL...")
    pg_conn = psycopg2.connect(db_url)
    pg_cur = pg_conn.cursor()

    try:
        # Check current row counts in Neon
        print("\nChecking existing Neon counts before migration:")
        for tbl in ['accounts_user', 'documents_document', 'permissions_documentpermission', 'audit_auditevent']:
            pg_cur.execute(f"SELECT COUNT(*) FROM {tbl};")
            count = pg_cur.fetchone()[0]
            print(f"  {tbl}: {count} rows")
            if count > 0:
                print(f"WARNING: Table {tbl} already contains {count} rows. Aborting to avoid duplicates.")
                sys.exit(1)

        # 1. accounts_user
        print("\n--- Migrating accounts_user ---")
        sqlite_cur.execute("SELECT * FROM accounts_user ORDER BY id ASC;")
        users = sqlite_cur.fetchall()
        print(f"Found {len(users)} users in SQLite.")

        user_insert_query = """
            INSERT INTO accounts_user (
                id, password, last_login, is_superuser, username,
                first_name, last_name, email, is_staff, is_active,
                date_joined, role
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        for u in users:
            pg_cur.execute(user_insert_query, (
                u['id'],
                u['password'],
                u['last_login'],
                bool(u['is_superuser']),
                u['username'],
                u['first_name'],
                u['last_name'],
                u['email'],
                bool(u['is_staff']),
                bool(u['is_active']),
                u['date_joined'],
                u['role'],
            ))
        print(f"Inserted {len(users)} users into Neon.")

        # 2. documents_document
        print("\n--- Migrating documents_document ---")
        sqlite_cur.execute("SELECT * FROM documents_document ORDER BY id ASC;")
        docs = sqlite_cur.fetchall()
        print(f"Found {len(docs)} documents in SQLite.")

        doc_insert_query = """
            INSERT INTO documents_document (
                id, uuid, name, description, category,
                original_filename, storage_filename, file_size,
                mime_type, sha256_hash, created_at, updated_at,
                owner_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        for d in docs:
            pg_cur.execute(doc_insert_query, (
                d['id'],
                d['uuid'],
                d['name'],
                d['description'],
                d['category'],
                d['original_filename'],
                d['storage_filename'],
                d['file_size'],
                d['mime_type'],
                d['sha256_hash'],
                d['created_at'],
                d['updated_at'],
                d['owner_id'],
            ))
        print(f"Inserted {len(docs)} documents into Neon.")

        # 3. permissions_documentpermission
        print("\n--- Migrating permissions_documentpermission ---")
        sqlite_cur.execute("SELECT * FROM permissions_documentpermission ORDER BY id ASC;")
        perms = sqlite_cur.fetchall()
        print(f"Found {len(perms)} permissions in SQLite.")

        perm_insert_query = """
            INSERT INTO permissions_documentpermission (
                id, uuid, permission_type, created_at, updated_at,
                document_id, granted_by_id, user_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        """
        for p in perms:
            pg_cur.execute(perm_insert_query, (
                p['id'],
                p['uuid'],
                p['permission_type'],
                p['created_at'],
                p['updated_at'],
                p['document_id'],
                p['granted_by_id'],
                p['user_id'],
            ))
        print(f"Inserted {len(perms)} permissions into Neon.")

        # 4. audit_auditevent
        print("\n--- Migrating audit_auditevent ---")
        sqlite_cur.execute("SELECT * FROM audit_auditevent ORDER BY id ASC;")
        events = sqlite_cur.fetchall()
        print(f"Found {len(events)} audit events in SQLite.")

        event_insert_query = """
            INSERT INTO audit_auditevent (
                id, uuid, event_type, status, actor_username,
                target_document_id_snapshot, target_document_name_snapshot,
                target_username, previous_permission, new_permission,
                timestamp, ip_address, user_agent, correlation_id,
                metadata, actor_id, target_document_id, target_user_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        for e in events:
            # Parse metadata JSON string to ensure valid jsonb
            raw_meta = e['metadata']
            if isinstance(raw_meta, str):
                try:
                    parsed_meta = json.loads(raw_meta)
                except Exception:
                    parsed_meta = {}
            elif isinstance(raw_meta, dict):
                parsed_meta = raw_meta
            else:
                parsed_meta = {}

            pg_cur.execute(event_insert_query, (
                e['id'],
                e['uuid'],
                e['event_type'],
                e['status'],
                e['actor_username'],
                e['target_document_id_snapshot'],
                e['target_document_name_snapshot'],
                e['target_username'],
                e['previous_permission'],
                e['new_permission'],
                e['timestamp'],
                e['ip_address'],
                e['user_agent'],
                e['correlation_id'],
                psycopg2.extras.Json(parsed_meta),
                e['actor_id'],
                e['target_document_id'],
                e['target_user_id'],
            ))
        print(f"Inserted {len(events)} audit events into Neon.")

        # 5. Synchronize sequences
        print("\n--- Synchronizing PostgreSQL primary key sequences ---")
        seq_tables = [
            'accounts_user',
            'documents_document',
            'permissions_documentpermission',
            'audit_auditevent'
        ]
        for tbl in seq_tables:
            pg_cur.execute(f"SELECT pg_get_serial_sequence('{tbl}', 'id');")
            seq_name = pg_cur.fetchone()[0]
            if seq_name:
                pg_cur.execute(f"SELECT setval('{seq_name}', (SELECT COALESCE(MAX(id), 1) FROM {tbl}));")
                new_val = pg_cur.fetchone()[0]
                print(f"  Sequence {seq_name} reset to {new_val}")
            else:
                # If identity column instead of serial
                pg_cur.execute(f"""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = '{tbl}' AND is_identity = 'YES';
                """)
                identity_col = pg_cur.fetchone()
                if identity_col:
                    pg_cur.execute(f"SELECT setval(pg_get_serial_sequence('{tbl}', '{identity_col[0]}'), (SELECT COALESCE(MAX(id), 1) FROM {tbl}));")
                    print(f"  Identity sequence for {tbl} reset.")

        # 6. Verify row counts and data integrity
        print("\n--- Verifying Neon row counts & data integrity ---")
        expected_counts = {
            'accounts_user': len(users),
            'documents_document': len(docs),
            'permissions_documentpermission': len(perms),
            'audit_auditevent': len(events),
        }
        for tbl, expected in expected_counts.items():
            pg_cur.execute(f"SELECT COUNT(*) FROM {tbl};")
            actual = pg_cur.fetchone()[0]
            print(f"  {tbl}: expected={expected}, actual={actual}")
            assert actual == expected, f"Count mismatch on {tbl}: expected {expected}, got {actual}"

        # Verify specific records
        pg_cur.execute("SELECT id, username, role FROM accounts_user ORDER BY id ASC;")
        pg_users = pg_cur.fetchall()
        print(f"Verified {len(pg_users)} users in Neon: {[(u[0], u[1], u[2]) for u in pg_users]}")

        pg_cur.execute("SELECT id, original_filename, storage_filename, sha256_hash FROM documents_document ORDER BY id ASC;")
        pg_docs = pg_cur.fetchall()
        print(f"Verified {len(pg_docs)} documents in Neon:")
        for d in pg_docs:
            print(f"  ID {d[0]}: {d[1]} -> {d[2]} ({d[3][:12]}...)")

        # Commit the transaction!
        pg_conn.commit()
        print("\nSUCCESS: All data successfully migrated to Neon PostgreSQL and committed!")

    except Exception as err:
        pg_conn.rollback()
        print(f"\nERROR DURING MIGRATION (Rolled back): {err}")
        raise
    finally:
        sqlite_conn.close()
        pg_conn.close()

if __name__ == '__main__':
    migrate()
