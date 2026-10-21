import sqlite3
import subprocess
import datetime
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
DB_PATH = os.environ.get("AWGPANEL_DB_PATH", "/var/lib/sg-awg-panel/panel.db")

def init_db():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS awg_traffic_history (
                client_id INTEGER,
                date_str TEXT,
                rx_bytes INTEGER DEFAULT 0,
                tx_bytes INTEGER DEFAULT 0,
                PRIMARY KEY (client_id, date_str)
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS awg_traffic_state (
                client_id INTEGER PRIMARY KEY,
                last_rx INTEGER DEFAULT 0,
                last_tx INTEGER DEFAULT 0
            )
        """)

def get_clients():
    with sqlite3.connect(DB_PATH) as con:
        try:
            cur = con.execute("SELECT id, public_key FROM awg_clients")
            return {row[1]: row[0] for row in cur.fetchall()}
        except sqlite3.OperationalError:
            try:
                cur = con.execute("SELECT id, peer_public_key FROM awg_clients")
                return {row[1]: row[0] for row in cur.fetchall()}
            except sqlite3.OperationalError:
                return {}

def track():
    init_db()
    clients = get_clients()
    if not clients:
        logging.warning("Клиенты не найдены в БД:")
        return
        
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    
    try:
        out = subprocess.check_output(["awg", "show", "awg0", "dump"]).decode()
    except subprocess.CalledProcessError:
        logging.error("Не удалось выполнить awg show")
        return
        
    with sqlite3.connect(DB_PATH) as con:
        for line in out.strip().split("\n")[1:]:
            parts = line.split("\t")
            if len(parts) < 8: continue
            pubkey = parts[0]
            rx = int(parts[5])
            tx = int(parts[6])
            
            if pubkey not in clients:
                continue
            
            client_id = clients[pubkey]
            
            cur = con.execute("SELECT last_rx, last_tx FROM awg_traffic_state WHERE client_id = ?", (client_id,))
            row = cur.fetchone()
            
            if row:
                last_rx, last_tx = row
                delta_rx = rx - last_rx if rx >= last_rx else rx
                delta_tx = tx - last_tx if tx >= last_tx else tx
            else:
                delta_rx = rx
                delta_tx = tx
                con.execute("INSERT INTO awg_traffic_state (client_id, last_rx, last_tx) VALUES (?, ?, ?)", (client_id, rx, tx))
            
            if row:
                con.execute("UPDATE awg_traffic_state SET last_rx = ?, last_tx = ? WHERE client_id = ?", (rx, tx, client_id))
            
            con.execute("""
                INSERT INTO awg_traffic_history (client_id, date_str, rx_bytes, tx_bytes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(client_id, date_str) DO UPDATE SET
                    rx_bytes = rx_bytes + excluded.rx_bytes,
                    tx_bytes = tx_bytes + excluded.tx_bytes
            """, (client_id, today, delta_rx, delta_tx))
        con.commit()

if __name__ == "__main__":
    track()
