use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;
use tracing::{debug, info};
use uuid::Uuid;

/// Represents a packet capture session
#[derive(Debug, Clone)]
pub struct CaptureSessionInfo {
    pub id: String,
    pub interface: String,
    pub filter: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub packet_count: i64,
}

/// Represents a stored packet
#[derive(Debug, Clone)]
pub struct StoredPacket {
    pub id: i64,
    pub session_id: String,
    pub timestamp: DateTime<Utc>,
    pub length: i32,
    pub data: Vec<u8>,
}

/// SQLite-based packet storage
pub struct PacketStore {
    conn: Connection,
}

impl PacketStore {
    /// Create a new packet store or open an existing one
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn = Connection::open(db_path).context("Failed to open database")?;
        let store = Self { conn };
        store.initialize_schema()?;
        Ok(store)
    }

    /// Create an in-memory database (useful for testing)
    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("Failed to create in-memory database")?;
        let store = Self { conn };
        store.initialize_schema()?;
        Ok(store)
    }

    /// Initialize the database schema
    fn initialize_schema(&self) -> Result<()> {
        debug!("Initializing database schema");
        
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                interface TEXT NOT NULL,
                filter TEXT,
                start_time TEXT NOT NULL,
                end_time TEXT,
                packet_count INTEGER DEFAULT 0
            )",
            [],
        ).context("Failed to create sessions table")?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                length INTEGER NOT NULL,
                data BLOB NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )",
            [],
        ).context("Failed to create packets table")?;

        // Create indices for performance
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_packets_session 
             ON packets(session_id)",
            [],
        )?;

        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_packets_timestamp 
             ON packets(timestamp)",
            [],
        )?;

        Ok(())
    }

    /// Create a new capture session
    pub fn create_session(&self, interface: &str, filter: Option<&str>) -> Result<String> {
        let session_id = Uuid::new_v4().to_string();
        let start_time = Utc::now();

        info!("Creating new capture session: {}", session_id);

        self.conn.execute(
            "INSERT INTO sessions (id, interface, filter, start_time) VALUES (?1, ?2, ?3, ?4)",
            params![session_id, interface, filter, start_time.to_rfc3339()],
        ).context("Failed to create session")?;

        Ok(session_id)
    }

    /// End a capture session
    pub fn end_session(&self, session_id: &str) -> Result<()> {
        let end_time = Utc::now();
        
        self.conn.execute(
            "UPDATE sessions SET end_time = ?1 WHERE id = ?2",
            params![end_time.to_rfc3339(), session_id],
        ).context("Failed to end session")?;

        Ok(())
    }

    /// Save a packet to the database
    pub fn save_packet(
        &self,
        session_id: &str,
        timestamp: DateTime<Utc>,
        data: &[u8],
    ) -> Result<i64> {
        let mut stmt = self.conn.prepare_cached(
            "INSERT INTO packets (session_id, timestamp, length, data) 
             VALUES (?1, ?2, ?3, ?4)"
        ).context("Failed to prepare insert statement")?;

        let packet_id = stmt.insert(params![
            session_id,
            timestamp.to_rfc3339(),
            data.len() as i32,
            data,
        ]).context("Failed to insert packet")?;

        // Update session packet count
        self.conn.execute(
            "UPDATE sessions SET packet_count = packet_count + 1 WHERE id = ?1",
            params![session_id],
        )?;

        Ok(packet_id)
    }

    /// Get session information
    pub fn get_session(&self, session_id: &str) -> Result<Option<CaptureSessionInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, interface, filter, start_time, end_time, packet_count 
             FROM sessions WHERE id = ?1"
        )?;

        let result = stmt.query_row(params![session_id], |row| {
            Ok(CaptureSessionInfo {
                id: row.get(0)?,
                interface: row.get(1)?,
                filter: row.get(2)?,
                start_time: row.get::<_, String>(3)?.parse().unwrap(),
                end_time: row.get::<_, Option<String>>(4)?
                    .and_then(|s| s.parse().ok()),
                packet_count: row.get(5)?,
            })
        });

        match result {
            Ok(session) => Ok(Some(session)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e).context("Failed to query session"),
        }
    }

    /// List all sessions
    pub fn list_sessions(&self) -> Result<Vec<CaptureSessionInfo>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, interface, filter, start_time, end_time, packet_count 
             FROM sessions ORDER BY start_time DESC"
        )?;

        let sessions = stmt.query_map([], |row| {
            Ok(CaptureSessionInfo {
                id: row.get(0)?,
                interface: row.get(1)?,
                filter: row.get(2)?,
                start_time: row.get::<_, String>(3)?.parse().unwrap(),
                end_time: row.get::<_, Option<String>>(4)?
                    .and_then(|s| s.parse().ok()),
                packet_count: row.get(5)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        Ok(sessions)
    }

    /// Get packets for a session
    pub fn get_packets(&self, session_id: &str, limit: Option<i64>) -> Result<Vec<StoredPacket>> {
        let query = if let Some(lim) = limit {
            format!(
                "SELECT id, session_id, timestamp, length, data 
                 FROM packets WHERE session_id = ?1 
                 ORDER BY timestamp ASC LIMIT {}",
                lim
            )
        } else {
            "SELECT id, session_id, timestamp, length, data 
             FROM packets WHERE session_id = ?1 
             ORDER BY timestamp ASC".to_string()
        };

        let mut stmt = self.conn.prepare(&query)?;

        let packets = stmt.query_map(params![session_id], |row| {
            Ok(StoredPacket {
                id: row.get(0)?,
                session_id: row.get(1)?,
                timestamp: row.get::<_, String>(2)?.parse().unwrap(),
                length: row.get(3)?,
                data: row.get(4)?,
            })
        })?.collect::<Result<Vec<_>, _>>()?;

        Ok(packets)
    }

    /// Get total number of packets in database
    pub fn get_total_packet_count(&self) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM packets",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_store() {
        let store = PacketStore::new_in_memory();
        assert!(store.is_ok());
    }

    #[test]
    fn test_create_session() {
        let store = PacketStore::new_in_memory().unwrap();
        let session_id = store.create_session("eth0", Some("tcp port 80"));
        assert!(session_id.is_ok());
        
        let session_id = session_id.unwrap();
        let session = store.get_session(&session_id).unwrap();
        assert!(session.is_some());
        
        let session = session.unwrap();
        assert_eq!(session.interface, "eth0");
        assert_eq!(session.filter, Some("tcp port 80".to_string()));
        assert_eq!(session.packet_count, 0);
    }

    #[test]
    fn test_save_and_retrieve_packets() {
        let store = PacketStore::new_in_memory().unwrap();
        let session_id = store.create_session("eth0", None).unwrap();
        
        let packet_data = vec![0x01, 0x02, 0x03, 0x04];
        let timestamp = Utc::now();
        
        let packet_id = store.save_packet(&session_id, timestamp, &packet_data);
        assert!(packet_id.is_ok());
        
        let packets = store.get_packets(&session_id, None).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].data, packet_data);
        
        let session = store.get_session(&session_id).unwrap().unwrap();
        assert_eq!(session.packet_count, 1);
    }

    #[test]
    fn test_end_session() {
        let store = PacketStore::new_in_memory().unwrap();
        let session_id = store.create_session("eth0", None).unwrap();
        
        let session = store.get_session(&session_id).unwrap().unwrap();
        assert!(session.end_time.is_none());
        
        store.end_session(&session_id).unwrap();
        
        let session = store.get_session(&session_id).unwrap().unwrap();
        assert!(session.end_time.is_some());
    }
}
