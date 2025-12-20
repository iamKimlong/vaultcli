//! Database Queries
//!
//! Parameterized queries for CRUD operations on credentials and projects.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, Row};

use super::{
    models::{AuditAction, AuditLog, Credential, CredentialType, Project},
    DbError, DbResult,
};

// ============================================================================
// Project Queries
// ============================================================================

/// Create a new project
pub fn create_project(conn: &Connection, project: &Project) -> DbResult<()> {
    conn.execute(
        r#"
        INSERT INTO projects (id, name, description, color, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![
            project.id,
            project.name,
            project.description,
            project.color,
            project.created_at.to_rfc3339(),
            project.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

/// Get a project by ID
pub fn get_project(conn: &Connection, id: &str) -> DbResult<Project> {
    conn.query_row(
        "SELECT id, name, description, color, created_at, updated_at FROM projects WHERE id = ?1",
        [id],
        row_to_project,
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => DbError::NotFound(format!("Project: {}", id)),
        _ => e.into(),
    })
}

/// Get all projects
pub fn get_all_projects(conn: &Connection) -> DbResult<Vec<Project>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, description, color, created_at, updated_at FROM projects ORDER BY name",
    )?;

    let projects = stmt
        .query_map([], row_to_project)?
        .filter_map(|r| r.ok())
        .collect();

    Ok(projects)
}

/// Update a project
pub fn update_project(conn: &Connection, project: &Project) -> DbResult<()> {
    let rows = conn.execute(
        r#"
        UPDATE projects
        SET name = ?2, description = ?3, color = ?4, updated_at = ?5
        WHERE id = ?1
        "#,
        params![
            project.id,
            project.name,
            project.description,
            project.color,
            Utc::now().to_rfc3339(),
        ],
    )?;

    if rows == 0 {
        return Err(DbError::NotFound(format!("Project: {}", project.id)));
    }

    Ok(())
}

/// Delete a project
pub fn delete_project(conn: &Connection, id: &str) -> DbResult<()> {
    // Move credentials to default project first
    conn.execute(
        "UPDATE credentials SET project_id = 'default' WHERE project_id = ?1",
        [id],
    )?;

    let rows = conn.execute("DELETE FROM projects WHERE id = ?1 AND id != 'default'", [id])?;

    if rows == 0 {
        return Err(DbError::NotFound(format!("Project: {}", id)));
    }

    Ok(())
}

fn row_to_project(row: &Row) -> rusqlite::Result<Project> {
    Ok(Project {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        color: row.get(3)?,
        created_at: parse_datetime(row.get::<_, String>(4)?),
        updated_at: parse_datetime(row.get::<_, String>(5)?),
    })
}

// ============================================================================
// Credential Queries
// ============================================================================

/// Create a new credential
pub fn create_credential(conn: &Connection, credential: &Credential) -> DbResult<()> {
    let tags_json = serde_json::to_string(&credential.tags).unwrap_or_else(|_| "[]".to_string());

    conn.execute(
        r#"
        INSERT INTO credentials (id, name, credential_type, project_id, username, encrypted_secret, encrypted_notes, url, tags, created_at, updated_at, accessed_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        "#,
        params![
            credential.id,
            credential.name,
            credential.credential_type.as_str(),
            credential.project_id,
            credential.username,
            credential.encrypted_secret,
            credential.encrypted_notes,
            credential.url,
            tags_json,
            credential.created_at.to_rfc3339(),
            credential.updated_at.to_rfc3339(),
            credential.accessed_at.map(|dt| dt.to_rfc3339()),
        ],
    )?;

    Ok(())
}

/// Get a credential by ID
pub fn get_credential(conn: &Connection, id: &str) -> DbResult<Credential> {
    conn.query_row(
        r#"
        SELECT id, name, credential_type, project_id, username, encrypted_secret, encrypted_notes, url, tags, created_at, updated_at, accessed_at
        FROM credentials
        WHERE id = ?1
        "#,
        [id],
        row_to_credential,
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => DbError::NotFound(format!("Credential: {}", id)),
        _ => e.into(),
    })
}

/// Get all credentials
pub fn get_all_credentials(conn: &Connection) -> DbResult<Vec<Credential>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, name, credential_type, project_id, username, encrypted_secret, encrypted_notes, url, tags, created_at, updated_at, accessed_at
        FROM credentials
        ORDER BY name
        "#,
    )?;

    let credentials = stmt
        .query_map([], row_to_credential)?
        .filter_map(|r| r.ok())
        .collect();

    Ok(credentials)
}

/// Get credentials by project
pub fn get_credentials_by_project(conn: &Connection, project_id: &str) -> DbResult<Vec<Credential>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, name, credential_type, project_id, username, encrypted_secret, encrypted_notes, url, tags, created_at, updated_at, accessed_at
        FROM credentials
        WHERE project_id = ?1
        ORDER BY name
        "#,
    )?;

    let credentials = stmt
        .query_map([project_id], row_to_credential)?
        .filter_map(|r| r.ok())
        .collect();

    Ok(credentials)
}

/// Get credentials by tag
pub fn get_credentials_by_tag(conn: &Connection, tag: &str) -> DbResult<Vec<Credential>> {
    let pattern = format!("%\"{}%", tag);
    let mut stmt = conn.prepare(
        r#"
        SELECT id, name, credential_type, project_id, username, encrypted_secret, encrypted_notes, url, tags, created_at, updated_at, accessed_at
        FROM credentials
        WHERE tags LIKE ?1
        ORDER BY name
        "#,
    )?;

    let credentials = stmt
        .query_map([pattern], row_to_credential)?
        .filter_map(|r| r.ok())
        .collect();

    Ok(credentials)
}

/// Search credentials using FTS5
pub fn search_credentials(conn: &Connection, query: &str) -> DbResult<Vec<Credential>> {
    // Escape special FTS5 characters
    let escaped_query = query
        .replace('"', "\"\"")
        .replace('*', "")
        .replace(':', "");

    if escaped_query.trim().is_empty() {
        return get_all_credentials(conn);
    }

    // Use prefix matching for better UX
    let fts_query = format!("\"{}\"*", escaped_query);

    let mut stmt = conn.prepare(
        r#"
        SELECT c.id, c.name, c.credential_type, c.project_id, c.username, c.encrypted_secret, c.encrypted_notes, c.url, c.tags, c.created_at, c.updated_at, c.accessed_at
        FROM credentials c
        INNER JOIN credentials_fts fts ON c.rowid = fts.rowid
        WHERE credentials_fts MATCH ?1
        ORDER BY rank
        "#,
    )?;

    let credentials = stmt
        .query_map([fts_query], row_to_credential)?
        .filter_map(|r| r.ok())
        .collect();

    Ok(credentials)
}

/// Update a credential
pub fn update_credential(conn: &Connection, credential: &Credential) -> DbResult<()> {
    let tags_json = serde_json::to_string(&credential.tags).unwrap_or_else(|_| "[]".to_string());

    let rows = conn.execute(
        r#"
        UPDATE credentials
        SET name = ?2, credential_type = ?3, project_id = ?4, username = ?5, encrypted_secret = ?6, encrypted_notes = ?7, url = ?8, tags = ?9, updated_at = ?10
        WHERE id = ?1
        "#,
        params![
            credential.id,
            credential.name,
            credential.credential_type.as_str(),
            credential.project_id,
            credential.username,
            credential.encrypted_secret,
            credential.encrypted_notes,
            credential.url,
            tags_json,
            Utc::now().to_rfc3339(),
        ],
    )?;

    if rows == 0 {
        return Err(DbError::NotFound(format!("Credential: {}", credential.id)));
    }

    Ok(())
}

/// Update credential access time
pub fn touch_credential(conn: &Connection, id: &str) -> DbResult<()> {
    conn.execute(
        "UPDATE credentials SET accessed_at = ?2 WHERE id = ?1",
        params![id, Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

/// Delete a credential
pub fn delete_credential(conn: &Connection, id: &str) -> DbResult<()> {
    let rows = conn.execute("DELETE FROM credentials WHERE id = ?1", [id])?;

    if rows == 0 {
        return Err(DbError::NotFound(format!("Credential: {}", id)));
    }

    Ok(())
}

fn row_to_credential(row: &Row) -> rusqlite::Result<Credential> {
    let tags_json: String = row.get(8)?;
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();

    let accessed_at: Option<String> = row.get(11)?;

    Ok(Credential {
        id: row.get(0)?,
        name: row.get(1)?,
        credential_type: CredentialType::from_str(&row.get::<_, String>(2)?),
        project_id: row.get(3)?,
        username: row.get(4)?,
        encrypted_secret: row.get(5)?,
        encrypted_notes: row.get(6)?,
        url: row.get(7)?,
        tags,
        created_at: parse_datetime(row.get::<_, String>(9)?),
        updated_at: parse_datetime(row.get::<_, String>(10)?),
        accessed_at: accessed_at.map(parse_datetime),
    })
}

// ============================================================================
// Audit Log Queries
// ============================================================================

/// Create an audit log entry
pub fn create_audit_log(conn: &Connection, log: &AuditLog) -> DbResult<i64> {
    conn.execute(
        r#"
        INSERT INTO audit_log (timestamp, action, credential_id, details, hmac)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            log.timestamp.to_rfc3339(),
            log.action.as_str(),
            log.credential_id,
            log.details,
            log.hmac,
        ],
    )?;

    Ok(conn.last_insert_rowid())
}

/// Get recent audit logs
pub fn get_recent_audit_logs(conn: &Connection, limit: usize) -> DbResult<Vec<AuditLog>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, timestamp, action, credential_id, details, hmac
        FROM audit_log
        ORDER BY timestamp DESC
        LIMIT ?1
        "#,
    )?;

    let logs = stmt
        .query_map([limit], |row| {
            Ok(AuditLog {
                id: row.get(0)?,
                timestamp: parse_datetime(row.get::<_, String>(1)?),
                action: AuditAction::from_str(&row.get::<_, String>(2)?),
                credential_id: row.get(3)?,
                details: row.get(4)?,
                hmac: row.get(5)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok(logs)
}

/// Get audit logs for a credential
pub fn get_credential_audit_logs(conn: &Connection, credential_id: &str) -> DbResult<Vec<AuditLog>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, timestamp, action, credential_id, details, hmac
        FROM audit_log
        WHERE credential_id = ?1
        ORDER BY timestamp DESC
        "#,
    )?;

    let logs = stmt
        .query_map([credential_id], |row| {
            Ok(AuditLog {
                id: row.get(0)?,
                timestamp: parse_datetime(row.get::<_, String>(1)?),
                action: AuditAction::from_str(&row.get::<_, String>(2)?),
                credential_id: row.get(3)?,
                details: row.get(4)?,
                hmac: row.get(5)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok(logs)
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_datetime(s: String) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[test]
    fn test_project_crud() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let project = Project::new("Test Project".to_string(), Some("Desc".to_string()));
        create_project(conn, &project).unwrap();

        let fetched = get_project(conn, &project.id).unwrap();
        assert_eq!(fetched.name, "Test Project");

        let all = get_all_projects(conn).unwrap();
        assert!(all.len() >= 2); // default + test

        delete_project(conn, &project.id).unwrap();
        assert!(get_project(conn, &project.id).is_err());
    }

    #[test]
    fn test_credential_crud() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let mut cred = Credential::new(
            "GitHub Token".to_string(),
            CredentialType::ApiKey,
            "default".to_string(),
            "encrypted_secret".to_string(),
        );
        cred.username = Some("user".to_string());
        cred.tags = vec!["dev".to_string(), "api".to_string()];

        create_credential(conn, &cred).unwrap();

        let fetched = get_credential(conn, &cred.id).unwrap();
        assert_eq!(fetched.name, "GitHub Token");
        assert_eq!(fetched.tags.len(), 2);

        delete_credential(conn, &cred.id).unwrap();
        assert!(get_credential(conn, &cred.id).is_err());
    }

    #[test]
    fn test_fts_search() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let cred1 = Credential::new(
            "AWS Production".to_string(),
            CredentialType::ApiKey,
            "default".to_string(),
            "enc".to_string(),
        );
        let cred2 = Credential::new(
            "AWS Staging".to_string(),
            CredentialType::ApiKey,
            "default".to_string(),
            "enc".to_string(),
        );
        let cred3 = Credential::new(
            "GitHub Token".to_string(),
            CredentialType::ApiKey,
            "default".to_string(),
            "enc".to_string(),
        );

        create_credential(conn, &cred1).unwrap();
        create_credential(conn, &cred2).unwrap();
        create_credential(conn, &cred3).unwrap();

        let results = search_credentials(conn, "AWS").unwrap();
        assert_eq!(results.len(), 2);

        let results = search_credentials(conn, "GitHub").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_audit_log() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let log = AuditLog::new(
            AuditAction::Create,
            Some("cred-1".to_string()),
            Some("Created credential".to_string()),
            "hmac_value".to_string(),
        );

        let id = create_audit_log(conn, &log).unwrap();
        assert!(id > 0);

        let recent = get_recent_audit_logs(conn, 10).unwrap();
        assert!(!recent.is_empty());
    }
}
