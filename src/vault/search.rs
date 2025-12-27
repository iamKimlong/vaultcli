//! Search and Filter Operations
//!
//! Fast search and filtering of credentials.

use crate::db::{self, Credential, CredentialType};

use super::VaultResult;

/// Search results with metadata
#[derive(Debug, Clone)]
pub struct SearchResults {
    pub credentials: Vec<Credential>,
    pub total: usize,
    pub query: Option<String>,
}

impl SearchResults {
    pub fn new(credentials: Vec<Credential>, query: Option<String>) -> Self {
        let total = credentials.len();
        Self {
            credentials,
            total,
            query,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }
}

/// Search credentials by text query
pub fn search(conn: &rusqlite::Connection, query: &str) -> VaultResult<SearchResults> {
    let trimmed = query.trim();
    let credentials = if trimmed.is_empty() {
        db::get_all_credentials(conn)?
    } else {
        db::search_credentials(conn, trimmed)?
    };

    Ok(SearchResults::new(
        credentials,
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        },
    ))
}

/// Filter credentials by tag
pub fn filter_by_tag(conn: &rusqlite::Connection, tag: &str) -> VaultResult<SearchResults> {
    let credentials = db::get_credentials_by_tag(conn, tag)?;
    Ok(SearchResults::new(credentials, Some(format!("tag:{}", tag))))
}

/// Filter credentials by type
pub fn filter_by_type(
    conn: &rusqlite::Connection,
    cred_type: CredentialType,
) -> VaultResult<SearchResults> {
    let all = db::get_all_credentials(conn)?;
    let filtered: Vec<_> = all
        .into_iter()
        .filter(|c| c.credential_type == cred_type)
        .collect();

    Ok(SearchResults::new(
        filtered,
        Some(format!("type:{}", cred_type.as_str())),
    ))
}

/// Combined filter with multiple criteria
pub fn filter_combined(
    conn: &rusqlite::Connection,
    query: Option<&str>,
    tag: Option<&str>,
    cred_type: Option<CredentialType>,
) -> VaultResult<SearchResults> {
    // Start with all credentials or search results
    let mut credentials = match query {
        Some(q) if !q.trim().is_empty() => db::search_credentials(conn, q.trim())?,
        _ => db::get_all_credentials(conn)?,
    };

    // Apply filters
    if let Some(t) = tag {
        let tag_lower = t.to_lowercase();
        credentials.retain(|c| c.tags.iter().any(|ct| ct.to_lowercase().contains(&tag_lower)));
    }

    if let Some(ct) = cred_type {
        credentials.retain(|c| c.credential_type == ct);
    }

    // Build query string for display
    let mut query_parts = Vec::new();
    if let Some(q) = query {
        if !q.trim().is_empty() {
            query_parts.push(q.trim().to_string());
        }
    }
    if let Some(t) = tag {
        query_parts.push(format!("tag:{}", t));
    }
    if let Some(ct) = cred_type {
        query_parts.push(format!("type:{}", ct.as_str()));
    }

    let query_string = if query_parts.is_empty() {
        None
    } else {
        Some(query_parts.join(" "))
    };

    Ok(SearchResults::new(credentials, query_string))
}

/// Get recently accessed credentials
pub fn get_recent(conn: &rusqlite::Connection, limit: usize) -> VaultResult<SearchResults> {
    let mut all = db::get_all_credentials(conn)?;

    // Sort by accessed_at (most recent first), then by updated_at
    all.sort_by(|a, b| {
        let a_time = a.accessed_at.unwrap_or(a.updated_at);
        let b_time = b.accessed_at.unwrap_or(b.updated_at);
        b_time.cmp(&a_time)
    });

    all.truncate(limit);

    Ok(SearchResults::new(all, Some("recent".to_string())))
}

/// Get all unique tags
pub fn get_all_tags(conn: &rusqlite::Connection) -> VaultResult<Vec<String>> {
    let all = db::get_all_credentials(conn)?;

    let mut tags: Vec<String> = all
        .into_iter()
        .flat_map(|c| c.tags)
        .collect();

    tags.sort();
    tags.dedup();

    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_string, MasterKey};
    use crate::db::Database;

    fn test_key() -> MasterKey {
        MasterKey::from_bytes([0x42u8; 32])
    }

    fn setup_test_data(conn: &rusqlite::Connection) {
        let key = test_key();
        let blob = |s: &str| encrypt_string(key.as_ref(), s).unwrap();

        let creds = vec![
            ("AWS Prod", CredentialType::ApiKey, vec!["cloud", "prod"]),
            ("AWS Staging", CredentialType::ApiKey, vec!["cloud", "staging"]),
            ("GitHub Token", CredentialType::ApiKey, vec!["dev"]),
            ("Gmail", CredentialType::Password, vec!["personal"]),
        ];

        for (name, ctype, tags) in creds {
            let mut cred = Credential::new(
                name.to_string(),
                ctype,
                blob("secret"),
            );
            cred.tags = tags.into_iter().map(|s| s.to_string()).collect();
            db::create_credential(conn, &cred).unwrap();
        }
    }

    #[test]
    fn test_search() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let results = search(db.conn(), "AWS").unwrap();
        assert_eq!(results.total, 2);

        let results = search(db.conn(), "GitHub").unwrap();
        assert_eq!(results.total, 1);

        let results = search(db.conn(), "").unwrap();
        assert_eq!(results.total, 4);
    }

    #[test]
    fn test_filter_by_type() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let results = filter_by_type(db.conn(), CredentialType::ApiKey).unwrap();
        assert_eq!(results.total, 3);

        let results = filter_by_type(db.conn(), CredentialType::Password).unwrap();
        assert_eq!(results.total, 1);
    }

    #[test]
    fn test_combined_filter() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let results = filter_combined(
            db.conn(),
            Some("AWS"),
            Some("prod"),
            None,
        )
        .unwrap();
        assert_eq!(results.total, 1);
        assert_eq!(results.credentials[0].name, "AWS Prod");
    }

    #[test]
    fn test_get_all_tags() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let tags = get_all_tags(db.conn()).unwrap();
        assert!(tags.contains(&"cloud".to_string()));
        assert!(tags.contains(&"prod".to_string()));
        assert!(tags.contains(&"dev".to_string()));
    }
}
