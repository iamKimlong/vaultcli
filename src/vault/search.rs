//! Search Operations
//!
//! Fast search and filtering of credentials.

use crate::db::{self, Credential, CredentialType};

use super::VaultResult;

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

pub fn search(conn: &rusqlite::Connection, query: &str) -> VaultResult<SearchResults> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        let credentials = db::get_all_credentials(conn)?;
        return Ok(SearchResults::new(credentials, None));
    }

    let credentials = db::search_credentials(conn, trimmed)?;
    Ok(SearchResults::new(credentials, Some(trimmed.to_string())))
}

pub fn search_by_tag(conn: &rusqlite::Connection, tag: &str) -> VaultResult<SearchResults> {
    let credentials = db::get_credentials_by_tag(conn, &[tag.to_string()])?;
    Ok(SearchResults::new(credentials, Some(format!("tag:{}", tag))))
}

pub fn search_by_type(
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

fn fetch_initial_credentials(
    conn: &rusqlite::Connection,
    query: Option<&str>,
) -> VaultResult<Vec<Credential>> {
    let Some(q) = query else {
        return db::get_all_credentials(conn).map_err(Into::into);
    };

    let trimmed = q.trim();
    if trimmed.is_empty() {
        return db::get_all_credentials(conn).map_err(Into::into);
    }

    db::search_credentials(conn, trimmed).map_err(Into::into)
}

fn filter_by_tag(credentials: &mut Vec<Credential>, tag: &str) {
    let tag_lower = tag.to_lowercase();
    credentials.retain(|c| credential_has_tag(c, &tag_lower));
}

fn credential_has_tag(cred: &Credential, tag_lower: &str) -> bool {
    cred.tags.iter().any(|ct| ct.to_lowercase().contains(tag_lower))
}

fn filter_by_type(credentials: &mut Vec<Credential>, cred_type: CredentialType) {
    credentials.retain(|c| c.credential_type == cred_type);
}

fn build_query_string(
    query: Option<&str>,
    tag: Option<&str>,
    cred_type: Option<CredentialType>,
) -> Option<String> {
    let mut parts = Vec::new();

    if let Some(q) = query {
        let trimmed = q.trim();
        if !trimmed.is_empty() {
            parts.push(trimmed.to_string());
        }
    }

    if let Some(t) = tag {
        parts.push(format!("tag:{}", t));
    }

    if let Some(ct) = cred_type {
        parts.push(format!("type:{}", ct.as_str()));
    }

    if parts.is_empty() {
        return None;
    }

    Some(parts.join(" "))
}

pub fn search_combined(
    conn: &rusqlite::Connection,
    query: Option<&str>,
    tag: Option<&str>,
    cred_type: Option<CredentialType>,
) -> VaultResult<SearchResults> {
    let mut credentials = fetch_initial_credentials(conn, query)?;

    if let Some(t) = tag {
        filter_by_tag(&mut credentials, t);
    }

    if let Some(ct) = cred_type {
        filter_by_type(&mut credentials, ct);
    }

    let query_string = build_query_string(query, tag, cred_type);
    Ok(SearchResults::new(credentials, query_string))
}

fn compare_by_access_time(a: &Credential, b: &Credential) -> std::cmp::Ordering {
    let a_time = a.accessed_at.unwrap_or(a.updated_at);
    let b_time = b.accessed_at.unwrap_or(b.updated_at);
    b_time.cmp(&a_time)
}

pub fn get_recent(conn: &rusqlite::Connection, limit: usize) -> VaultResult<SearchResults> {
    let mut all = db::get_all_credentials(conn)?;
    all.sort_by(compare_by_access_time);
    all.truncate(limit);
    Ok(SearchResults::new(all, Some("recent".to_string())))
}

pub fn get_all_tags(conn: &rusqlite::Connection) -> VaultResult<Vec<String>> {
    let all = db::get_all_credentials(conn)?;
    let mut tags: Vec<String> = all.into_iter().flat_map(|c| c.tags).collect();
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

    fn create_test_credential(name: &str, ctype: CredentialType, tags: Vec<&str>) -> Credential {
        let key = test_key();
        let blob = encrypt_string(key.as_ref(), "secret").unwrap();
        let mut cred = Credential::new(name.to_string(), ctype, blob);
        cred.tags = tags.into_iter().map(|s| s.to_string()).collect();
        cred
    }

    fn setup_test_data(conn: &rusqlite::Connection) {
        let creds = vec![
            ("AWS Prod", CredentialType::ApiKey, vec!["cloud", "prod"]),
            ("AWS Staging", CredentialType::ApiKey, vec!["cloud", "staging"]),
            ("GitHub Token", CredentialType::ApiKey, vec!["dev"]),
            ("Gmail", CredentialType::Password, vec!["personal"]),
        ];

        for (name, ctype, tags) in creds {
            let cred = create_test_credential(name, ctype, tags);
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
    fn test_search_by_type() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let results = search_by_type(db.conn(), CredentialType::ApiKey).unwrap();
        assert_eq!(results.total, 3);

        let results = search_by_type(db.conn(), CredentialType::Password).unwrap();
        assert_eq!(results.total, 1);
    }

    #[test]
    fn test_combined_search() {
        let db = Database::open_in_memory().unwrap();
        setup_test_data(db.conn());

        let results = search_combined(db.conn(), Some("AWS"), Some("prod"), None).unwrap();
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
