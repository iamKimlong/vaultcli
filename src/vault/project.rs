//! Project Operations
//!
//! CRUD operations for projects.

use crate::db::{self, Project};

use super::{VaultError, VaultResult};

/// Create a new project
pub fn create_project(
    conn: &rusqlite::Connection,
    name: String,
    description: Option<String>,
    color: Option<String>,
) -> VaultResult<Project> {
    let mut project = Project::new(name, description);
    project.color = color;

    db::create_project(conn, &project)?;

    Ok(project)
}

/// Get a project by ID
pub fn get_project(conn: &rusqlite::Connection, id: &str) -> VaultResult<Project> {
    Ok(db::get_project(conn, id)?)
}

/// List all projects
pub fn list_projects(conn: &rusqlite::Connection) -> VaultResult<Vec<Project>> {
    Ok(db::get_all_projects(conn)?)
}

/// Delete a project
pub fn delete_project(conn: &rusqlite::Connection, id: &str) -> VaultResult<()> {
    if id == "default" {
        return Err(VaultError::OperationFailed(
            "Cannot delete the default project".to_string(),
        ));
    }

    db::delete_project(conn, id)?;
    Ok(())
}

/// Get credential count for a project
pub fn get_credential_count(conn: &rusqlite::Connection, project_id: &str) -> VaultResult<usize> {
    let creds = db::get_credentials_by_project(conn, project_id)?;
    Ok(creds.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[test]
    fn test_project_crud() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let project = create_project(
            conn,
            "Test Project".to_string(),
            Some("Description".to_string()),
            Some("#ff0000".to_string()),
        )
        .unwrap();

        assert_eq!(project.name, "Test Project");
        assert_eq!(project.color, Some("#ff0000".to_string()));

        let fetched = get_project(conn, &project.id).unwrap();
        assert_eq!(fetched.name, "Test Project");

        let all = list_projects(conn).unwrap();
        assert!(all.len() >= 2); // default + test

        delete_project(conn, &project.id).unwrap();
        assert!(get_project(conn, &project.id).is_err());
    }

    #[test]
    fn test_cannot_delete_default() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let result = delete_project(conn, "default");
        assert!(result.is_err());
    }
}
