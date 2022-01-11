use super::{get_db_con, Result};
use crate::{error::Error::*, DBPool};
use common::*;
use mobc_postgres::tokio_postgres::Row;

pub const TABLE: &str = "users";
const SELECT_FIELDS: &str = "id, username";

pub async fn fetch(db_pool: &DBPool) -> Result<Vec<User>> {
    let con = get_db_con(db_pool).await?;
    let query = format!("SELECT {} FROM {}", SELECT_FIELDS, TABLE);
    let rows = con.query(query.as_str(), &[]).await.map_err(DBQueryError)?;

    Ok(rows.iter().map(|r| row_to_user(&r)).collect())
}

pub async fn fetch_one(db_pool: &DBPool, id: i32) -> Result<User> {
    let con = get_db_con(db_pool).await?;
    let query = format!("SELECT {} FROM {} WHERE id = $1", SELECT_FIELDS, TABLE);

    let row = con
        .query_one(query.as_str(), &[&id])
        .await
        .map_err(DBQueryError)?;
    Ok(row_to_user(&row))
}

pub async fn create(db_pool: &DBPool, body: SignupRequest) -> Result<User> {
    let con = get_db_con(db_pool).await?;
    let query = format!("INSERT INTO {} (username) VALUES ($1) RETURNING *", TABLE);
    let row = con
        .query_one(query.as_str(), &[&body.username])
        .await
        .map_err(DBQueryError)?;
    Ok(row_to_user(&row))
}

fn row_to_user(row: &Row) -> User {
    let id: i32 = row.get(0);
    let username: String = row.get(1);
    User { id, username }
}
