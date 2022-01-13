use super::{get_db_con, Result};
use crate::{error::Error::*, DBPool};
use common::*;
use mobc_postgres::tokio_postgres::Row;
use std::collections::HashMap;

pub const TABLE: &str = "users";
const SELECT_FIELDS: &str = "id, username, accumulator, pub_key, witnesses, params";

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

pub async fn fetch_one_by_username(db_pool: &DBPool, username: String) -> Result<User> {
    let con = get_db_con(db_pool).await?;
    let query = format!("SELECT {} FROM {} WHERE username = $1", SELECT_FIELDS, TABLE);

    let row = con
        .query_one(query.as_str(), &[&username])
        .await
        .map_err(DBQueryError)?;
    Ok(row_to_user(&row))
}

pub async fn create(db_pool: &DBPool, body: SignupRequest) -> Result<User> {
    let con = get_db_con(db_pool).await?;
    let query = format!("INSERT INTO {} (username, accumulator, pub_key, witnesses, params) VALUES ($1, $2, $3, $4, $5) RETURNING *", TABLE);

    let row = con
        .query_one(query.as_str(), &[&body.username, &body.accumulator, &body.pub_key, &body.witnesses, &body.params])
        .await
        .map_err(DBQueryError)?;
    Ok(row_to_user(&row))
}

fn row_to_user(row: &Row) -> User {
    let id: i32 = row.get(0);
    let username: String = row.get(1);
    let accumulator: String = row.get(2);
    let pub_key: String = row.get(3);
    let witnesses: String = row.get(4);
    let params: String = row.get(5);

    User { id, username, accumulator, pub_key, witnesses, params}
}
