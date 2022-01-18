extern crate base64;
extern crate vb_accumulator;

use crate::{db, DBPool, Result};
use common::*;
use warp::{http::StatusCode, reject, reply::json, Reply};
use base64::{decode as base64decode};
use std::str;
use ark_bls12_381::{Bls12_381, FrParameters, G2Affine};
use ark_ec::{PairingEngine};
use ark_serialize::{CanonicalDeserialize};

use vb_accumulator::setup::{PublicKey, SetupParams};
use vb_accumulator::positive::{PositiveAccumulator, Accumulator};
use vb_accumulator::witness::MembershipWitness;
use ark_ff::Fp256;

type Fr = <Bls12_381 as PairingEngine>::Fr;

pub async fn list_pets_handler(owner_id: i32, db_pool: DBPool) -> Result<impl Reply> {
    let pets = db::pet::fetch(&db_pool, owner_id)
        .await
        .map_err(reject::custom)?;
    Ok(json::<Vec<_>>(
        &pets.into_iter().map(PetResponse::of).collect(),
    ))
}

pub async fn create_pet_handler(
    owner_id: i32,
    body: PetRequest,
    db_pool: DBPool,
) -> Result<impl Reply> {
    Ok(json(&PetResponse::of(
        db::pet::create(&db_pool, owner_id, body)
            .await
            .map_err(reject::custom)?,
    )))
}

pub async fn delete_pet_handler(owner_id: i32, id: i32, db_pool: DBPool) -> Result<impl Reply> {
    db::pet::delete(&db_pool, owner_id, id)
        .await
        .map_err(reject::custom)?;
    Ok(StatusCode::OK)
}

pub async fn list_owners_handler(db_pool: DBPool) -> Result<impl Reply> {
    let owners = db::owner::fetch(&db_pool).await.map_err(reject::custom)?;
    Ok(json::<Vec<_>>(
        &owners.into_iter().map(OwnerResponse::of).collect(),
    ))
}

pub async fn fetch_owner_handler(id: i32, db_pool: DBPool) -> Result<impl Reply> {
    let owner = db::owner::fetch_one(&db_pool, id)
        .await
        .map_err(reject::custom)?;
    Ok(json(&OwnerResponse::of(owner)))
}

pub async fn create_owner_handler(body: OwnerRequest, db_pool: DBPool) -> Result<impl Reply> {
    Ok(json(&OwnerResponse::of(
        db::owner::create(&db_pool, body)
            .await
            .map_err(reject::custom)?,
    )))
}

pub async fn signup_handler(body: SignupRequest, db_pool: DBPool) -> Result<impl Reply> {
    Ok(json(&SignupResponse::of(
        db::user::create(&db_pool, body)
            .await
            .map_err(reject::custom)?,
    )))
}

pub async fn signin_handler(body: SigninRequest, db_pool: DBPool) -> Result<impl Reply> {
    let user: User = db::user::fetch_one_by_username(&db_pool, body.username)
        .await
        .map_err(reject::custom)?;

    let decoded_accumulator: String = String::from_utf8(base64decode(user.accumulator).unwrap().clone()).unwrap();
    let decoded_pub_key: String = String::from_utf8(base64decode(user.pub_key).unwrap().clone()).unwrap();
    let decoded_witnesses: String = String::from_utf8(base64decode(user.witnesses).unwrap().clone()).unwrap();
    let decoded_params: String = String::from_utf8(base64decode(user.params).unwrap().clone()).unwrap();
    let password = String::from_utf8(base64decode(body.password).unwrap().clone()).unwrap();

    let decoded_accumulator_elements = decoded_accumulator.split(",");
    let decoded_pub_key_elements = decoded_pub_key.split(",");
    let decoded_params_elements = decoded_params.split(",");

    let mut accumulator_vec = vec![];
    for s in decoded_accumulator_elements.clone() {
        accumulator_vec.push(s.parse::<u8>().unwrap());
    }

    let mut pub_key_vec = vec![];
    for s in decoded_pub_key_elements.clone() {
        pub_key_vec.push(s.parse::<u8>().unwrap());
    }

    let mut params_vec = vec![];
    for s in decoded_params_elements.clone() {
        params_vec.push(s.parse::<u8>().unwrap());
    }

    let decoded_witnesses_vec: Vec<&str> = decoded_witnesses.split(",").collect();
    let witnesses_count = decoded_witnesses_vec.len() / 48;
    let mut witnesses_vec = Vec::new();

    for x in 0..witnesses_count {
        let mut i = x * 48;
        let mut witness_bytes: [u8; 48] = [0; 48];

        let mut witness_bytes_vec = vec![];

        for y in 0..48 {
            witness_bytes[y] = decoded_witnesses_vec[i].parse::<u8>().unwrap();
            witness_bytes_vec.push(witness_bytes[y]);
            i = i + 1;
        }
        witnesses_vec.push(witness_bytes_vec);
    }

    let mut password_bytes: [u8; 32] = [0; 32];
    let decoded_password_elements = password.split(",");
    let mut i = 0;
    for s in decoded_password_elements {
        password_bytes[i] = s.parse::<u8>().unwrap();
        i = i + 1;
    }
    let ps: &[u8] = &password_bytes;
    let elem_pass: Fp256<FrParameters> = Fr::deserialize(ps).unwrap();

    let verify_accumulator: PositiveAccumulator<Bls12_381> = CanonicalDeserialize::deserialize(&accumulator_vec[..]).unwrap();
    let pub_key: PublicKey<G2Affine> = CanonicalDeserialize::deserialize(&pub_key_vec[..]).unwrap();
    let params: SetupParams<Bls12_381> = CanonicalDeserialize::deserialize(&params_vec[..]).unwrap();

    let mut found = false;
    for x in 0..witnesses_count {
        let witness_bytes_vec = witnesses_vec[x].clone();
        let witness_membership: MembershipWitness<<Bls12_381 as PairingEngine>::G1Affine> = CanonicalDeserialize::deserialize(&witness_bytes_vec[..]).unwrap();

        if verify_accumulator.verify_membership(&elem_pass, &witness_membership, &pub_key, &params) {
            found = true;
            break;
        }
    }

    if found {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::FORBIDDEN)
    }
}

