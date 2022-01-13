extern crate base64;
extern crate vb_accumulator;
//extern crate bls12_381;

use std::convert::TryInto;
use crate::{db, DBPool, Result};
use common::*;
use warp::{http::StatusCode, reject, reply::json, Reply};
use base64::{decode as base64decode};
use std::str;
use ark_bls12_381::Bls12_381;
use blake2::Blake2b;
// use digest::{BlockInput, Digest as Digest2, FixedOutput, Reset, Update};

// use ark_bls12_381::{Bls12_381, G1Affine};
//use bls12_381::*;

use ark_ec::{
    models::{ModelParameters, SWModelParameters},
    short_weierstrass_jacobian::*,
};

use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, SWFlags, SerializationError,
};

use vb_accumulator::setup::{Keypair, SetupParams};
use vb_accumulator::positive::{PositiveAccumulator, Accumulator};
use vb_accumulator::persistence::State;

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

    // let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);

    let mut accumulator_bytes: [u8; 48] = [0; 48];
    let mut decoded_accumulator_elements = decoded_accumulator.split(",");
    let mut i=0;
    for s in decoded_accumulator_elements {
        accumulator_bytes[i] = s.parse::<u8>().unwrap();
        i=i+1;
    }

    let mut params_bytes: [u8; 144] = [0; 144];
    let mut decoded_params_elements = decoded_params.split(",");
    let mut j=0;
    for s in decoded_params_elements {
        params_bytes[j] = s.parse::<u8>().unwrap();
        j=j+1;
    }

    let mut pub_key_bytes: [u8; 96] = [0; 96];
    let mut decoded_pub_key_elements = decoded_pub_key.split(",");
    let mut k=0;
    for s in decoded_pub_key_elements {
        pub_key_bytes[k] = s.parse::<u8>().unwrap();
        k=k+1;
    }

    // let mut pub_key_bytes: [u8; 96] = [0; 96];
    // let mut decoded_pub_key_elements = decoded_pub_key.split(",");
    // let mut i=0;
    // for s in decoded_pub_key_elements {
    //     pub_key_bytes[i] = s.parse::<u8>().unwrap();
    //     i=i+1;
    // }

    //let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
    //let g1 = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
    //let params1 = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);


    let params = SetupParams::<Bls12_381>::new::<Blake2b>(&params_bytes);


    let original_accumulator:PositiveAccumulator<Bls12_381> = PositiveAccumulator::initialize(&params);

    // let g1affine = <AffineCurve as G1Affine>::from_compressed(&accumulator_bytes).unwrap();
    //let g1affine = G1Affine::from_compressed(&accumulator_bytes).unwrap();

    //let aff = GroupAffine::<P>::deserialize_uncompressed(reader)?;

    //let g1 = AffineCurve::fromBytes();
    // let aaa = PositiveAccumulator::from_accumulated()deserialize().deserialize()_from();

    let mut acc: &[u8] = &accumulator_bytes;
    let verifAccumulator: PositiveAccumulator<Bls12_381> = PositiveAccumulator::from_accumulated(GroupAffine::deserialize(acc).unwrap());
    //accumulator.verify_membership()
    //pub type G1Affine = GroupAffine<>;

    let found = false;
    let encodedPassword;
    //TODO
    for (let i = 0; i < 3; i++) {
        try {
            if (verifAccumulator.verify_membership(encodedPassword, new MembershipWitness(fromObject(user.witnesses[i])), fromObject(user.pubKey), params)) {
                found = true;
                break;
            }
        } catch (e: unknown) {
            console.log("Something wrong");
            console.log(e);
            if (e instanceof Error) {
                console.log(e.message);
            }
        }
    }

    if (!found) {
        return res.status(401).send("Login failed");
    }



    Ok(StatusCode::OK)
}

fn pop(barry: &[u8]) -> &[u8; 48] {
    barry.try_into().expect("slice with incorrect length")
}
