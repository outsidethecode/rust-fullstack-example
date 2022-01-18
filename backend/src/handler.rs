extern crate base64;
extern crate vb_accumulator;
//extern crate bls12_381;

use std::convert::TryInto;
use std::fs::File;
use crate::{db, DBPool, Result};
use common::*;
use warp::{http::StatusCode, reject, reply::json, Reply};
use base64::{decode as base64decode};
use std::str;
use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
use blake2::Blake2b;



// use digest::{BlockInput, Digest as Digest2, FixedOutput, Reset, Update};

// use ark_bls12_381::{Bls12_381, G1Affine};
//use bls12_381::*;

use ark_ec::{AffineCurve, models::{ModelParameters, SWModelParameters}, PairingEngine, short_weierstrass_jacobian::*};

use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, SWFlags, SerializationError,
};

use vb_accumulator::setup::{Keypair, PublicKey, SetupParams};
use vb_accumulator::positive::{PositiveAccumulator, Accumulator};
use vb_accumulator::persistence::State;
use vb_accumulator::witness::MembershipWitness;
use ark_bls12_381::Fr as BlsScalar;
use ark_ff::fields::PrimeField;
use ark_std::{rand::rngs::StdRng, rand::SeedableRng, UniformRand};
use vb_accumulator::persistence::*;

use std::collections::HashSet;
use std::hash::Hash;


type Fr = <Bls12_381 as PairingEngine>::Fr;

#[derive(Clone, Debug)]
pub struct InMemoryState<T: Clone> {
    pub db: HashSet<T>,
}

impl<T: Clone> InMemoryState<T> {
    pub fn new() -> Self {
        let db = HashSet::<T>::new();
        Self { db }
    }
}

impl<T: Clone + Hash + Eq + Sized> State<T> for InMemoryState<T> {
    fn add(&mut self, element: T) {
        self.db.insert(element);
    }

    fn remove(&mut self, element: &T) {
        self.db.remove(element);
    }

    fn has(&self, element: &T) -> bool {
        self.db.get(element).is_some()
    }

    fn size(&self) -> u64 {
        self.db.len() as u64
    }
}


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
    for s in decoded_accumulator_elements.clone() {
        accumulator_bytes[i] = s.parse::<u8>().unwrap();
        i=i+1;
    }

    let mut accumulator_vec = vec![];
    let mut i=0;
    for s in decoded_accumulator_elements.clone() {
        accumulator_vec.push(s.parse::<u8>().unwrap());
        i=i+1;
    }


    let mut params_bytes: [u8; 144] = [0; 144];
    let mut decoded_params_elements = decoded_params.split(",");
    let mut j=0;
    for s in decoded_params_elements.clone() {
        params_bytes[j] = s.parse::<u8>().unwrap();
        j=j+1;
    }

    let mut params_vec = vec![];
    let mut j=0;
    for s in decoded_params_elements.clone() {
        params_vec.push(s.parse::<u8>().unwrap());
        j=j+1;
    }

    let mut pub_key_bytes: [u8; 96] = [0; 96];
    let mut decoded_pub_key_elements = decoded_pub_key.split(",");
    let mut k=0;
    for s in decoded_pub_key_elements.clone() {
        pub_key_bytes[k] = s.parse::<u8>().unwrap();
        k=k+1;
    }


    let mut pub_key_vec = vec![];
    let mut k=0;
    for s in decoded_pub_key_elements.clone() {
        pub_key_vec.push(s.parse::<u8>().unwrap());
        k=k+1;
    }


    let mut decoded_witnesses_vec: Vec<&str> = decoded_witnesses.split(",").collect();
    let witnesses_count = decoded_witnesses_vec.len()/48;
    let mut witnesses_vec = Vec::new();

    for x in 0..witnesses_count {
        let mut l= x * 48;
        let mut witness_bytes: [u8; 48] = [0; 48];

        let mut witness_bytes_vec = vec![];

        for y in 0..48 {
            witness_bytes[y] = decoded_witnesses_vec[l].parse::<u8>().unwrap();
            witness_bytes_vec.push(witness_bytes[y]);
            l=l+1;
        }
        witnesses_vec.push(witness_bytes_vec);
    }

    let password = String::from_utf8(base64decode(body.password).unwrap().clone()).unwrap();

    let mut password_bytes: [u8; 32] = [0; 32];
    let mut decoded_password_elements = password.split(",");
    let mut m=0;
    for s in decoded_password_elements {
        password_bytes[m] = s.parse::<u8>().unwrap();
        m=m+1;
    }
    let mut ps: &[u8] = &password_bytes;

    let verify_accumulator: PositiveAccumulator<Bls12_381> = CanonicalDeserialize::deserialize(&accumulator_vec[..]).unwrap();
    let pub_key: PublicKey<G2Affine> = CanonicalDeserialize::deserialize(&pub_key_vec[..]).unwrap();
    let params: SetupParams<Bls12_381> = CanonicalDeserialize::deserialize(&params_vec[..]).unwrap();


    // --------------------------

    // type Fr = <Bls12_381 as PairingEngine>::Fr;
    // let elem = Fr::deserialize(acc);
    let elementPassword = BlsScalar::from_le_bytes_mod_order(&password_bytes); // THIS LOOK UGLY
    let elemPass = Fr::deserialize(ps).unwrap();
    // --------------------------

    //let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);




    let mut rng = StdRng::seed_from_u64(0u64);
    let mut state = InMemoryState::new();
    let keypair = Keypair::<Bls12_381>::generate_using_rng(&mut rng, &params);
    let elem = Fr::rand(&mut rng);

    let new_accumulator = verify_accumulator
        .add(elem, &keypair.secret_key, &mut state)
        .unwrap();

    let m_wit:MembershipWitness<G1Affine> = new_accumulator
        .get_membership_witness(&elem, &keypair.secret_key, &state)
        .unwrap();

    let mut temp_witness_bytes: [u8; 32];


    let mut serz = vec![];
    CanonicalSerialize::serialize(&m_wit, &mut serz).unwrap();
    let deserz: MembershipWitness<<Bls12_381 as PairingEngine>::G1Affine> = CanonicalDeserialize::deserialize(&serz[..]).unwrap();


    let mut serz_acc = vec![];
    CanonicalSerialize::serialize(&new_accumulator, &mut serz_acc).unwrap();


    // let bbb = <MembershipWitness<G1Affine> as CanonicalSerialize>::serialize(buffer);



    // --------------------------


    let mut found = false;

    for x in 0..witnesses_count {
        let mut witness_bytes_vec = witnesses_vec[x].clone();
        //let mut witness: &[u8; 32] = &witness_bytes;

        //let aaa = <MembershipWitness<G1Affine> as CanonicalDeserialize>::deserialize(&witness);


        //let witness_membership = <MembershipWitness<G1Affine>>::deserialize(witness).unwrap();
        let witness_membership: MembershipWitness<<Bls12_381 as PairingEngine>::G1Affine> = CanonicalDeserialize::deserialize(&witness_bytes_vec[..]).unwrap();

        if verify_accumulator.verify_membership(&elemPass, &witness_membership ,&pub_key, &params) {
            found = true;
            break;
        }

        if verify_accumulator2.verify_membership(&elemPass, &witness_membership ,&pub_key2, &params2) {
            found = true;
            break;
        }
    }

    if found {
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::FORBIDDEN)
    }
    //let params = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);
    //let g1 = <Bls12_381 as PairingEngine>::G1Projective::rand(&mut rng).into_affine();
    //let params1 = SetupParams::<Bls12_381>::generate_using_rng(&mut rng);

    // let original_accumulator:PositiveAccumulator<Bls12_381> = PositiveAccumulator::initialize(&params);

    // let g1affine = <AffineCurve as G1Affine>::from_compressed(&accumulator_bytes).unwrap();
    //let g1affine = G1Affine::from_compressed(&accumulator_bytes).unwrap();

    //let aff = GroupAffine::<P>::deserialize_uncompressed(reader)?;

    //let g1 = AffineCurve::fromBytes();
    // let aaa = PositiveAccumulator::from_accumulated()deserialize().deserialize()_from();



}

