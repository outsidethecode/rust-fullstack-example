use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Clone, PartialEq, Debug)]
pub struct Owner {
    pub id: i32,
    pub name: String,
}

#[derive(Deserialize, Clone, PartialEq, Debug)]
pub struct User {
    pub id: i32,
    pub username: String,
    // pub accumulator: HashMap<u8,u8>,
    // pub pubKey: HashMap<u8,u8>,
    // pub witnesses: Vec<HashMap<u8,u8>>,
    // pub params: HashMap<u8,u8>
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct OwnerRequest {
    pub name: String,
}

// #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
// pub struct Uint8ArrayJsonObject {
//     entries: 
// }

// #[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
// pub struct Uint8ArrayEntry {
//     key: String,
//     value: String
// }

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SignupRequest {
    pub username: String,
    pub accumulator: HashMap<u8,u8>,
    pub pubKey: HashMap<u8,u8>,
    pub witnesses: Vec<HashMap<u8,u8>>,
    pub params: HashMap<u8,u8>
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct OwnerResponse {
    pub id: i32,
    pub name: String,
}

impl OwnerResponse {
    pub fn of(owner: Owner) -> OwnerResponse {
        OwnerResponse {
            id: owner.id,
            name: owner.name,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SignupResponse {
    pub id: i32,
    pub username: String,
}

impl SignupResponse {
    pub fn of(user: User) -> SignupResponse {
        SignupResponse {
            id: user.id,
            username: user.username,
        }
    }
}

#[derive(Deserialize, Clone, PartialEq, Debug)]
pub struct Pet {
    pub id: i32,
    pub name: String,
    pub owner_id: i32,
    pub animal_type: String,
    pub color: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PetRequest {
    pub name: String,
    pub animal_type: String,
    pub color: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PetResponse {
    pub id: i32,
    pub name: String,
    pub animal_type: String,
    pub color: Option<String>,
}

impl PetResponse {
    pub fn of(pet: Pet) -> PetResponse {
        PetResponse {
            id: pet.id,
            name: pet.name,
            animal_type: pet.animal_type,
            color: pet.color,
        }
    }
}
