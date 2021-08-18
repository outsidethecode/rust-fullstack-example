use chrono::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct Owner {
    pub id: i32,
    pub name: String,
}

#[derive(Deserialize)]
pub struct OwnerRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct OwnerUpdateRequest {
    pub name: String,
}

#[derive(Serialize)]
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

#[derive(Deserialize)]
pub struct Pet {
    pub id: i32,
    pub name: String,
    pub owner_id: i32,
    pub animal_type: String,
    pub birthday: Option<DateTime<Utc>>,
    pub color: Option<String>,
}

#[derive(Deserialize)]
pub struct PetRequest {
    pub name: String,
    pub animal_type: String,
    pub birthday: Option<DateTime<Utc>>,
    pub color: Option<String>,
}

#[derive(Deserialize)]
pub struct PetUpdateRequest {
    pub name: String,
    pub animal_type: String,
    pub birthday: Option<DateTime<Utc>>,
    pub color: Option<String>,
}

#[derive(Serialize)]
pub struct PetResponse {
    pub id: i32,
    pub name: String,
    pub animal_type: String,
    pub birthday: Option<DateTime<Utc>>,
    pub color: Option<String>,
}

impl PetResponse {
    pub fn of(pet: Pet) -> PetResponse {
        PetResponse {
            id: pet.id,
            name: pet.name,
            animal_type: pet.animal_type,
            birthday: pet.birthday,
            color: pet.color,
        }
    }
}