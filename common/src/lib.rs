use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone, PartialEq, Debug)]
pub struct Owner {
    pub id: i32,
    pub name: String,
}

#[derive(Deserialize, Clone, PartialEq, Debug)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub accumulator: String,
    pub pub_key: String,
    pub witnesses: String,
    pub params: String
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
    pub accumulator: String,
    pub pub_key: String,
    pub witnesses: String,
    pub params: String
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct SigninRequest {
    pub username: String,
    pub password: String,
}

// impl Serialize for SignupRequest {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let mut map = serializer.serialize_map(Some(self.params.len()))?;
//         for (k, v) in &self.params {
//             map.serialize_entry(&k.to_string(), &v)?;
//         }
//         map.end()
//     }
// }

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
