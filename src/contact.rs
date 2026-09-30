use std::time::SystemTime;

use serde::{Deserialize, Serialize};

const MAX_SUBJECT_ID_LEN: usize = 64;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SubjectId(Vec<u8>);

impl SubjectId {
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, SubjectIdError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_SUBJECT_ID_LEN {
            return Err(SubjectIdError);
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Visitor {
    name: String,
    subject_id: SubjectId,
}

impl Visitor {
    pub fn new(name: impl Into<String>, subject_id: SubjectId) -> Self {
        Self {
            name: name.into(),
            subject_id,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn subject_id(&self) -> &SubjectId {
        &self.subject_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubjectIdError;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[repr(i32)]
#[serde(rename_all = "snake_case")]
pub enum ContactStatus {
    #[default]
    Pending = 0,
    Active = 2,
    Transfered = 3,
    Expired = 4,
    Blocked = 5,
}

impl TryFrom<i32> for ContactStatus {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Pending),
            2 => Ok(Self::Active),
            3 => Ok(Self::Transfered),
            4 => Ok(Self::Expired),
            5 => Ok(Self::Blocked),
            _ => Err(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Contact {
    name: String,
    alias: Option<String>,
    class: String,
    subject_id: SubjectId,
    description: String,
    status: ContactStatus,
    updated_at: SystemTime,
    created_at: SystemTime,
}

impl Contact {
    pub fn set_alias(&mut self, alias: Option<String>) {
        self.alias = alias;
        self.touch();
    }

    pub fn set_class(&mut self, class: String) {
        self.class = class;
        self.touch();
    }

    pub fn check_subject_id(&mut self, subject_id: &SubjectId) -> ContactStatus {
        if self.subject_id != *subject_id && self.status == ContactStatus::Active {
            self.status = ContactStatus::Transfered;
            self.touch();
        }
        self.status
    }

    pub fn set_description(&mut self, description: String) {
        self.description = description;
        self.touch();
    }

    pub fn block(&mut self) {
        self.status = ContactStatus::Blocked;
        self.touch();
    }

    pub fn status(&self) -> ContactStatus {
        self.status
    }

    fn touch(&mut self) {
        self.updated_at = SystemTime::now();
    }
}

#[cfg(test)]
mod tests {
    use super::{ContactStatus, SubjectId};

    #[test]
    fn contact_status_values_match_the_database_contract() {
        assert_eq!(ContactStatus::Pending as i32, 0);
        assert_eq!(ContactStatus::Active as i32, 2);
        assert_eq!(ContactStatus::Transfered as i32, 3);
        assert_eq!(ContactStatus::Expired as i32, 4);
        assert_eq!(ContactStatus::Blocked as i32, 5);
    }

    #[test]
    fn subject_id_accepts_a_dhttp_owner_hash() {
        let owner_hash = "0".repeat(64);

        assert_eq!(
            SubjectId::new(owner_hash.as_bytes()).unwrap().as_bytes(),
            owner_hash.as_bytes()
        );
    }

    #[test]
    fn subject_id_rejects_values_longer_than_a_dhttp_owner_hash() {
        assert!(SubjectId::new(vec![0; 65]).is_err());
    }
}
