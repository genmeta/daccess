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
