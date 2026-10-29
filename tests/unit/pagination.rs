use super::*;

#[test]
fn defaults_to_the_first_page() {
    let pagination = Pagination::default();
    assert_eq!(pagination.page, 1);
    assert_eq!(pagination.page_size, 20);
    assert_eq!(pagination.offset_limit().unwrap(), (0, 20));
}

#[test]
fn rejects_invalid_ranges() {
    assert!(
        Pagination {
            page: 0,
            page_size: 20
        }
        .offset_limit()
        .is_err()
    );
    assert!(
        Pagination {
            page: 1,
            page_size: 0
        }
        .offset_limit()
        .is_err()
    );
    assert!(
        Pagination {
            page: 1,
            page_size: 101
        }
        .offset_limit()
        .is_err()
    );
    assert!(
        Pagination {
            page: u64::MAX,
            page_size: 100
        }
        .offset_limit()
        .is_err()
    );
}
