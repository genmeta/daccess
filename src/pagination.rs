use sea_orm::Order;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::api::{ApiError, bad_request};

const DEFAULT_PAGE_SIZE: u64 = 20;
const MAX_PAGE_SIZE: u64 = 100;

#[derive(Clone, Copy, Deserialize)]
#[serde(default)]
pub(crate) struct Pagination {
    page: u64,
    page_size: u64,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
        }
    }
}

impl Pagination {
    pub(crate) fn offset_limit(self) -> Result<(i64, i64), ApiError> {
        if self.page == 0 {
            return Err(bad_request("page must be greater than zero"));
        }
        if !(1..=MAX_PAGE_SIZE).contains(&self.page_size) {
            return Err(bad_request(format!(
                "page_size must be between 1 and {MAX_PAGE_SIZE}"
            )));
        }
        let offset = self
            .page
            .checked_sub(1)
            .and_then(|page| page.checked_mul(self.page_size))
            .and_then(|offset| i64::try_from(offset).ok())
            .ok_or_else(|| bad_request("page is too large"))?;
        Ok((offset, self.page_size as i64))
    }
}

#[derive(Deserialize)]
#[serde(default)]
pub(crate) struct PageQuery<S> {
    page: u64,
    page_size: u64,
    pub(crate) sort: S,
    #[serde(deserialize_with = "deserialize_order")]
    pub(crate) order: Order,
}

impl<S: Default> Default for PageQuery<S> {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: DEFAULT_PAGE_SIZE,
            sort: S::default(),
            order: Order::Desc,
        }
    }
}

impl<S> PageQuery<S> {
    pub(crate) fn pagination(&self) -> Pagination {
        Pagination {
            page: self.page,
            page_size: self.page_size,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct Page<T> {
    items: T,
    total: u64,
    page: u64,
    page_size: u64,
}

impl<T> Page<T> {
    pub(crate) fn new(items: T, total: u64, pagination: Pagination) -> Self {
        Self {
            items,
            total,
            page: pagination.page,
            page_size: pagination.page_size,
        }
    }
}

fn deserialize_order<'de, D>(deserializer: D) -> Result<Order, D::Error>
where
    D: Deserializer<'de>,
{
    match String::deserialize(deserializer)?.as_str() {
        "asc" => Ok(Order::Asc),
        "desc" => Ok(Order::Desc),
        value => Err(D::Error::custom(format!(
            "unknown order {value:?}, expected asc or desc"
        ))),
    }
}

pub(crate) fn order_sql(order: &Order) -> &'static str {
    match order {
        Order::Asc => "ASC",
        Order::Desc => "DESC",
        _ => unreachable!("HTTP query only accepts ascending or descending order"),
    }
}

#[cfg(test)]
mod tests {
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
}
