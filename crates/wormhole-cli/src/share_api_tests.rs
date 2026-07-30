use axum::{http::StatusCode, response::IntoResponse as _};

use super::select_unique_priority;

#[test]
fn ambiguous_name_targets_are_rejected_and_stronger_identity_wins() {
    let error = select_unique_priority(&[2, 2]).expect_err("ambiguous service name");
    assert_eq!(error.into_response().status(), StatusCode::CONFLICT);
    assert_eq!(select_unique_priority(&[2, 1]).expect("project identity"), 1);
    assert_eq!(select_unique_priority(&[2, 1, 0]).expect("endpoint UUID"), 2);
}
