use shadowmesh_core::*;
use std::sync::Arc;

#[test]
fn test_speed_test_initialization() {
    let client = create_api_client("https://api.test.com".to_string()).unwrap();
    let speed_test = create_speed_test(client);
    // basic check
    assert!(Arc::strong_count(&speed_test) >= 1);
}

// In a real environment, we'd mock the server, but for now we'll just verify the logic
// can be called without immediate panics if the client is valid.
