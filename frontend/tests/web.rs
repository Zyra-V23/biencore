use wasm_bindgen_test::*;
use kawaii_antivirus_rs_frontend::App; // Assuming crate name is kawaii_antivirus_rs_frontend based on workspace structure

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn app_renders_without_panic() {
    // This test primarily ensures that the App component and its children
    // can be initialized and rendered without causing a panic.
    // It doesn't check for specific DOM content, but it's a good first step
    // to catch basic rendering issues or unhandled errors during component setup.
    
    // Create a dummy element to mount the app into, if necessary.
    // Yew's renderer by default might try to attach to the document body.
    // For isolated testing, sometimes a specific root element is preferred.
    // However, for a simple "does it render" test, letting it attach to body is fine.
    
    yew::Renderer::<App>::new().render();
    
    // If the above line executes without panicking, the test is considered passed.
    assert!(true, "App component rendered without panic.");
}

// Optional: A test to ensure the document body is not empty after render.
// This is a slightly more involved test.
#[wasm_bindgen_test]
fn document_body_has_content_after_app_render() {
    // Ensure the document is clean or set up a specific test div
    let document = web_sys::window().unwrap().document().unwrap();
    let body = document.body().unwrap();
    
    // Clear body for a cleaner test, or use a dedicated empty div
    // body.set_inner_html(""); // Be cautious with this in a shared test environment

    yew::Renderer::<App>::new().render(); // Renders into the body or a default root

    // Check if the body (or a specific app div) has child elements
    // This is a very basic check. A more robust test would look for specific elements.
    assert!(body.children().length() > 0, "Document body should have child elements after app render.");

    // Example: Check for the main container if your App always renders it
    let container = document.query_selector(".container");
    match container {
        Ok(Some(_element)) => { /* Found .container */ assert!(true); },
        Ok(None) => panic!("App did not render the .container div"),
        Err(e) => panic!("Error querying for .container: {:?}", e),
    }
}
