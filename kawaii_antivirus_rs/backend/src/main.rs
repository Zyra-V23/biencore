use actix_web::{get, web, App, HttpServer, Responder, HttpResponse, Error};
use serde::Serialize;
use std::path::PathBuf;
use actix_files as fs;
use actix_multipart::Multipart;
use futures_util::stream::StreamExt as _;
use std::io::Write;
use std::collections::{HashSet, BTreeSet};

use md5;
use sha1::{Sha1, Digest as Sha1Digest};
use sha2::{Sha256, Digest as Sha2Digest};
use hex;
use lazy_static::lazy_static;
use infer;

// --- Static Data ---
lazy_static! {
    static ref DUMMY_MALWARE_HASHES_SHA256: HashSet<String> = {
        let mut m = HashSet::new();
        // SHA256 of an empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        m.insert("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string());
        // Example: SHA256 of a file containing "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" (EICAR test string)
        m.insert("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string());
        m.insert("your_test_malware_hash_here_sha256".to_string()); // Placeholder
        m
    };
}

// --- Module Declaration ---
mod claude_ai;
#[cfg(test)]
mod tests; // Include the unit tests module

// --- Imports ---
use crate::claude_ai::get_claude_interpretation; // Import the Claude AI function


// --- Response Structures ---
#[derive(Serialize)]
struct Hashes {
    md5: String,
    sha1: String,
    sha256: String,
}

#[derive(Serialize)]
struct StaticAnalysisResults {
    extracted_strings: Vec<String>, // Using Vec for potentially ordered/limited strings
    file_type_guess: String,
}

#[derive(Serialize, Clone)] // Added Clone here as it's passed to Claude
struct FileAnalysisResponse {
    message: String,
    filename: String,
    size: u64,
    hashes: Hashes,
    hash_match_malware: bool,
    static_analysis: StaticAnalysisResults,
    // New field for Claude AI interpretation
    claude_ai_interpretation: Option<String>, // Option to handle potential errors
}

#[derive(Serialize)]
struct HelloResponse {
    message: String,
}

#[get("/api/hello")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().json(HelloResponse {
        message: "Hello from Actix!".to_string(),
    })
}

// --- Helper Functions ---
fn extract_printable_ascii_strings(data: &[u8], min_len: usize, max_strings: usize) -> Vec<String> {
    let mut strings = BTreeSet::new(); // Use BTreeSet to get unique strings sorted alphabetically
    let mut current_string = Vec::new();

    for &byte in data {
        if byte >= 32 && byte <= 126 { // Printable ASCII range
            current_string.push(byte);
        } else {
            if current_string.len() >= min_len {
                if let Ok(s) = String::from_utf8(current_string.clone()) {
                    strings.insert(s);
                    if strings.len() >= max_strings {
                        break;
                    }
                }
            }
            current_string.clear();
        }
    }
    if current_string.len() >= min_len && strings.len() < max_strings {
        if let Ok(s) = String::from_utf8(current_string) {
            strings.insert(s);
        }
    }
    strings.into_iter().collect() // Convert BTreeSet to Vec
}


// --- Route Handlers ---

// Handler for file uploads (Updated)
async fn upload_file(mut payload: Multipart) -> Result<HttpResponse, Error> {
    let mut file_data = Vec::new();
    let mut original_filename = String::new();
    
    // Iterate over multipart items
    while let Some(item) = payload.next().await {
        let mut field = item?;
        let content_disposition = field.content_disposition();
        
        if let Some(name) = content_disposition.get_name() {
            if name == "file" { // Ensure this matches the FormData key from the frontend
                if let Some(f_name) = content_disposition.get_filename() {
                    original_filename = sanitize_filename::sanitize(f_name);
                }

                while let Some(chunk) = field.next().await {
                    let data = chunk?;
                    file_data.extend_from_slice(&data);
                }
                // Assuming one file upload per request for simplicity
                if !file_data.is_empty() {
                     break;
                }
            }
        }
    }

    if original_filename.is_empty() || file_data.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "No file uploaded or file is empty.",
            "message": "Please select a file to upload."
        })));
    }

    let size = file_data.len() as u64;

    // 1. Calculate Hashes
    let md5_hash = hex::encode(md5::compute(&file_data).0);
    
    let mut sha1_hasher = Sha1::new();
    sha1_hasher.update(&file_data);
    let sha1_hash = hex::encode(sha1_hasher.finalize());

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(&file_data);
    let sha256_hash = hex::encode(sha256_hasher.finalize());

    // 2. Check against dummy malware hashes
    let is_malware = DUMMY_MALWARE_HASHES_SHA256.contains(&sha256_hash);

    // 3. Basic Static Analysis
    // String Extraction
    let extracted_strings = extract_printable_ascii_strings(&file_data, 4, 20);

    // File Type Guessing (using infer)
    let file_type_guess = match infer::get(&file_data) {
        Some(kind) => format!("{} (.{})", kind.mime_type(), kind.extension()),
        None => "unknown".to_string(),
    };

    let preliminary_analysis = FileAnalysisResponse {
        message: "File analyzed successfully!".to_string(), // Temp message, might be updated
        filename: original_filename.clone(), // Clone as it's used again for Claude
        size,
        hashes: Hashes {
            md5: md5_hash,
            sha1: sha1_hash,
            sha256: sha256_hash,
        },
        hash_match_malware: is_malware,
        static_analysis: StaticAnalysisResults {
            extracted_strings,
            file_type_guess,
        },
        claude_ai_interpretation: None, // Initialize as None
    };

    // 4. Call Claude AI for interpretation
    // We clone preliminary_analysis here if get_claude_interpretation needs to own it,
    // or pass a reference if it can borrow. The current claude_ai.rs takes a reference.
    let claude_result = get_claude_interpretation(&preliminary_analysis).await;
    
    let final_response = FileAnalysisResponse {
        claude_ai_interpretation: Some(match claude_result {
            Ok(interpretation) => interpretation,
            Err(e) => format!("Claude AI Error: {}", e),
        }),
        ..preliminary_analysis // Use struct update syntax to copy other fields
    };

    Ok(HttpResponse::Ok().json(final_response))
}

async fn serve_index() -> impl Responder {
    // This path assumes the `dist` directory is one level up from `backend`
    // and then inside `frontend`.
    // So, if backend is at `kawaii_antivirus_rs/backend`,
    // frontend/dist is at `kawaii_antivirus_rs/frontend/dist`
    let path: PathBuf = PathBuf::from("../frontend/dist/index.html");
    if path.exists() {
        HttpResponse::Ok().content_type("text/html").body(std::fs::read_to_string(path).unwrap())
    } else {
        HttpResponse::NotFound().body("index.html not found. Make sure the frontend is built.")
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let port = 8080;
    println!("🦀 Backend server starting on http://localhost:{} 🦀", port);

    // Create uploads directory if it doesn't exist (optional, if saving files)
    // std::fs::create_dir_all("./uploads").unwrap();


    HttpServer::new(|| {
        App::new()
            .service(hello)
            .route("/", web::get().to(serve_index)) // Serve Yew's index.html at root
            // Serve other static files from Yew.
            .service(fs::Files::new("/static", "../frontend/dist").show_files_listing())
            // Register the new file upload route
            .route("/api/upload", web::post().to(upload_file))
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}

#[cfg(test)]
mod integration_tests {
    use super::*; // Make items from parent module (main) accessible
    use actix_web::{test, web, App, http::{StatusCode, header::CONTENT_TYPE}};
    use actix_http::body::MessageBody;
    use bytes::Bytes;
    use serde_json::json;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    // Helper to create a multipart payload for file upload
    fn create_test_payload(file_content: &[u8], filename: &str) -> actix_multipart::Multipart {
        let mut payload = actix_multipart::test::create_ einfache_payload(); // "einfache" is German for simple, seems to be the test function name
        payload.add_field(
            "file", // This must match the name expected by the handler
            actix_multipart::Field::new(
                "file", // Field name
                "application/octet-stream", // Content type of the field data
                Bytes::from(file_content.to_vec()), // Field data
            )
            .with_filename(filename), // Sets the filename for the field
        );
        payload
    }
    
    // Helper to create an empty payload
    fn create_empty_test_payload() -> actix_multipart::Multipart {
        actix_multipart::test::create_simple_payload() // No fields added
    }


    #[actix_rt::test]
    async fn test_hello_endpoint() {
        let app = App::new().service(hello); // Only testing the hello service
        let mut app = test::init_service(app).await;

        let req = test::TestRequest::get().uri("/api/hello").to_request();
        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().try_into_bytes().unwrap();
        let expected_json = json!({"message": "Hello from Actix!"});
        let actual_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        
        assert_eq!(actual_json, expected_json);
    }

    #[actix_rt::test]
    async fn test_upload_valid_file() {
        // Set up the environment variable for Claude AI mocking
        std::env::set_var("CLAUDE_API_KEY", "TEST_API_KEY_VALID");

        // The app service for upload_file. Note: upload_file is not a service itself but a handler.
        // We need to register it with a route.
        let app_service = App::new()
            .route("/api/upload", web::post().to(upload_file)); // Correctly register the handler
        
        let mut app = test::init_service(app_service).await;
        
        let file_content = b"This is a test file content for Kawaii Antivirus.";
        let filename = "kawaii_test_file.txt";
        let payload = create_test_payload(file_content, filename);

        let req = test::TestRequest::post()
            .uri("/api/upload")
            .set_payload(payload) // Set the multipart payload
            .to_request();
        
        let resp = test::call_service(&mut app, req).await;
        
        assert_eq!(resp.status(), StatusCode::OK, "Expected 200 OK for valid file upload");

        let body = resp.into_body().try_into_bytes().unwrap();
        let analysis_resp: FileAnalysisResponse = serde_json::from_slice(&body).expect("Failed to deserialize response");

        assert_eq!(analysis_resp.filename, filename);
        assert_eq!(analysis_resp.size, file_content.len() as u64);
        assert!(!analysis_resp.hashes.md5.is_empty());
        assert!(!analysis_resp.hashes.sha1.is_empty());
        assert!(!analysis_resp.hashes.sha256.is_empty());
        assert!(analysis_resp.static_analysis.file_type_guess.contains("text/plain")); // infer might guess this for simple text
        assert!(analysis_resp.claude_ai_interpretation.is_some());
        assert!(analysis_resp.claude_ai_interpretation.unwrap().contains("Mocked Claude AI Interpretation"));

        std::env::remove_var("CLAUDE_API_KEY"); // Clean up env var
    }

    #[actix_rt::test]
    async fn test_upload_no_file() {
        let app_service = App::new().route("/api/upload", web::post().to(upload_file));
        let mut app = test::init_service(app_service).await;
        
        // Create a multipart payload that does not contain a field named "file"
        // or an empty payload.
        let payload = create_empty_test_payload(); // This creates a payload with no fields.

        let req = test::TestRequest::post()
            .uri("/api/upload")
            .set_payload(payload)
            .to_request();
            
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "Expected 400 Bad Request for no file");
    }

    #[actix_rt::test]
    async fn test_upload_empty_file_content() {
        // This test is similar to 'no file' if the file content is empty,
        // as our handler checks `file_data.is_empty()`.
        let app_service = App::new().route("/api/upload", web::post().to(upload_file));
        let mut app = test::init_service(app_service).await;
        
        let file_content = b""; // Empty content
        let filename = "empty_file.txt";
        let payload = create_test_payload(file_content, filename);

        let req = test::TestRequest::post()
            .uri("/api/upload")
            .set_payload(payload)
            .to_request();
            
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "Expected 400 Bad Request for empty file content");
    }

    // --- Static File Serving Tests ---
    // Note: These tests assume that the frontend has been built and `dist` exists.
    // For a CI environment, you might need a build step for the frontend first.
    // Here, we'll mock the file existence or ensure `../frontend/dist` is accessible relative to where tests run.
    // For simplicity, we'll assume the files exist. If not, these tests would fail.

    // Helper to set up the full app for static file tests
    fn setup_full_app() -> App<impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >> {
        App::new()
            .service(hello) // Assuming hello is defined in the outer scope (super::*)
            .route("/", web::get().to(serve_index))
            .service(actix_files::Files::new("/static", "../frontend/dist").show_files_listing())
            .route("/api/upload", web::post().to(upload_file))
    }
    
    // We need to create dummy files for these tests to pass reliably without a real frontend build.
    fn create_dummy_dist_files() -> std::io::Result<()> {
        let dist_path = Path::new("../frontend/dist");
        if !dist_path.exists() {
            std::fs::create_dir_all(dist_path)?;
        }
        let index_path = dist_path.join("index.html");
        let style_path = dist_path.join("style.css");

        if !index_path.exists() {
            let mut file = File::create(index_path)?;
            file.write_all(b"<html><head><title>Dummy</title></head><body>Dummy Index</body></html>")?;
        }
        if !style_path.exists() {
            let mut file = File::create(style_path)?;
            file.write_all(b"/* Dummy CSS */ body { color: red; }")?;
        }
        Ok(())
    }


    #[actix_rt::test]
    async fn test_serve_index_html() {
        assert!(create_dummy_dist_files().is_ok(), "Failed to create dummy dist files for test");

        let app = setup_full_app();
        let mut app = test::init_service(app).await;

        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
        assert_eq!(content_type, "text/html");
    }

    #[actix_rt::test]
    async fn test_serve_static_style_css() {
        assert!(create_dummy_dist_files().is_ok(), "Failed to create dummy dist files for test");
        
        let app = setup_full_app();
        let mut app = test::init_service(app).await;

        let req = test::TestRequest::get().uri("/static/style.css").to_request();
        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
        assert_eq!(content_type, "text/css"); // infer might guess this for .css
    }
}
