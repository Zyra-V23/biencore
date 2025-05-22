// backend/src/tests.rs

#[cfg(test)]
mod unit_tests {
    use crate::{FileAnalysisResponse, Hashes, StaticAnalysisResults}; // Import necessary structs from main
    use crate::claude_ai::{format_claude_prompt, get_claude_interpretation}; // Import from claude_ai module
    use crate::extract_printable_ascii_strings; // Import from main
    use std::collections::HashSet;
    use std::env;
    use hex; // For converting byte arrays to hex strings in tests

    // --- Hashing Tests ---
    #[test]
    fn test_md5_hashing() {
        let data = b"hello world";
        let expected_md5 = "5eb63bbbe01eeed093cb22bb8f5acdc3"; // Known MD5 for "hello world"
        let actual_md5 = hex::encode(md5::compute(data).0);
        assert_eq!(actual_md5, expected_md5);
    }

    #[test]
    fn test_sha1_hashing() {
        use sha1::{Sha1, Digest};
        let data = b"hello world";
        let expected_sha1 = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"; // Known SHA1 for "hello world"
        let mut hasher = Sha1::new();
        hasher.update(data);
        let actual_sha1 = hex::encode(hasher.finalize());
        assert_eq!(actual_sha1, expected_sha1);
    }

    #[test]
    fn test_sha256_hashing() {
        use sha2::{Sha256, Digest};
        let data = b"hello world";
        let expected_sha256 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"; // Known SHA256 for "hello world"
        let mut hasher = Sha256::new();
        hasher.update(data);
        let actual_sha256 = hex::encode(hasher.finalize());
        assert_eq!(actual_sha256, expected_sha256);
    }

    // --- String Extraction Tests ---
    #[test]
    fn test_string_extraction_basic() {
        let data = b"Hello\0World\x0112345\x02ニャン\x03test"; // Includes non-ASCII and control chars
        let strings = extract_printable_ascii_strings(data, 4, 10);
        assert_eq!(strings, vec!["12345", "Hello", "World", "test"]); // Sorted due to BTreeSet
    }

    #[test]
    fn test_string_extraction_min_length() {
        let data = b"abc\0defgh\0ijklmno";
        let strings = extract_printable_ascii_strings(data, 5, 10);
        assert_eq!(strings, vec!["defgh", "ijklmno"]);
    }

    #[test]
    fn test_string_extraction_max_strings() {
        let data = b"str1\0str2\0str3\0str4";
        let strings = extract_printable_ascii_strings(data, 3, 2); // Max 2 strings
        assert_eq!(strings.len(), 2);
        // Can't guarantee which 2 due to BTreeSet internal ordering on insert then collect
        // but we can check if they are from the original set
        let expected_set: HashSet<String> = vec!["str1".to_string(), "str2".to_string(), "str3".to_string(), "str4".to_string()].into_iter().collect();
        assert!(expected_set.contains(&strings[0]));
        assert!(expected_set.contains(&strings[1]));
    }

    #[test]
    fn test_string_extraction_no_strings() {
        let data = b"\x01\x02\x03\x04\x05";
        let strings = extract_printable_ascii_strings(data, 4, 10);
        assert!(strings.is_empty());
    }

    // --- File Type Guessing (Infer) ---
    // Basic test to ensure infer doesn't panic and gives 'unknown' for random/empty data.
    #[test]
    fn test_infer_with_random_data() {
        let data = b"\xDE\xAD\xBE\xEF\xCA\xFE\xBA\xBE";
        let kind = infer::get(data);
        // We don't assert a specific type, just that it handles it (might be None or some default)
        // For truly random data, it's likely None.
        // For this specific byte sequence, it might guess something or be None.
        // The key is it doesn't panic.
        if let Some(k) = kind {
            println!("Infer guessed: {} for random data", k.mime_type());
        } else {
            println!("Infer returned None for random data");
        }
        // A more robust test would use known magic bytes for a specific file type.
        // e.g., for PNG: b"\x89PNG\r\n\x1a\n"
        let png_data = b"\x89PNG\r\n\x1a\n";
        let png_kind = infer::get(png_data);
        assert!(png_kind.is_some());
        assert_eq!(png_kind.unwrap().mime_type(), "image/png");
    }
    
    #[test]
    fn test_infer_with_empty_data() {
        let data = b"";
        let kind = infer::get(data);
        assert!(kind.is_none()); // Infer should return None for empty data
    }


    // --- Claude AI Prompt Formatting Tests ---
    #[test]
    fn test_claude_prompt_formatting() {
        let analysis_data = FileAnalysisResponse {
            message: "Test message".to_string(),
            filename: "test_file.exe".to_string(),
            size: 1024,
            hashes: Hashes {
                md5: "md5hash".to_string(),
                sha1: "sha1hash".to_string(),
                sha256: "sha256hash".to_string(),
            },
            hash_match_malware: true,
            static_analysis: StaticAnalysisResults {
                extracted_strings: vec!["string1".to_string(), "string2".to_string()],
                file_type_guess: "application/octet-stream (.bin)".to_string(),
            },
            claude_ai_interpretation: None, // Not used in prompt formatting
        };
        let prompt = format_claude_prompt(&analysis_data);
        assert!(prompt.contains("File Name: test_file.exe"));
        assert!(prompt.contains("File Size: 1024 bytes"));
        assert!(prompt.contains("File Type Guess: application/octet-stream (.bin)"));
        assert!(prompt.contains("MD5: md5hash"));
        assert!(prompt.contains("SHA1: sha1hash"));
        assert!(prompt.contains("SHA256: sha256hash"));
        assert!(prompt.contains("Matched known malware hash: true"));
        assert!(prompt.contains("Extracted Strings (sample): string1, string2"));
    }

    // --- Mocked Claude Client Tests ---
    #[actix_rt::test] // Use actix_rt::test for async tests
    async fn test_get_claude_interpretation_mocked_valid_key() {
        env::set_var("CLAUDE_API_KEY", "TEST_API_KEY_VALID");
        let analysis_data = sample_file_analysis_response(); // Helper to create dummy data
        let result = get_claude_interpretation(&analysis_data).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Mocked Claude AI Interpretation: This file shows characteristics potentially indicative of unwanted software due to specific string patterns and hash match. Potential risk: Medium.".to_string());
        env::remove_var("CLAUDE_API_KEY");
    }

    #[actix_rt::test]
    async fn test_get_claude_interpretation_mocked_error_key() {
        env::set_var("CLAUDE_API_KEY", "TEST_API_KEY_ERROR");
        let analysis_data = sample_file_analysis_response();
        let result = get_claude_interpretation(&analysis_data).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Mocked Claude AI Error: Unable to connect to service. Simulated API failure.".to_string());
        env::remove_var("CLAUDE_API_KEY");
    }

    #[actix_rt::test]
    async fn test_get_claude_interpretation_mocked_default_key() {
        env::remove_var("CLAUDE_API_KEY"); // Ensure no specific test key is set
        let analysis_data = sample_file_analysis_response();
        let result = get_claude_interpretation(&analysis_data).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Mocked Claude AI Interpretation: Default response. File data processed in mock mode.".to_string());
    }

    // Helper function for Claude tests
    fn sample_file_analysis_response() -> FileAnalysisResponse {
        FileAnalysisResponse {
            message: "".to_string(),
            filename: "".to_string(),
            size: 0,
            hashes: Hashes { md5: "".to_string(), sha1: "".to_string(), sha256: "".to_string() },
            hash_match_malware: false,
            static_analysis: StaticAnalysisResults { extracted_strings: vec![], file_type_guess: "".to_string() },
            claude_ai_interpretation: None,
        }
    }
}

// Note: Integration tests for Actix handlers will be added directly in main.rs or a separate integration test file.
// For now, this file `tests.rs` will be for unit tests.
// The build system needs to know about this file.
// If this file is `backend/src/tests.rs`, then in `backend/src/main.rs` add `mod tests;`
// Or, if it's `backend/tests/unit_tests.rs`, Cargo will pick it up automatically if `main.rs` is a library or has a lib.rs.
// Given `main.rs` is a binary, it's often simpler to put `#[cfg(test)] mod tests { ... }` directly in `main.rs` or use `mod tests;`
// For this exercise, creating `backend/src/tests.rs` and adding `mod tests;` to `main.rs` is a clean approach.
