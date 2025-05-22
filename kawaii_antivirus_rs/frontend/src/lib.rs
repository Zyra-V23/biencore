use yew::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;
use web_sys::{File, FormData, HtmlInputElement};
use reqwasm::http::Request;
use serde::Deserialize; // For deserializing the backend response

// --- State Definitions ---

#[derive(Clone, Debug, PartialEq, Deserialize)]
struct HashesInfo {
    md5: String,
    sha1: String,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
struct StaticAnalysisInfo {
    extracted_strings: Vec<String>,
    file_type_guess: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
struct FileAnalysisData { // Renamed from FileInfo to better match backend response
    filename: String,
    size: u64,
    message: String, // Overall message from backend
    hashes: HashesInfo,
    hash_match_malware: bool,
    static_analysis: StaticAnalysisInfo,
    claude_ai_interpretation: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
enum UploadState {
    Idle,
    Uploading,
    Success(FileAnalysisData), // Updated to use FileAnalysisData
    Error(String),
}

// --- Header Component (remains the same) ---
#[function_component(HeaderComponent)]
fn header_component() -> Html {
    html! {
        <header class="header">
            <h1>{ "Nyan Nyan Antivirus ✨" }</h1>
        </header>
    }
}

// --- Upload Section Component ---
#[derive(Properties, PartialEq)]
struct UploadSectionProps {
    on_file_select: Callback<Option<File>>,
    on_upload: Callback<()>,
    selected_file_name: Option<String>, // To display the name of the selected file
    upload_state: UploadState, // To disable button during upload
}

#[function_component(UploadSectionComponent)]
fn upload_section_component(props: &UploadSectionProps) -> Html {
    let on_change = {
        let on_file_select = props.on_file_select.clone();
        Callback::from(move |e: Event| {
            let input: HtmlInputElement = e.target_unchecked_into();
            if let Some(files) = input.files() {
                if files.length() > 0 {
                    on_file_select.emit(files.get(0));
                } else {
                    on_file_select.emit(None);
                }
            }
        })
    };

    let on_click_upload = {
        let on_upload = props.on_upload.clone();
        Callback::from(move |_| {
            on_upload.emit(());
        })
    };

    let is_uploading = matches!(props.upload_state, UploadState::Uploading);

    html! {
        <section class="upload-section">
            <h2>{ "Scan Your Files!" }</h2>
            <input type="file" onchange={on_change} disabled={is_uploading} />
            {
                if let Some(name) = &props.selected_file_name {
                    html!{ <p>{ "Selected file: " } { name }</p> }
                } else {
                    html!{ <p class="placeholder-text">{ "No file selected nya~" }</p> }
                }
            }
            <button onclick={on_click_upload} disabled={is_uploading || props.selected_file_name.is_none()}>
                { if is_uploading { "Uploading..." } else { "Upload Nya!" } }
            </button>
        </section>
    }
}

// --- Results Section Component ---
#[derive(Properties, PartialEq)]
struct ResultsSectionProps {
    upload_state: UploadState,
}

#[function_component(ResultsSectionComponent)]
fn results_section_component(props: &ResultsSectionProps) -> Html {
    html! {
        <section class="results-section">
            <h2>{ "Analysis Results" }</h2>
            {
                match &props.upload_state {
                    UploadState::Idle => html!{ <p class="placeholder-text">{ "Waiting for a file to scan, meow!" }</p> },
                    UploadState::Uploading => html!{
                        <>
                            <p>{ "Uploading and analyzing... please wait, purr..." }</p>
                            // Simple text loading, could be replaced with a CSS spinner or gif
                            // <div class="spinner"></div> // Placeholder for a spinner
                            <img src="/static/loading_cat.gif" alt="Loading..." width="50" /> // Kawaii loading indicator
                        </>
                    },
                    UploadState::Success(analysis_data) => html!{
                        <>
                            <h3 style="color: green;">{ análisis_data.message.clone() }</h3>
                            <div class="analysis-results">
                                <p><strong>{ "File Name: " }</strong>{ analysis_data.filename.clone() }</p>
                                <p><strong>{ "File Size: " }</strong>{ format!("{} bytes", analysis_data.size) }</p>
                                
                                <h4>{ "Hashes:" }</h4>
                                <ul>
                                    <li><strong>{ "MD5: " }</strong>{ analysis_data.hashes.md5.clone() }</li>
                                    <li><strong>{ "SHA1: " }</strong>{ analysis_data.hashes.sha1.clone() }</li>
                                    <li><strong>{ "SHA256: " }</strong>{ analysis_data.hashes.sha256.clone() }</li>
                                </ul>
                                
                                <p>
                                    <strong>{ "Malware Match: " }</strong>
                                    if analysis_data.hash_match_malware {
                                        <span style="color: red; font-weight: bold;">{ "Yes (Matched a known signature!)" }</span>
                                    } else {
                                        <span style="color: green;">{ "No" }</span>
                                    }
                                </p>
                                
                                <h4>{ "Static Analysis:" }</h4>
                                <p><strong>{ "File Type Guess: " }</strong>{ analysis_data.static_analysis.file_type_guess.clone() }</p>
                                <p><strong>{ "Extracted Strings (sample):" }</strong></p>
                                if analysis_data.static_analysis.extracted_strings.is_empty() {
                                    <p class="placeholder-text">{ "No printable strings found." }</p>
                                } else {
                                    <ul class="string-list">
                                        { for analysis_data.static_analysis.extracted_strings.iter().map(|s| html!{ <li>{ s }</li> }) }
                                    </ul>
                                }
                                
                                <h4>{ "AI Interpretation ✨:" }</h4>
                                if let Some(interpretation) = &analysis_data.claude_ai_interpretation {
                                    <p class="ai-interpretation">{ interpretation }</p>
                                } else {
                                    <p class="placeholder-text">{ "No AI interpretation available." }</p>
                                }
                            </div>
                        </>
                    },
                    UploadState::Error(error_message) => html!{
                        <p style="color: red;">{ format!("Error: {}", error_message) }</p>
                    },
                }
            }
        </section>
    }
}

// --- Footer Component (remains the same) ---
#[function_component(FooterComponent)]
fn footer_component() -> Html {
    html! {
        <footer class="footer">
            <p>{ "© 2024 Nyan Nyan Security. All rights reserved. Meow!" }</p>
        </footer>
    }
}

// --- Root App Component ---
#[function_component(App)]
fn app() -> Html {
    let selected_file_state = use_state(|| Option::<File>::None);
    let upload_state = use_state(|| UploadState::Idle);

    let on_file_select = {
        let selected_file_state = selected_file_state.clone();
        let upload_state = upload_state.clone();
        Callback::from(move |file: Option<File>| {
            selected_file_state.set(file);
            upload_state.set(UploadState::Idle); // Reset state if a new file is selected
        })
    };

    let on_upload = {
        let selected_file_state = selected_file_state.clone();
        let upload_state = upload_state.clone();
        Callback::from(move |_| {
            if let Some(file) = &*selected_file_state {
                let form_data = FormData::new().unwrap();
                form_data.append_with_blob("file", file).unwrap(); // "file" must match backend

                upload_state.set(UploadState::Uploading);
                let upload_state_clone = upload_state.clone();

                spawn_local(async move {
                    match Request::post("/api/upload")
                        .body(form_data)
                        .send()
                        .await
                    {
                        Ok(response) => {
                            if response.ok() {
                                match response.json::<FileAnalysisData>().await { // Expecting FileAnalysisData now
                                    Ok(analysis_result) => {
                                        upload_state_clone.set(UploadState::Success(analysis_result));
                                    }
                                    Err(e) => {
                                        upload_state_clone.set(UploadState::Error(format!("Failed to parse response: {}", e)));
                                    }
                                }
                            } else {
                                let error_body = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                                upload_state_clone.set(UploadState::Error(format!("Upload failed with status {}: {}", response.status(), error_body)));
                            }
                        }
                        Err(e) => {
                            upload_state_clone.set(UploadState::Error(format!("Network error: {}", e)));
                        }
                    }
                });
            } else {
                upload_state.set(UploadState::Error("No file selected to upload.".to_string()));
            }
        })
    };
    
    let selected_file_name = (*selected_file_state).as_ref().map(|f| f.name());

    html! {
        <div class="container">
            <HeaderComponent />
            <main>
                <UploadSectionComponent 
                    on_file_select={on_file_select} 
                    on_upload={on_upload}
                    selected_file_name={selected_file_name}
                    upload_state={(*upload_state).clone()}
                />
                <ResultsSectionComponent upload_state={(*upload_state).clone()} />
            </main>
            <FooterComponent />
        </div>
    }
}

// Entry point for the WASM module
#[wasm_bindgen(start)]
pub fn run_app() {
    yew::Renderer::<App>::new().render();
}
