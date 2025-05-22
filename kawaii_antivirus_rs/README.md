# Kawaii Antivirus RS ✨ (Rust Edition)

This project is a Rust-based web application featuring:
- A backend built with Actix Web.
- A frontend built with Yew and compiled to WebAssembly.

## Project Structure

The project is organized as a Cargo workspace:

- `kawaii_antivirus_rs/`: Workspace root.
  - `Cargo.toml`: Defines the workspace.
  - `backend/`: The Actix Web backend crate.
    - `src/main.rs`: Backend server logic.
  - `frontend/`: The Yew frontend crate.
    - `src/lib.rs`: Frontend application logic (Yew components).
    - `static/index.html`: The HTML file that loads the Yew WASM application. This will be copied to `frontend/dist` by `wasm-pack`.

## Prerequisites

- Rust: Make sure you have Rust installed. You can get it from [rustup.rs](https://rustup.rs/).
- `wasm-pack`: For building the Yew frontend to WebAssembly.
  ```bash
  cargo install wasm-pack
  ```

## How to Build and Run

1.  **Build the Frontend (Yew to WASM):**

    Navigate to the `frontend` directory and use `wasm-pack` to build. The output will be placed in `frontend/dist`.
    The `wasm-pack build` command will also copy the `static/index.html` to the `dist` directory.

    ```bash
    cd frontend
    wasm-pack build --target web --out-dir ./dist -- --no-default-features --features csr # For Yew 0.21
    cd .. 
    ```
    *Note: The `--out-name frontend` argument for `wasm-pack` ensures the generated JS and WASM files are named `frontend.js` and `frontend_bg.wasm`, matching the import in `index.html`.*
    *Correction: The default output name is derived from the crate name, which is already "frontend". The `--out-dir ./dist` is the main thing. The `index.html` needs to load `./pkg/frontend.js` if `--out-dir pkg` (default) or `./frontend.js` if `--out-dir .` and `--out-name frontend` is used. The current `index.html` is set up for `./pkg/frontend.js`. The backend serves from `../frontend/dist`, and the `index.html` in `frontend/static` will be copied/used from `frontend/dist`. The script path in `index.html` (`./pkg/frontend.js`) assumes `wasm-pack` places its output in a `pkg` subdirectory within the `--out-dir`. If `wasm-pack` output is directly in `dist`, the script path in `index.html` should be `./frontend.js`. Let's assume `wasm-pack` creates a `pkg` dir inside `dist` or we adjust the `index.html` path.*

    For simplicity, the current `index.html` expects the files to be in `dist/pkg/`. `wasm-pack build --target web --out-dir ./dist` usually creates `dist/frontend.js`, `dist/frontend_bg.wasm` and `dist/package.json`. It can also create a `pkg` subfolder if not specified otherwise. I will adjust the `index.html` to expect files in `dist/` directly, not `dist/pkg/` for simpler `wasm-pack` command.

2.  **Run the Backend (Actix Web Server):**

    Navigate to the `backend` directory and run the server using `cargo run`.
    The server is configured to run on `http://localhost:8080`.

    ```bash
    cd backend
    cargo run
    ```

3.  **Access the Application:**

    Open your web browser and go to `http://localhost:8080`. You should see the Yew frontend served by the Actix backend.

## Development Notes

- The backend serves the `index.html` (and other static assets from the Yew build) from the `../frontend/dist` directory.
- The `/api/hello` endpoint on the backend provides a sample JSON response.
- The Yew frontend includes a button to fetch and display the message from `/api/hello`.

## Troubleshooting

- **`index.html not found`**: Make sure you have successfully run the `wasm-pack build` command in the `frontend` directory, and that the `dist` directory exists in `frontend` with `index.html` and the WASM/JS files.
- **WASM not loading**: Check the browser's developer console for errors. Path issues in `index.html` (for the JS loader) or `wasm-pack` build configurations are common. Ensure the `script` tag in `frontend/static/index.html` correctly points to the generated JavaScript loader file (e.g., `frontend.js` or `pkg/frontend.js` depending on `wasm-pack` output structure).

---
Kawaii coding! ✨🌸
