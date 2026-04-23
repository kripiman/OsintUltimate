use rust_embed::RustEmbed;
use axum::response::IntoResponse;

#[derive(RustEmbed)]
#[folder = "src/core/web/assets/"]
pub struct Assets;

pub async fn serve_asset(axum::extract::Path(path): axum::extract::Path<String>) -> impl IntoResponse {
    let asset = Assets::get(&path).or_else(|| Assets::get("index.html"));

    match asset {
        Some(content) => {
            let mime = mime_guess::from_path(&path).first_or_octet_stream();
            (
                [("Content-Type", mime.as_ref())],
                content.data.to_vec(),
            ).into_response()
        }
        None => (axum::http::StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn serve_index() -> impl IntoResponse {
    serve_asset(axum::extract::Path("index.html".to_string())).await
}

pub async fn serve_login() -> impl IntoResponse {
    serve_asset(axum::extract::Path("login.html".to_string())).await
}
