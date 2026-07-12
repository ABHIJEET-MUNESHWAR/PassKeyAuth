//! HTTP/GraphQL application assembly and graceful shutdown.

use std::time::Duration;

use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse, GraphQLSubscription};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use metrics_exporter_prometheus::PrometheusHandle;
use passkeyauth_api::IdentitySchema;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

async fn graphql_handler(
    State(schema): State<IdentitySchema>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

async fn playground() -> impl IntoResponse {
    Html(playground_source(
        GraphQLPlaygroundConfig::new("/graphql").subscription_endpoint("/graphql/ws"),
    ))
}

async fn health_live() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "alive" }))
}

async fn health_ready() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ready" }))
}

/// Build the axum router: GraphQL (POST + playground + WS), health, metrics.
pub fn build_app(
    schema: IdentitySchema,
    metrics: PrometheusHandle,
    request_timeout: Duration,
) -> Router {
    let metrics_route = get(move || {
        let handle = metrics.clone();
        async move { handle.render() }
    });

    Router::new()
        .route("/graphql", get(playground).post(graphql_handler))
        .route_service("/graphql/ws", GraphQLSubscription::new(schema.clone()))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/metrics", metrics_route)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(schema)
}

/// Resolve when the process receives Ctrl-C or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::build_recorder;
    use passkeyauth_api::{build_schema, GraphQlContext};
    use passkeyauth_core::{EngineConfig, IdentityEngine};
    use passkeyauth_infra::{
        BroadcastBus, InMemoryIdentityStore, InMemoryIssuerStore, InMemoryTreeStore,
    };
    use std::sync::Arc;

    fn app() -> Router {
        let bus = Arc::new(BroadcastBus::new(16));
        let engine = IdentityEngine::new(
            Arc::new(InMemoryIdentityStore::new()),
            Arc::new(InMemoryIssuerStore::new()),
            Arc::new(InMemoryTreeStore::new()),
            bus.clone(),
            EngineConfig::default(),
        );
        let schema = build_schema(GraphQlContext {
            engine,
            events: bus,
        });
        build_app(schema, build_recorder(), Duration::from_secs(5))
    }

    #[tokio::test]
    async fn app_builds() {
        let _ = app();
    }
}
