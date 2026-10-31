//! Stream-service handle adapters. Forwarded payloads never cross the host ABI.
use crate::{
    Result, Value,
    callbacks::get_callbacks,
    quic,
    resources::{Output, Resource, get_resource, get_router},
    values::{dictionary, handle_field, object_value, session_fields, string_field},
};
use std::{collections::HashMap, sync::Arc};
use xconn_core::{
    async_::{
        rawsocket::BoxStream,
        services::stream_broker::{StreamBroker, forward},
    },
    wampproto::types::SessionDetails,
};

fn identity(fields: &HashMap<String, Value>, name: &str) -> Result<SessionDetails> {
    let fields = dictionary(fields.get(name).ok_or("authenticated identity is required")?)?;
    let id = i64::try_from(handle_field(&fields, "session_id")?).map_err(|_| "invalid session ID")?;
    let mut identity = SessionDetails::new(
        id,
        string_field(&fields, "realm")?,
        string_field(&fields, "authid")?,
        string_field(&fields, "authrole")?,
        false,
    );
    identity.auth_method = string_field(&fields, "authmethod").unwrap_or_default();
    identity.auth_extra = dictionary(fields.get("authextra").unwrap_or(&Value::Null))?;
    Ok(identity)
}

fn broker(fields: &HashMap<String, Value>) -> Result<StreamBroker> {
    match get_resource(handle_field(fields, "handle")?)?.as_ref() {
        Resource::StreamBroker(broker) => Ok(broker.clone()),
        _ => Err("expected stream broker".into()),
    }
}

pub(super) async fn dispatch(method: &str, fields: HashMap<String, Value>) -> Result<Output> {
    match method {
        "service_stream_configure" => {
            use xconn_core::async_::services::routing::StreamRouting;
            let router = get_router(handle_field(&fields, "handle")?)?;
            let callbacks = get_callbacks(handle_field(&fields, "callback")?)?;
            let destination_callbacks = callbacks.clone();
            let route_callbacks = callbacks.clone();
            let routing = StreamRouting::new(
                move |identity| match destination_callbacks.call(
                    "stream_destination",
                    Value::Dict(session_fields(&xconn_core::SessionDetails::from_protocol(identity))),
                ) {
                    Ok(Value::Str(key)) if !key.is_empty() => Some(key),
                    _ => None,
                },
                move |incoming| {
                    let callbacks = route_callbacks.clone();
                    async move {
                        let source = incoming.session.clone();
                        let fields = HashMap::from([(
                            "source".into(),
                            Value::Dict(session_fields(&xconn_core::SessionDetails::from_protocol(&source))),
                        )]);
                        let output = quic::stream_output(incoming.stream, fields);
                        let handle =
                            handle_field(&dictionary(&output.value).map_err(xconn_core::Error::new)?, "handle")
                                .map_err(xconn_core::Error::new)?;
                        let response = callbacks
                            .call("stream_route", output.value.clone())
                            .map_err(xconn_core::Error::new)?;
                        let response = dictionary(&response).map_err(xconn_core::Error::new)?;
                        let key = string_field(&response, "key").map_err(xconn_core::Error::new)?;
                        let prefix = match response.get("prefix") {
                            Some(Value::Bytes(bytes)) => bytes.0.clone(),
                            None | Some(Value::Null) => Vec::new(),
                            _ => return Err(xconn_core::Error::new("expected stream prefix bytes")),
                        };
                        let failure = match response.get("failure") {
                            Some(Value::Bytes(bytes)) => bytes.0.clone(),
                            None | Some(Value::Null) => Vec::new(),
                            _ => return Err(xconn_core::Error::new("expected stream failure bytes")),
                        };
                        let stream = quic::take_stream(handle).map_err(xconn_core::Error::new)?;
                        Ok(xconn_core::async_::quic::AuthenticatedStream {
                            stream,
                            session: source,
                        }
                        .route_to(key)
                        .with_prefix(prefix)
                        .with_failure(failure))
                    }
                },
                Arc::new(move |source, key, target| {
                    matches!(
                        callbacks.call(
                            "stream_authorize",
                            object_value([
                                (
                                    "source",
                                    Value::Dict(session_fields(&xconn_core::SessionDetails::from_protocol(source)))
                                ),
                                ("key", Value::Str(key.into())),
                                (
                                    "target",
                                    Value::Dict(session_fields(&xconn_core::SessionDetails::from_protocol(target)))
                                ),
                            ])
                        ),
                        Ok(Value::Bool(true))
                    )
                }),
            );
            router.route_streams(routing).map_err(|error| error.to_string())?;
            Ok(Output::plain(Value::Null))
        }
        "service_stream_new" => {
            let callbacks = get_callbacks(handle_field(&fields, "callback")?)?;
            let broker = StreamBroker::new(Arc::new(move |source, key, target| {
                matches!(
                    callbacks.call(
                        "stream_authorize",
                        object_value([
                            (
                                "source",
                                Value::Dict(session_fields(&xconn_core::SessionDetails::from_protocol(source)))
                            ),
                            ("key", Value::Str(key.into())),
                            (
                                "target",
                                Value::Dict(session_fields(&xconn_core::SessionDetails::from_protocol(target)))
                            ),
                        ])
                    ),
                    Ok(Value::Bool(true))
                )
            }));
            Ok(Output::resource(Resource::StreamBroker(broker), HashMap::new()))
        }
        "service_stream_register_quic" => {
            let broker = broker(&fields)?;
            let connection = quic::connection(handle_field(&fields, "connection")?)?;
            let registration = broker
                .register(
                    string_field(&fields, "key")?,
                    identity(&fields, "target")?,
                    Arc::new(move || {
                        let connection = connection.clone();
                        Box::pin(async move { Ok(Box::new(connection.open_raw().await?) as BoxStream) })
                    }),
                )
                .map_err(|error| error.to_string())?;
            Ok(Output::resource(
                Resource::StreamDestination(registration),
                HashMap::new(),
            ))
        }
        "service_stream_open" => {
            let stream = broker(&fields)?
                .open(&identity(&fields, "source")?, &string_field(&fields, "key")?)
                .await
                .map_err(|error| error.to_string())?;
            Ok(quic::stream_output(stream, HashMap::new()))
        }
        "service_stream_relay" => {
            let broker = broker(&fields)?;
            let source = identity(&fields, "source")?;
            let key = string_field(&fields, "key")?;
            let incoming = quic::take_stream(handle_field(&fields, "stream")?)?;
            let (sent, received) = broker
                .relay(&source, &key, incoming)
                .await
                .map_err(|error| error.to_string())?;
            Ok(Output::plain(object_value([
                ("sent", Value::UInt(sent)),
                ("received", Value::UInt(received)),
            ])))
        }
        "service_stream_forward" => {
            let incoming = handle_field(&fields, "incoming")?;
            let outgoing = handle_field(&fields, "outgoing")?;
            if incoming == outgoing {
                return Err("forwarding requires two different streams".into());
            }
            let incoming = quic::take_stream(incoming)?;
            let outgoing = quic::take_stream(outgoing)?;
            let (sent, received) = forward(incoming, outgoing).await.map_err(|error| error.to_string())?;
            Ok(Output::plain(object_value([
                ("sent", Value::UInt(sent)),
                ("received", Value::UInt(received)),
            ])))
        }
        _ => Err(format!("unknown stream service operation {method}")),
    }
}
