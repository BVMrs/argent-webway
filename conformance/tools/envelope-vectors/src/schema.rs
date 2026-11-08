//! The slice of `a2a.proto` (tag v1.0.1, package lf.a2a.v1) the vectors need: signer-form
//! checking (spec §4.3) and body locations (spec Appendix B).

use crate::encoding::{is_canonical_b64std, parse_ts};
use crate::json::Value;

#[derive(Clone, Copy)]
pub enum Kind {
    Str,
    Bytes,
    Bool,
    Int32,
    Enum(&'static [&'static str]),
    Msg(&'static str),
    /// google.protobuf.Struct / Value: free JSON.
    Free,
    Timestamp,
}

#[derive(Clone, Copy)]
pub struct Field {
    pub json: &'static str,
    pub proto: &'static str,
    pub kind: Kind,
    pub repeated: bool,
    /// Explicit presence: `optional`, oneof member, or message-typed.
    pub presence: bool,
}

const fn f(json: &'static str, proto: &'static str, kind: Kind) -> Field {
    let presence = matches!(kind, Kind::Msg(_) | Kind::Free | Kind::Timestamp);
    Field { json, proto, kind, repeated: false, presence }
}
const fn rep(json: &'static str, proto: &'static str, kind: Kind) -> Field {
    Field { json, proto, kind, repeated: true, presence: false }
}
const fn opt(json: &'static str, proto: &'static str, kind: Kind) -> Field {
    Field { json, proto, kind, repeated: false, presence: true }
}

const ROLE: &[&str] = &["ROLE_UNSPECIFIED", "ROLE_USER", "ROLE_AGENT"];
const TASK_STATE: &[&str] = &[
    "TASK_STATE_UNSPECIFIED",
    "TASK_STATE_SUBMITTED",
    "TASK_STATE_WORKING",
    "TASK_STATE_COMPLETED",
    "TASK_STATE_FAILED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_INPUT_REQUIRED",
    "TASK_STATE_REJECTED",
    "TASK_STATE_AUTH_REQUIRED",
];

pub fn message_fields(name: &str) -> &'static [Field] {
    use Kind::*;
    match name {
        "SendMessageRequest" => const { &[
            f("tenant", "tenant", Str),
            f("message", "message", Msg("Message")),
            f("configuration", "configuration", Msg("SendMessageConfiguration")),
            f("metadata", "metadata", Free),
        ] },
        "SendMessageConfiguration" => const { &[
            rep("acceptedOutputModes", "accepted_output_modes", Str),
            f("taskPushNotificationConfig", "task_push_notification_config", Free),
            opt("historyLength", "history_length", Int32),
            f("returnImmediately", "return_immediately", Bool),
        ] },
        "Message" => const { &[
            f("messageId", "message_id", Str),
            f("contextId", "context_id", Str),
            f("taskId", "task_id", Str),
            f("role", "role", Enum(ROLE)),
            rep("parts", "parts", Msg("Part")),
            f("metadata", "metadata", Free),
            rep("extensions", "extensions", Str),
            rep("referenceTaskIds", "reference_task_ids", Str),
        ] },
        "Part" => const { &[
            opt("text", "text", Str),
            opt("raw", "raw", Bytes),
            opt("url", "url", Str),
            opt("data", "data", Free),
            f("metadata", "metadata", Free),
            f("filename", "filename", Str),
            f("mediaType", "media_type", Str),
        ] },
        "Task" => const { &[
            f("id", "id", Str),
            f("contextId", "context_id", Str),
            f("status", "status", Msg("TaskStatus")),
            rep("artifacts", "artifacts", Msg("Artifact")),
            rep("history", "history", Msg("Message")),
            f("metadata", "metadata", Free),
        ] },
        "TaskStatus" => const { &[
            f("state", "state", Enum(TASK_STATE)),
            f("message", "message", Msg("Message")),
            f("timestamp", "timestamp", Timestamp),
        ] },
        "Artifact" => const { &[
            f("artifactId", "artifact_id", Str),
            f("name", "name", Str),
            f("description", "description", Str),
            rep("parts", "parts", Msg("Part")),
            f("metadata", "metadata", Free),
            rep("extensions", "extensions", Str),
        ] },
        "SendMessageResponse" => const { &[f("task", "task", Msg("Task")), f("message", "message", Msg("Message"))] },
        "StreamResponse" => const { &[
            f("task", "task", Msg("Task")),
            f("message", "message", Msg("Message")),
            f("statusUpdate", "status_update", Msg("TaskStatusUpdateEvent")),
            f("artifactUpdate", "artifact_update", Msg("TaskArtifactUpdateEvent")),
        ] },
        "TaskStatusUpdateEvent" => const { &[
            f("taskId", "task_id", Str),
            f("contextId", "context_id", Str),
            f("status", "status", Msg("TaskStatus")),
            f("metadata", "metadata", Free),
        ] },
        "TaskArtifactUpdateEvent" => const { &[
            f("taskId", "task_id", Str),
            f("contextId", "context_id", Str),
            f("artifact", "artifact", Msg("Artifact")),
            f("append", "append", Bool),
            f("lastChunk", "last_chunk", Bool),
            f("metadata", "metadata", Free),
        ] },
        "GetTaskRequest" => const { &[
            f("tenant", "tenant", Str),
            f("id", "id", Str),
            opt("historyLength", "history_length", Int32),
        ] },
        "CancelTaskRequest" => const { &[f("tenant", "tenant", Str), f("id", "id", Str), f("metadata", "metadata", Free)] },
        "SubscribeToTaskRequest" => const { &[f("tenant", "tenant", Str), f("id", "id", Str)] },
        other => panic!("no schema for {other}"),
    }
}

pub const A2A_OPS: &[&str] = &[
    "SendMessage",
    "SendStreamingMessage",
    "GetTask",
    "ListTasks",
    "CancelTask",
    "SubscribeToTask",
    "CreateTaskPushNotificationConfig",
    "GetTaskPushNotificationConfig",
    "ListTaskPushNotificationConfigs",
    "DeleteTaskPushNotificationConfig",
    "GetExtendedAgentCard",
];

/// Body schema for (typ, op), when the vectors' schema slice covers it.
pub fn body_schema(typ: &str, op: &str) -> Option<&'static str> {
    match (typ, op) {
        ("request", "SendMessage" | "SendStreamingMessage") => Some("SendMessageRequest"),
        ("response", "SendMessage") => Some("SendMessageResponse"),
        ("response", "SendStreamingMessage") | ("event", _) => Some("StreamResponse"),
        ("request", "GetTask") => Some("GetTaskRequest"),
        ("request", "CancelTask") => Some("CancelTaskRequest"),
        ("request", "SubscribeToTask") => Some("SubscribeToTaskRequest"),
        ("response", "GetTask" | "CancelTask") => Some("Task"),
        _ => None,
    }
}

const P_MSG: &str = "/message/parts/*";
const P_TASK: [&str; 3] = ["/task/status/message/parts/*", "/task/artifacts/*/parts/*", "/task/history/*/parts/*"];

/// Appendix B: (Part patterns, taskId pointers, contextId pointers).
pub fn locations(typ: &str, op: &str) -> (Vec<&'static str>, Vec<&'static str>, Vec<&'static str>) {
    let resp_parts = || {
        let mut v = vec![P_MSG];
        v.extend(P_TASK);
        v
    };
    match (typ, op) {
        ("request", "SendMessage" | "SendStreamingMessage") => {
            (vec![P_MSG], vec!["/message/taskId"], vec!["/message/contextId"])
        }
        ("response", "SendMessage" | "SendStreamingMessage") => {
            (resp_parts(), vec!["/message/taskId", "/task/id"], vec!["/message/contextId", "/task/contextId"])
        }
        ("event", _) => {
            let mut p = resp_parts();
            p.extend(["/statusUpdate/status/message/parts/*", "/artifactUpdate/artifact/parts/*"]);
            (
                p,
                vec!["/message/taskId", "/task/id", "/statusUpdate/taskId", "/artifactUpdate/taskId"],
                vec!["/message/contextId", "/task/contextId", "/statusUpdate/contextId", "/artifactUpdate/contextId"],
            )
        }
        ("response", "GetTask" | "CancelTask") => (
            vec!["/status/message/parts/*", "/artifacts/*/parts/*", "/history/*/parts/*"],
            vec!["/id"],
            vec!["/contextId"],
        ),
        ("request", "GetTask" | "CancelTask" | "SubscribeToTask") => (vec![], vec!["/id"], vec![]),
        _ => (vec![], vec![], vec![]),
    }
}

/// Expands a pattern with `*` (any array index) against `body` into concrete pointers.
pub fn expand(body: &Value, pattern: &str) -> Vec<String> {
    let mut acc = vec![String::new()];
    for tok in pattern.split('/').skip(1) {
        let mut next = vec![];
        for p in acc {
            if tok == "*" {
                if let Some(Value::Array(a)) = body.pointer(&p) {
                    for i in 0..a.len() {
                        next.push(format!("{p}/{i}"));
                    }
                }
            } else {
                let q = format!("{p}/{tok}");
                if body.pointer(&q).is_some() {
                    next.push(q);
                }
            }
        }
        acc = next;
    }
    acc
}

/// Spec ENV-121: true if every known field is in the signer form.
pub fn signer_form_ok(v: &Value, msg: &str) -> bool {
    let Some(members) = v.as_object() else { return false };
    let fields = message_fields(msg);
    for (k, val) in members {
        if let Some(fd) = fields.iter().find(|fd| fd.json == k) {
            if !field_ok(val, fd) {
                return false;
            }
        } else if fields.iter().any(|fd| fd.proto == k && fd.proto != fd.json) {
            return false; // proto name instead of json_name
        }
        // unknown members: kept and ignored
    }
    true
}

fn field_ok(v: &Value, fd: &Field) -> bool {
    if fd.repeated {
        return match v {
            Value::Array(a) => !a.is_empty() && a.iter().all(|x| scalar_ok(x, fd.kind, true)),
            _ => false,
        };
    }
    scalar_ok(v, fd.kind, fd.presence)
}

fn scalar_ok(v: &Value, kind: Kind, presence: bool) -> bool {
    match kind {
        Kind::Str => matches!(v, Value::String(s) if presence || !s.is_empty()),
        Kind::Bytes => matches!(v, Value::String(s) if (presence || !s.is_empty()) && is_canonical_b64std(s)),
        Kind::Bool => matches!(v, Value::Bool(b) if presence || *b),
        Kind::Int32 => matches!(v, Value::Number(n) if n.fract() == 0.0 && (presence || *n != 0.0)),
        Kind::Enum(names) => {
            matches!(v, Value::String(s) if names.contains(&s.as_str()) && (presence || !s.ends_with("_UNSPECIFIED")))
        }
        Kind::Msg(m) => signer_form_ok(v, m),
        Kind::Free => true,
        Kind::Timestamp => matches!(v, Value::String(s) if parse_ts(s).is_some()),
    }
}
