// Definitions for secret service interactions
// Similar to 'define.py' in secretstorage, except with error handling
// in separate error module

// DBus Name
pub const SS_DBUS_NAME: &'static str            = "org.freedesktop.secrets";

// DBus Object paths
pub const SS_PATH: &'static str            = "/org/freedesktop/secrets";
pub const DEFAULT_COLLECTION: &'static str = "/org/freedesktop/secrets/aliases/default";
pub const SESSION_COLLECTION: &'static str = "/org/freedesktop/secrets/collection/session";

// DBu Interfaces
pub const SS_INTERFACE_SERVICE: &'static str      = "org.freedesktop.Secret.Service";
pub const SS_INTERFACE_COLLECTION: &'static str   = "org.freedesktop.Secret.Collection";
pub const SS_INTERFACE_ITEM: &'static str         = "org.freedesktop.Secret.Item";
pub const SS_INTERFACE_SESSION: &'static str      = "org.freedesktop.Secret.Session";
pub const SS_INTERFACE_PROMPT: &'static str       = "org.freedesktop.Secret.Prompt";

// Algorithm Names
pub const ALGORITHM_PLAIN: &'static str = "plain";
pub const ALGORITHM_DH: &'static str    = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

