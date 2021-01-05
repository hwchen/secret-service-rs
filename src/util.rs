//Copyright 2016 secret-service-rs Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Contains helpers for:
//!   locking/unlocking
//!   exec_prompt
//!   formatting secrets

use crate::error::{Error, Result};
use crate::proxy::prompt::PromptProxy;
use crate::proxy::service::ServiceProxy;
use crate::session::Session;
use crate::ss::SS_DBUS_NAME;
use crate::ss_crypto::encrypt;
use crate::proxy::SecretStruct;
use crate::proxy::item::SecretStructInput;

use rand::{Rng, rngs::OsRng};
use std::sync::mpsc::channel;
use zvariant::ObjectPath;

// Helper enum for locking
pub(crate) enum LockAction {
    Lock,
    Unlock,
}

pub(crate) fn lock_or_unlock(
    conn: zbus::Connection,
    service_proxy: &ServiceProxy,
    object_path: &ObjectPath,
    lock_action: LockAction
    ) -> Result<()>
{
    let objects = vec![object_path];

    let lock_action_res = match lock_action {
        LockAction::Lock => service_proxy.lock(objects)?,
        LockAction::Unlock => service_proxy.unlock(objects)?,
    };

    if lock_action_res.object_paths.is_empty() {
        exec_prompt(conn, &lock_action_res.prompt)?;
    }
    Ok(())
}

pub(crate) fn format_secret(
    session: &Session,
    secret: &[u8],
    content_type: &str
    ) -> Result<SecretStructInput>
{
    let content_type = content_type.to_owned();

    if session.is_encrypted() {
        let mut rng = OsRng {};
        let mut aes_iv = [0;16];
        rng.fill(&mut aes_iv);

        let encrypted_secret = encrypt(secret, &session.get_aes_key()[..], &aes_iv)?;

        // Construct secret struct
        let parameters = aes_iv.to_vec();
        let value = encrypted_secret;

        Ok(SecretStructInput {
            inner: SecretStruct {
                session: session.object_path.clone(),
                parameters,
                value,
                content_type,
            }
        })
    } else {
        // just Plain for now
        let parameters = Vec::new();
        let value = secret.to_vec();

        Ok(SecretStructInput {
            inner: SecretStruct {
                session: session.object_path.clone(),
                parameters,
                value,
                content_type,
            }
        })
    }
}

pub(crate) fn exec_prompt(conn: zbus::Connection, prompt: &ObjectPath) -> Result<zvariant::OwnedValue> {
    let prompt_proxy = PromptProxy::new_for(
        &conn,
        SS_DBUS_NAME,
        prompt,
        )?;

    let (tx, rx) = channel();

    // create a handler for `completed` signal
    prompt_proxy
        .connect_completed(move |dismissed, result| {
            let res = if dismissed {
                Err(Error::Prompt)
            } else {
                Ok(result.into())
            };

            tx.send(res).expect("rx should not be dropped, channel scoped to this fn");

            Ok(())
        })?;

    // TODO figure out window_id
    let window_id = "";
    prompt_proxy.prompt(window_id)?;

    // waits for next signal and calls the handler.
    // If message handled by above handler, `next_signal` returns `Ok(None)`, ending loop.
    while prompt_proxy.next_signal()?.is_some() {};

    // See comment on allowing channels to panic: https://www.reddit.com/r/rust/comments/awh751/proposal_new_channels_for_rusts_standard_library/ehmk3lz/
    rx.recv().expect("tx shold not be dropped, channel scoped to this fn")
}
