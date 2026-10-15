//! Voice messages (rust/airchat-protocol/docs/protocol.md §8.4, §9.7): Ogg Opus files of at most 1 MiB, fetched without
//! asking, and deleted on the receiving device a quarter of an hour after they were first played.

use super::{Action, Node, NodeError, Store, now_ms};
use crate::storage::{VOICE_KEEP_MS, groups::group_file};

impl Node {
    /// The user played voice message `file` (a group file as [`group_file`] names it): if it came
    /// in and was not played before, its quarter of an hour starts now.
    pub fn voice_played(&mut self, file: i64) -> Result<Vec<Action>, NodeError> {
        let account = self.account()?;
        let db = account.db();
        let now = now_ms();
        Ok(if file < 0 {
            if !db.group_voice_played(-file, now)? {
                return Ok(Vec::new());
            }
            db.group_message(-file)?
                .map(|message| Action::GroupMessageUpdated { message })
                .into_iter()
                .collect()
        } else {
            if !db.voice_played(file, now)? {
                return Ok(Vec::new());
            }
            db.message(file)?
                .map(|message| Action::MessageUpdated { message })
                .into_iter()
                .collect()
        })
    }

    /// Voice messages played a quarter of an hour ago or more lose their content.
    pub(super) fn expire_voice(&mut self, now_ms: i64) -> Vec<Action> {
        let Store::Open(account) = &self.store else {
            return Vec::new();
        };
        let before = now_ms - VOICE_KEEP_MS;
        let mut actions = Vec::new();
        for message in account.db().expire_voice(before).unwrap_or_default() {
            let _ = account.clear_file(message.id);
            actions.push(Action::MessageUpdated { message });
        }
        for message in account.db().expire_group_voice(before).unwrap_or_default() {
            let _ = account.clear_file(group_file(message.row));
            actions.push(Action::GroupMessageUpdated { message });
        }
        actions
    }
}
