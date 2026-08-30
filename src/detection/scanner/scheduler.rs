#![deny(unsafe_code)]

use std::collections::VecDeque;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Task {
    pub id: usize,
    pub url: String,
    pub param: String,
}

#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Scheduler {
    queue: VecDeque<Task>,
    next_id: usize,
}

impl Scheduler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, url: impl Into<String>, param: impl Into<String>) {
        self.next_id += 1;
        self.queue.push_back(Task {
            id: self.next_id,
            url: url.into(),
            param: param.into(),
        });
    }

    #[must_use]
    pub fn pop(&mut self) -> Option<Task> {
        self.queue.pop_front()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}
