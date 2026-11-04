// SPDX-License-Identifier: Apache-2.0

//! Single home for [`qqq_core::is_layout_forgery`], kept as a module so the
//! `qqq_cap::text::is_layout_forgery` path existing callers use keeps
//! working.
pub use qqq_core::text::{is_invisible_format, is_layout_forgery};
