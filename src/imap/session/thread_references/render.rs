//! The THREAD reply (RFC 5256 §4):
//!
//! ```text
//! thread-list    = "(" (thread-members / thread-nested) ")"
//! thread-members = nz-number *(SP nz-number) [SP thread-nested]
//! thread-nested  = 2*thread-list
//! ```
//!
//! A message with one child continues its list (`(1 2 3)`), one with
//! several opens a nested list per child (`(1 (2)(3 4))`), and a dummy is
//! a bare `thread-nested` (`((1)(2))`), as ORDEREDSUBJECT renders too.
//! The walk keeps its pending work on a heap stack, so a reply chain as
//! long as the mailbox renders without recursion.

use std::fmt::Write;

use super::{Message, Tree};

enum Step {
	/// Open the thread-list of a node.
	List(u32),
	/// Close a thread-list opened earlier.
	Close,
}

/// Append the thread-lists of every top-level thread in `tree` to `out`,
/// numbering messages by UID when `uid` is set and by sequence otherwise.
pub(super) fn render(tree: &Tree, messages: &[Message], uid: bool, out: &mut String) {
	let number = |node: u32| {
		let message = &messages[node as usize];
		if uid { message.uid } else { message.seqno }
	};
	let mut stack = Vec::new();
	for &root in &tree.roots {
		stack.push(Step::List(root));
		while let Some(step) = stack.pop() {
			let node = match step {
				Step::Close => {
					out.push(')');
					continue;
				}
				Step::List(node) => node,
			};
			out.push('(');
			let mut node = node;
			if !tree.is_dummy(node) {
				let _ = write!(out, "{}", number(node));
				while let [only] = tree.children[node as usize].as_slice() {
					node = *only;
					let _ = write!(out, " {}", number(node));
				}
				if tree.children[node as usize].is_empty() {
					out.push(')');
					continue;
				}
				out.push(' ');
			}
			stack.push(Step::Close);
			for &child in tree.children[node as usize].iter().rev() {
				stack.push(Step::List(child));
			}
		}
	}
}
