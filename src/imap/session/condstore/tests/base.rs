use super::reply_modseq;
use crate::imap::command::ReturnOpt;

#[test]
fn reply_modseq_covers_the_returned_messages() {
	let modseqs = [5, 9, 7];
	assert_eq!(reply_modseq(&modseqs, None), Some(9));
	assert_eq!(reply_modseq(&modseqs, Some(&[ReturnOpt::Min])), Some(5));
	assert_eq!(reply_modseq(&modseqs, Some(&[ReturnOpt::Max])), Some(7));
	assert_eq!(
		reply_modseq(&modseqs, Some(&[ReturnOpt::Min, ReturnOpt::Max])),
		Some(7)
	);
	assert_eq!(reply_modseq(&modseqs, Some(&[ReturnOpt::Count])), Some(9));
	assert_eq!(reply_modseq(&[], Some(&[ReturnOpt::All])), None);
}
