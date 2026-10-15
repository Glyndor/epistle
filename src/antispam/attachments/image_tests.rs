use super::*;
use crate::antispam::attachments::corpus;

fn facts(real: RealType, bytes: &[u8]) -> ImageFacts {
	inspect_raster(real, bytes)
}

pub(crate) fn pe_header() -> Vec<u8> {
	let mut pe = b"MZ".to_vec();
	pe.resize(0x3c, 0);
	pe.extend_from_slice(&0x40u32.to_le_bytes());
	pe.extend_from_slice(b"PE\0\0");
	pe
}

pub(crate) fn png_then(tail: &[u8]) -> Vec<u8> {
	let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
	png.extend_from_slice(&13u32.to_be_bytes());
	png.extend_from_slice(b"IHDR");
	png.extend_from_slice(&[0; 13 + 4]);
	png.extend_from_slice(&0u32.to_be_bytes());
	png.extend_from_slice(b"IEND");
	png.extend_from_slice(&[0; 4]);
	png.extend_from_slice(tail);
	png
}

pub(crate) fn jpeg_then(tail: &[u8]) -> Vec<u8> {
	let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10];
	jpeg.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
	jpeg.extend_from_slice(&[0xff, 0xda, 0x00, 0x08, 1, 2, 3, 4, 5, 6]);
	jpeg.extend_from_slice(&[0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56]);
	jpeg.extend_from_slice(&[0xff, 0xd9]);
	jpeg.extend_from_slice(tail);
	jpeg
}

pub(crate) fn gif_then(tail: &[u8]) -> Vec<u8> {
	let mut gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00".to_vec();
	gif.extend_from_slice(&[0x21, 0xf9, 0x04, 0, 0, 0, 0, 0x00]);
	gif.extend_from_slice(&[0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0x00]);
	gif.extend_from_slice(&[0x02, 0x02, 0x4c, 0x01, 0x00]);
	gif.push(0x3b);
	gif.extend_from_slice(tail);
	gif
}

pub(crate) fn webp_then(tail: &[u8]) -> Vec<u8> {
	let mut webp = b"RIFF".to_vec();
	webp.extend_from_slice(&12u32.to_le_bytes());
	webp.extend_from_slice(b"WEBPVP8 \0\0\0\0");
	webp.extend_from_slice(tail);
	webp
}

#[test]
fn a_payload_after_the_logical_end_of_an_image_is_found() {
	let cases: Vec<(RealType, Vec<u8>)> = vec![
		(RealType::Png, png_then(&pe_header())),
		(RealType::Jpeg, jpeg_then(&corpus::zip_of(&["a.txt"]))),
		(RealType::Gif, gif_then(b"\x7fELF\x02\x01\x01")),
		(RealType::Webp, webp_then(b"#!/bin/sh\nrm -rf ~\n")),
	];
	for (real, bytes) in cases {
		assert_eq!(
			facts(real, &bytes),
			ImageFacts {
				payload: true,
				ambiguous: false
			},
			"{real:?}"
		);
	}
}

#[test]
fn a_clean_image_or_harmless_trailing_bytes_are_not_a_payload() {
	let cases: Vec<(RealType, Vec<u8>)> = vec![
		(RealType::Png, png_then(b"")),
		(RealType::Png, png_then(b"MZ but no PE header")),
		(RealType::Jpeg, jpeg_then(b"\0\0")),
		(RealType::Gif, gif_then(b"")),
		(RealType::Webp, webp_then(b"")),
	];
	for (real, bytes) in cases {
		assert_eq!(facts(real, &bytes), ImageFacts::default(), "{real:?}");
	}
}

#[test]
fn the_tail_scan_stays_linear() {
	let tail = b"MZ".repeat(4 << 20);
	let started = std::time::Instant::now();
	assert!(!facts(RealType::Png, &png_then(&tail)).payload);
	assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn a_payload_inside_metadata_is_found() {
	let mut text_chunk = (pe_header().len() as u32).to_be_bytes().to_vec();
	text_chunk.extend_from_slice(b"tEXt");
	text_chunk.extend_from_slice(&pe_header());
	text_chunk.extend_from_slice(&[0; 4]);
	let png = png_then(b"");
	let iend = png.len() - 12;
	let mut with_text = png[..iend].to_vec();
	with_text.extend_from_slice(&text_chunk);
	with_text.extend_from_slice(&png[iend..]);
	assert!(facts(RealType::Png, &with_text).payload, "PNG tEXt");

	let mut jpeg = vec![0xff, 0xd8, 0xff, 0xfe, 0x00, 0x08];
	jpeg.extend_from_slice(b"PK\x03\x04xx");
	jpeg.extend_from_slice(&jpeg_then(b"")[2..]);
	assert!(facts(RealType::Jpeg, &jpeg).payload, "JPEG comment");

	let mut gif = gif_then(b"");
	let trailer = gif.len() - 1;
	let comment = [0x21, 0xfe, 0x05, 0x7f, b'E', b'L', b'F', 0x02, 0x00];
	gif.splice(trailer..trailer, comment);
	assert!(facts(RealType::Gif, &gif).payload, "GIF comment");

	let mut webp = b"RIFF".to_vec();
	webp.extend_from_slice(&(4u32 + 8 + 4).to_le_bytes());
	webp.extend_from_slice(b"WEBPEXIF");
	webp.extend_from_slice(&4u32.to_le_bytes());
	webp.extend_from_slice(b"#!/x");
	assert!(facts(RealType::Webp, &webp).payload, "WebP EXIF");
}

#[test]
fn an_end_of_image_inside_an_app_segment_is_not_the_end() {
	let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe1, 0x00, 0x06, 0xff, 0xd9, 0x00, 0x00];
	jpeg.extend_from_slice(&jpeg_then(&pe_header())[2..]);
	assert!(facts(RealType::Jpeg, &jpeg).payload);
}

#[test]
fn an_image_that_cannot_be_walked_is_ambiguous() {
	let mut bad_png = png_then(b"");
	bad_png[8..12].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
	let mut no_end_jpeg = jpeg_then(b"");
	no_end_jpeg.truncate(no_end_jpeg.len() - 2);
	let mut long_webp = webp_then(b"");
	long_webp[4..8].copy_from_slice(&4096u32.to_le_bytes());
	let mut short_webp = webp_then(b"");
	short_webp[4..8].copy_from_slice(&2u32.to_le_bytes());
	let mut no_trailer_gif = gif_then(b"");
	no_trailer_gif.pop();
	for (real, bytes) in [
		(RealType::Png, bad_png),
		(RealType::Jpeg, no_end_jpeg),
		(RealType::Webp, long_webp),
		(RealType::Webp, short_webp),
		(RealType::Gif, no_trailer_gif),
	] {
		assert!(facts(real, &bytes).ambiguous, "{real:?}");
	}
}

#[test]
fn a_payload_inside_an_exif_segment_is_found() {
	let mut jpeg = vec![0xff, 0xd8, 0xff, 0xe1, 0x00, 0x0e];
	jpeg.extend_from_slice(b"Exif\0\0\x7fELF\x02\x01");
	jpeg.extend_from_slice(&jpeg_then(b"")[2..]);
	assert!(facts(RealType::Jpeg, &jpeg).payload);
}

#[test]
fn a_shebang_inside_appended_media_is_not_a_payload() {
	// Motion photos carry an MP4 after the JPEG and Ultra HDR photos a
	// second JPEG: compressed bytes that contain "#!/" about once every
	// 16 MiB. A script only means something where it starts.
	let mut video = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom".to_vec();
	video.extend_from_slice(&[0x5a; 4096]);
	video.extend_from_slice(b"#!/");
	video.extend_from_slice(&[0xa5; 4096]);
	assert_eq!(
		facts(RealType::Jpeg, &jpeg_then(&video)),
		ImageFacts::default(),
		"a motion photo"
	);
	let mut comment = vec![0xff, 0xd8, 0xff, 0xfe, 0x00, 0x0c];
	comment.extend_from_slice(b"see #!/usr");
	comment.extend_from_slice(&jpeg_then(b"")[2..]);
	assert_eq!(facts(RealType::Jpeg, &comment), ImageFacts::default());
	assert!(
		facts(RealType::Jpeg, &jpeg_then(b"\n#!/bin/sh\nid\n")).payload,
		"a script appended right after the image still is"
	);
}
