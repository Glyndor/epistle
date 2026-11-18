//! A reproducible stateful command corpus checked against an independent model.

use super::harness::*;

const MESSAGE: &[u8] = b"Subject: model canary\r\n\r\nbody\r\n";

#[tokio::test]
async fn generated_delete_reset_sequences_preserve_snapshot_and_commit_rules() {
	// Fixed seeds make a failing command sequence reproducible without a
	// fuzzing runtime. Each seed runs with QUIT and with transport EOF.
	for seed in [1_u64, 0x1498, 0xdead_beef, 0x5eed_cafe] {
		for commit in [false, true] {
			let server = Harness::start(|s| s).await;
			let ids = [1_u128, 2, 3].map(|n| {
				uuid::Uuid::from_u128(0x0190_0000_0000_7000_8000_0000_0000_0000 + n).to_string()
			});
			let paths = ids.each_ref().map(|id| server.seed("tester", id, MESSAGE));
			let mut client = server.login("tester", 3).await;
			let mut deleted = [false; 3];
			let mut random = seed;
			for step in 0..32 {
				random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
				let number = ((random >> 32) % 5) as usize;
				match (random >> 16) % 3 {
					0 => {
						send(&mut client, format!("DELE {number}\r\n").as_bytes()).await;
						if (1..=3).contains(&number) && !deleted[number - 1] {
							deleted[number - 1] = true;
							expect(&mut client, &format!("+OK message {number} deleted\r\n")).await;
						} else {
							expect(&mut client, "-ERR no such message\r\n").await;
						}
					}
					1 => {
						send(&mut client, b"RSET\r\n").await;
						deleted.fill(false);
						expect(&mut client, "+OK 3 messages\r\n").await;
					}
					_ => {
						send(&mut client, format!("UIDL {number}\r\n").as_bytes()).await;
						if (1..=3).contains(&number) && !deleted[number - 1] {
							expect(
								&mut client,
								&format!("+OK {number} {}\r\n", ids[number - 1]),
							)
							.await;
						} else {
							expect(&mut client, "-ERR no such message\r\n").await;
						}
					}
				}
				// A successful STAT between hostile commands prevents the abuse
				// error-streak bound from ending the modeled transaction early.
				let count = deleted.iter().filter(|gone| !**gone).count();
				send(&mut client, b"STAT\r\n").await;
				expect(
					&mut client,
					&format!("+OK {count} {}\r\n", count * MESSAGE.len()),
				)
				.await;
				for path in &paths {
					assert_eq!(
						std::fs::read(path).expect("uncommitted file"),
						MESSAGE,
						"seed={seed} step={step}: DELE committed before QUIT"
					);
				}
			}
			// Ensure every sequence ends with a pending deletion, so EOF versus
			// QUIT always exercises different persistence behavior.
			send(&mut client, b"RSET\r\nDELE 2\r\n").await;
			expect(&mut client, "+OK 3 messages\r\n").await;
			expect(&mut client, "+OK message 2 deleted\r\n").await;
			if commit {
				quit(&mut client).await;
			} else {
				abandon(&mut client).await;
			}
			assert_eq!(paths[1].exists(), !commit, "seed={seed} commit={commit}");
			for path in [&paths[0], &paths[2]] {
				assert_eq!(std::fs::read(path).expect("survivor"), MESSAGE);
			}
			server.healthy().await;
		}
	}
}
