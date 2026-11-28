//! Safe-Rust systematic Cauchy Reed-Solomon FEC over GF(2^8) for low-latency P2P video datagrams.
//! Allows 0-RTT packet recovery for up to `m` lost UDP datagrams per video frame without waiting
//! for QUIC retransmission or stalling on Head-of-Line blocking.
#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const MAX_FEC_DATA_SHARDS: usize = 200;
pub const DEFAULT_FEC_PERCENT: usize = 20;
const FEC_BLOCK_TTL: Duration = Duration::from_millis(160);
const MAX_PENDING_BLOCKS: usize = 12;

const fn build_gf_tables() -> ([u8; 512], [u8; 256]) {
	let mut exp = [0u8; 512];
	let mut log = [0u8; 256];
	let mut x: u16 = 1;
	let mut i = 0;
	while i < 255 {
		exp[i] = x as u8;
		exp[i + 255] = x as u8;
		log[x as usize] = i as u8;
		x <<= 1;
		if x & 0x100 != 0 {
			x ^= 0x11d;
		}
		i += 1;
	}
	exp[510] = exp[0];
	exp[511] = exp[1];
	(exp, log)
}

const GF_TABLES: ([u8; 512], [u8; 256]) = build_gf_tables();
const GF_EXP: &[u8; 512] = &GF_TABLES.0;
const GF_LOG: &[u8; 256] = &GF_TABLES.1;

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
	if a == 0 || b == 0 {
		0
	} else {
		GF_EXP[usize::from(GF_LOG[usize::from(a)]) + usize::from(GF_LOG[usize::from(b)])]
	}
}

#[inline]
fn gf_inv(a: u8) -> u8 {
	debug_assert!(a != 0);
	GF_EXP[255 - usize::from(GF_LOG[usize::from(a)])]
}

/// Cauchy entry `1 / (x_r ^ y_c)` where `x_r = k + r` and `y_c = c`.
/// Since `k + r >= k > c` and `k + m <= 255`, `x_r` and `y_c` are always distinct in GF(2^8),
/// guaranteeing every `k x k` submatrix of `[I_k ; C_{m x k}]` is nonsingular.
#[inline]
fn cauchy_coeff(parity_row: usize, data_col: usize, data_shards: usize) -> u8 {
	let x = (data_shards + parity_row) as u8;
	let y = data_col as u8;
	gf_inv(x ^ y)
}

fn mul_add_slice(dst: &mut [u8], src: &[u8], coeff: u8) {
	if coeff == 0 {
		return;
	}
	if coeff == 1 {
		for (d, &s) in dst.iter_mut().zip(src) {
			*d ^= s;
		}
		return;
	}
	let mut lut = [0u8; 256];
	let log_c = usize::from(GF_LOG[usize::from(coeff)]);
	for (i, slot) in lut.iter_mut().enumerate().skip(1) {
		*slot = GF_EXP[usize::from(GF_LOG[i]) + log_c];
	}
	for (d, &s) in dst.iter_mut().zip(src) {
		*d ^= lut[usize::from(s)];
	}
}

/// Systematic FEC block ready to be sent as `data_shards + parity_shards` UDP datagrams.
#[derive(Clone, Debug)]
pub struct FecEncodedBlock {
	pub data_shards: u8,
	pub parity_shards: u8,
	pub frame_len: usize,
	pub shards: Vec<Vec<u8>>,
}

/// Encodes `frame` into `data_shards` systematic shards plus `parity_shards` Cauchy RS shards.
/// Returns `None` if the frame exceeds `MAX_FEC_DATA_SHARDS * max_shard_payload`.
pub fn encode_frame(
	frame: &[u8],
	max_shard_payload: usize,
	fec_percent: usize,
) -> Option<FecEncodedBlock> {
	if frame.is_empty() || max_shard_payload == 0 {
		return None;
	}
	let data_shards = frame.len().div_ceil(max_shard_payload).max(1);
	if data_shards > MAX_FEC_DATA_SHARDS {
		return None;
	}
	let shard_len = frame.len().div_ceil(data_shards);
	if shard_len > max_shard_payload {
		return None;
	}
	let parity_shards = if data_shards <= 2 {
		1
	} else {
		(data_shards * fec_percent.clamp(5, 50))
			.div_ceil(100)
			.max(1)
	}
	.min(255 - data_shards);

	let total_shards = data_shards + parity_shards;
	let mut shards = Vec::with_capacity(total_shards);

	for c in 0..data_shards {
		let start = c * shard_len;
		let end = (start + shard_len).min(frame.len());
		let mut buf = vec![0u8; shard_len];
		if start < end {
			buf[..end - start].copy_from_slice(&frame[start..end]);
		}
		shards.push(buf);
	}

	for r in 0..parity_shards {
		let mut parity = vec![0u8; shard_len];
		for (c, data_shard) in shards[..data_shards].iter().enumerate() {
			let coeff = cauchy_coeff(r, c, data_shards);
			mul_add_slice(&mut parity, data_shard, coeff);
		}
		shards.push(parity);
	}

	Some(FecEncodedBlock {
		data_shards: data_shards as u8,
		parity_shards: parity_shards as u8,
		frame_len: frame.len(),
		shards,
	})
}

#[derive(Clone, Debug)]
pub struct ReconstructedFrame {
	pub data: Vec<u8>,
	pub fec_recovered: bool,
}

struct PendingBlock {
	created_at: Instant,
	data_shards: usize,
	parity_shards: usize,
	shard_len: usize,
	frame_len: usize,
	shards: Vec<Option<Vec<u8>>>,
	received: usize,
	completed: bool,
}

impl PendingBlock {
	fn try_reconstruct(&mut self) -> Option<ReconstructedFrame> {
		if self.completed || self.received < self.data_shards {
			return None;
		}
		let k = self.data_shards;
		if self.shards[..k].iter().all(Option::is_some) {
			self.completed = true;
			let mut out = Vec::with_capacity(self.frame_len);
			for shard in &self.shards[..k] {
				let bytes = shard.as_deref()?;
				let remaining = self.frame_len.saturating_sub(out.len());
				out.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
			}
			return (out.len() == self.frame_len).then_some(ReconstructedFrame {
				data: out,
				fec_recovered: false,
			});
		}

		let mut selected_rows = Vec::with_capacity(k);
		for (idx, slot) in self.shards.iter().enumerate() {
			if slot.is_some() {
				selected_rows.push(idx);
				if selected_rows.len() == k {
					break;
				}
			}
		}
		if selected_rows.len() < k {
			return None;
		}

		// Invert the k x k submatrix of [I_k ; C_{m x k}] via Gauss-Jordan over GF(2^8).
		let mut mat = vec![0u8; k * k];
		let mut inv = vec![0u8; k * k];
		for (row_i, &src_row) in selected_rows.iter().enumerate() {
			inv[row_i * k + row_i] = 1;
			if src_row < k {
				mat[row_i * k + src_row] = 1;
			} else {
				let parity_row = src_row - k;
				for col in 0..k {
					mat[row_i * k + col] = cauchy_coeff(parity_row, col, k);
				}
			}
		}

		for pivot in 0..k {
			let mut pivot_row = pivot;
			while pivot_row < k && mat[pivot_row * k + pivot] == 0 {
				pivot_row += 1;
			}
			if pivot_row == k {
				return None;
			}
			if pivot_row != pivot {
				for col in 0..k {
					mat.swap(pivot * k + col, pivot_row * k + col);
					inv.swap(pivot * k + col, pivot_row * k + col);
				}
			}
			let diag = mat[pivot * k + pivot];
			if diag != 1 {
				let scale = gf_inv(diag);
				for col in 0..k {
					mat[pivot * k + col] = gf_mul(mat[pivot * k + col], scale);
					inv[pivot * k + col] = gf_mul(inv[pivot * k + col], scale);
				}
			}
			for r in 0..k {
				if r == pivot {
					continue;
				}
				let factor = mat[r * k + pivot];
				if factor == 0 {
					continue;
				}
				for col in 0..k {
					let p_m = mat[pivot * k + col];
					let p_i = inv[pivot * k + col];
					mat[r * k + col] ^= gf_mul(factor, p_m);
					inv[r * k + col] ^= gf_mul(factor, p_i);
				}
			}
		}

		self.completed = true;
		let mut out = Vec::with_capacity(self.frame_len);
		let mut recovered_buf = vec![0u8; self.shard_len];
		for col in 0..k {
			let remaining = self.frame_len.saturating_sub(out.len());
			if let Some(present) = self.shards[col].as_deref() {
				out.extend_from_slice(&present[..present.len().min(remaining)]);
				continue;
			}
			recovered_buf.fill(0);
			for (j, &src_row) in selected_rows.iter().enumerate() {
				let coeff = inv[col * k + j];
				if coeff != 0
					&& let Some(shard) = self.shards[src_row].as_deref()
				{
					mul_add_slice(&mut recovered_buf, shard, coeff);
				}
			}
			out.extend_from_slice(&recovered_buf[..recovered_buf.len().min(remaining)]);
		}

		(out.len() == self.frame_len).then_some(ReconstructedFrame {
			data: out,
			fec_recovered: true,
		})
	}
}

/// Bounded receiver-side FEC reassembler tracking recent video frames.
#[derive(Default)]
pub struct FecAssembler {
	blocks: HashMap<u32, PendingBlock>,
	order: VecDeque<u32>,
	pub total_frames_ok: u64,
	pub total_frames_fec_recovered: u64,
	pub total_frames_expired_incomplete: u64,
}

impl FecAssembler {
	pub fn prune_expired(&mut self, now: Instant) {
		while let Some(&front_id) = self.order.front() {
			let expired = self.blocks.get(&front_id).is_none_or(|b| {
				b.completed || now.saturating_duration_since(b.created_at) >= FEC_BLOCK_TTL
			});
			if !expired {
				break;
			}
			self.order.pop_front();
			if let Some(block) = self.blocks.remove(&front_id)
				&& !block.completed
			{
				self.total_frames_expired_incomplete += 1;
			}
		}
	}

	#[allow(clippy::too_many_arguments)]
	pub fn push_shard(
		&mut self,
		frame_id: u32,
		data_shards: u8,
		parity_shards: u8,
		shard_idx: u8,
		frame_len: usize,
		shard_data: &[u8],
		max_frame_bytes: usize,
	) -> Option<ReconstructedFrame> {
		let k = usize::from(data_shards);
		let m = usize::from(parity_shards);
		let idx = usize::from(shard_idx);
		if k == 0
			|| k > MAX_FEC_DATA_SHARDS
			|| k + m > 255
			|| idx >= k + m
			|| frame_len == 0
			|| frame_len > max_frame_bytes
			|| shard_data.is_empty()
		{
			return None;
		}
		let expected_shard_len = frame_len.div_ceil(k);
		if shard_data.len() != expected_shard_len {
			return None;
		}

		let now = Instant::now();
		self.prune_expired(now);

		if !self.blocks.contains_key(&frame_id) {
			while self.blocks.len() >= MAX_PENDING_BLOCKS {
				let Some(old_id) = self.order.pop_front() else {
					break;
				};
				if let Some(old) = self.blocks.remove(&old_id)
					&& !old.completed
				{
					self.total_frames_expired_incomplete += 1;
				}
			}
			self.order.push_back(frame_id);
			self.blocks.insert(
				frame_id,
				PendingBlock {
					created_at: now,
					data_shards: k,
					parity_shards: m,
					shard_len: expected_shard_len,
					frame_len,
					shards: vec![None; k + m],
					received: 0,
					completed: false,
				},
			);
		}

		let block = self.blocks.get_mut(&frame_id)?;
		if block.completed
			|| block.data_shards != k
			|| block.parity_shards != m
			|| block.frame_len != frame_len
			|| block.shard_len != expected_shard_len
		{
			return None;
		}
		if block.shards[idx].is_some() {
			return None;
		}
		block.shards[idx] = Some(shard_data.to_vec());
		block.received += 1;
		let result = block.try_reconstruct();
		if let Some(ref res) = result {
			self.total_frames_ok += 1;
			if res.fec_recovered {
				self.total_frames_fec_recovered += 1;
			}
		}
		result
	}

	/// Marks `frame_id` completed (e.g. delivered via QUIC uni-stream fallback).
	pub fn mark_completed(&mut self, frame_id: u32) {
		if let Some(block) = self.blocks.get_mut(&frame_id) {
			block.completed = true;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn fec_recovers_single_shard_frame_using_parity() {
		let frame = b"hello sunshine/moonlight fec world!".to_vec();
		let encoded = encode_frame(&frame, 1000, DEFAULT_FEC_PERCENT).unwrap();
		assert_eq!(encoded.data_shards, 1);
		assert_eq!(encoded.parity_shards, 1);

		let mut dec = FecAssembler::default();
		// Drop data shard 0, deliver only parity shard 1.
		let res = dec
			.push_shard(
				10,
				encoded.data_shards,
				encoded.parity_shards,
				1,
				encoded.frame_len,
				&encoded.shards[1],
				1024 * 1024,
			)
			.unwrap();
		assert!(res.fec_recovered);
		assert_eq!(res.data, frame);
	}

	#[test]
	fn fec_recovers_multiple_data_and_mixed_losses() {
		// Unaligned frame size across ~16 shards.
		let frame: Vec<u8> = (0..17_321).map(|i| (i * 37 % 251) as u8).collect();
		let encoded = encode_frame(&frame, 1100, DEFAULT_FEC_PERCENT).unwrap();
		let k = usize::from(encoded.data_shards);
		let m = usize::from(encoded.parity_shards);
		assert_eq!(k, 16);
		assert!(m >= 4);

		// Drop 4 shards (mix of data shards 0, 5, 15 and parity shard k+1).
		let dropped = [0usize, 5, 15, k + 1];
		let mut dec = FecAssembler::default();
		let mut recovered = None;
		for (idx, shard) in encoded.shards.iter().enumerate() {
			if dropped.contains(&idx) {
				continue;
			}
			if let Some(res) = dec.push_shard(
				42,
				encoded.data_shards,
				encoded.parity_shards,
				idx as u8,
				encoded.frame_len,
				shard,
				1024 * 1024,
			) {
				recovered = Some(res);
				break;
			}
		}
		let recovered = recovered.expect("should recover all missing data shards");
		assert!(recovered.fec_recovered);
		assert_eq!(recovered.data, frame);
	}

	#[test]
	fn fec_returns_none_when_losses_exceed_parity_budget() {
		let frame: Vec<u8> = (0..10_000).map(|i| (i & 0xff) as u8).collect();
		let encoded = encode_frame(&frame, 1000, DEFAULT_FEC_PERCENT).unwrap();
		let k = usize::from(encoded.data_shards);
		let m = usize::from(encoded.parity_shards);
		let mut dec = FecAssembler::default();
		// Deliver only k - 1 shards.
		for (idx, shard) in encoded.shards.iter().take(k - 1).enumerate() {
			assert!(
				dec.push_shard(
					7,
					encoded.data_shards,
					encoded.parity_shards,
					idx as u8,
					encoded.frame_len,
					shard,
					1024 * 1024,
				)
				.is_none()
			);
		}
		assert_eq!(k + m, encoded.shards.len());
		assert_eq!(dec.total_frames_ok, 0);
	}
}
