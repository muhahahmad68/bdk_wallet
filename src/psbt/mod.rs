// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Additional functions on the `rust-bitcoin` `Psbt` structure.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{self, Display};

use bitcoin::psbt;
use bitcoin::{Amount, FeeRate, OutPoint, Psbt, Transaction, TxOut};

#[cfg(all(bdk_wallet_unstable, feature = "bdk-tx"))]
mod params;
#[cfg(all(bdk_wallet_unstable, feature = "bdk-tx"))]
pub use params::*;

pub(crate) fn validated_non_witness_prevout(
    input: &psbt::Input,
    outpoint: OutPoint,
) -> Option<&TxOut> {
    let prev_tx = input.non_witness_utxo.as_ref()?;
    if prev_tx.compute_txid() != outpoint.txid {
        return None;
    }
    prev_tx.output.get(outpoint.vout as usize)
}

// TODO: Upstream these PSBT utilities to rust-bitcoin.

/// Trait to add functions to extract utxos and calculate fees.
pub trait PsbtUtils {
    /// Get the `TxOut` for the specified input index, if it doesn't exist in the PSBT `None` is
    /// returned.
    fn get_utxo_for(&self, input_index: usize) -> Option<TxOut>;

    /// The total transaction fee amount, sum of input amounts minus sum of output amounts, in sats.
    /// If the PSBT is missing a TxOut for an input returns None.
    fn fee_amount(&self) -> Option<Amount>;

    /// The transaction's fee rate. This value will only be accurate if calculated AFTER the
    /// `Psbt` is finalized and all witness/signature data is added to the
    /// transaction.
    /// If the PSBT is missing a TxOut for an input returns None.
    fn fee_rate(&self) -> Option<FeeRate>;
}

impl PsbtUtils for Psbt {
    fn get_utxo_for(&self, input_index: usize) -> Option<TxOut> {
        let txin = self.unsigned_tx.input.get(input_index)?;
        let input = self.inputs.get(input_index)?;
        InputPrevout::new(None, txin, input)
            .ok()
            .map(|prevout| prevout.txout().clone())
    }

    fn fee_amount(&self) -> Option<Amount> {
        let tx = &self.unsigned_tx;
        let utxos: Option<Vec<TxOut>> = (0..tx.input.len()).map(|i| self.get_utxo_for(i)).collect();

        utxos.map(|inputs| {
            let input_amount: Amount = inputs.iter().map(|i| i.value).sum();
            let output_amount: Amount = self.unsigned_tx.output.iter().map(|o| o.value).sum();
            input_amount
                .checked_sub(output_amount)
                .expect("input amount must be greater than output amount")
        })
    }

    fn fee_rate(&self) -> Option<FeeRate> {
        let fee_amount = self.fee_amount();
        let weight = self.clone().extract_tx().ok()?.weight();
        fee_amount.map(|fee| fee / weight)
    }
}

/// Reasons an `InputPrevout` could not be constructed for a PSBT input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrevoutError {
    /// The candidate transaction's txid or vout doesn't match the outpoint being spent.
    Invalid,
    /// The claimed `witness_utxo` disagrees with the verified prevout.
    Mismatch,
    /// Neither a verified prevout nor a `witness_utxo` was available.
    Missing,
}

impl Display for PrevoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => write!(
                f,
                "candidate previous transaction doesn't match the outpoint"
            ),
            Self::Mismatch => write!(
                f,
                "witness_utxo disagrees with the verified previous output"
            ),
            Self::Missing => write!(f, "no previous output data available for this input"),
        }
    }
}

/// The previous output of a PSBT input, tagged with how much it can be trusted.
///
/// `Graph` and `NonWitness` are "verified": the candidate transaction's txid and vout were
/// checked against the outpoint being spent. `Claimed` is backed only by the input's
/// `witness_utxo`, which the PSBT creator can lie about. When a verified txout is also claimed via
/// `witness_utxo`, the two must agree or construction fails.
#[derive(Debug, Clone)]
pub(crate) enum InputPrevout<'a> {
    /// The wallet's tx graph had the full previous transaction.
    TxGraph(Arc<Transaction>, usize),
    /// The input's own `non_witness_utxo` matched the outpoint.
    NonWitness(&'a Transaction, usize),
    /// Only the input's `witness_utxo` was present.
    Witness(&'a TxOut),
}

impl InputPrevout<'_> {
    /// Whether the prevout is verified to be P2TR.
    pub(crate) fn is_verified_p2tr(&self) -> bool {
        !matches!(self, Self::Witness(_)) && self.is_p2tr()
    }

    /// Whether the prevout's script pubkey is P2TR, verified or merely claimed.
    pub(crate) fn is_p2tr(&self) -> bool {
        self.txout().script_pubkey.is_p2tr()
    }

    fn txout(&self) -> &TxOut {
        match self {
            // vout is in range: checked in `InputPrevout::new`.
            Self::TxGraph(tx, vout) => &tx.output[*vout],
            Self::NonWitness(tx, vout) => &tx.output[*vout],
            Self::Witness(txout) => txout,
        }
    }
}

impl<'a> InputPrevout<'a> {
    /// Validate and construct the prevout for a single PSBT input.
    ///
    /// `prev_tx` is the full previous transaction from the wallet's tx graph, if known; as the
    /// source of truth it takes precedence over the input's own (untrusted) `non_witness_utxo`.
    pub(crate) fn new(
        prev_tx: Option<Arc<Transaction>>,
        txin: &'a bitcoin::TxIn,
        input: &'a bitcoin::psbt::Input,
    ) -> Result<Self, PrevoutError> {
        let outpoint = txin.previous_output;
        let vout = outpoint.vout as usize;

        let matches_outpoint =
            |tx: &Transaction| tx.compute_txid() == outpoint.txid && vout < tx.output.len();

        // A claimed witness-utxo must agree with a verified txout, if we have one.
        let agrees_with_claim =
            |txout: &TxOut| input.witness_utxo.as_ref().is_none_or(|w| w == txout);

        if let Some(prev_tx) = prev_tx {
            if !matches_outpoint(&prev_tx) {
                return Err(PrevoutError::Invalid);
            }
            if !agrees_with_claim(&prev_tx.output[vout]) {
                return Err(PrevoutError::Mismatch);
            }
            return Ok(Self::TxGraph(prev_tx, vout));
        }

        if let Some(non_witness_utxo) = &input.non_witness_utxo {
            if !matches_outpoint(non_witness_utxo) {
                return Err(PrevoutError::Invalid);
            }
            if !agrees_with_claim(&non_witness_utxo.output[vout]) {
                return Err(PrevoutError::Mismatch);
            }
            return Ok(Self::NonWitness(non_witness_utxo, vout));
        }

        input
            .witness_utxo
            .as_ref()
            .map(Self::Witness)
            .ok_or(PrevoutError::Missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::psbt::Input;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute,
        transaction,
    };

    /// Builds a simple transaction with one output of the given value
    fn build_tx(value: Amount) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value,
                script_pubkey: ScriptBuf::default(),
            }],
        }
    }

    /// Builds a PSBT spending from the given previous transaction at the given vout
    fn build_psbt(prev_tx: &Transaction, vout: u32) -> Psbt {
        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_tx.compute_txid(),
                    vout,
                },
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::default(),
            }],
        };
        Psbt::from_unsigned_tx(unsigned_tx).unwrap()
    }

    #[test]
    fn get_utxo_for_returns_none_on_txid_mismatch() {
        let real_tx = build_tx(Amount::from_sat(100_000));

        // A different transaction with an inflated value — simulates attacker input
        let fake_tx = build_tx(Amount::from_sat(999_999_999));

        // PSBT spends from real_tx but attacker supplies fake_tx as non_witness_utxo
        let mut psbt = build_psbt(&real_tx, 0);
        psbt.inputs[0] = Input {
            non_witness_utxo: Some(fake_tx), // txid won't match
            ..Default::default()
        };

        // Must return None — fake tx rejected
        assert_eq!(psbt.get_utxo_for(0), None);
    }

    #[test]
    fn get_utxo_for_returns_none_on_vout_out_of_bounds() {
        let prev_tx = build_tx(Amount::from_sat(100_000));
        // prev_tx only has 1 output (vout 0), but we claim to spend vout 3
        let mut psbt = build_psbt(&prev_tx, 3);
        psbt.inputs[0] = Input {
            non_witness_utxo: Some(prev_tx), // txid matches, but vout 3 doesn't exist
            ..Default::default()
        };

        // Must return None — vout out of bounds, no panic
        assert_eq!(psbt.get_utxo_for(0), None);
    }
}
