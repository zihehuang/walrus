// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A transaction builder for programmable transactions containing Walrus-related calls.

use std::{
    collections::{BTreeSet, HashSet},
    fmt::Debug,
    str::FromStr,
};

use fastcrypto::traits::ToFromBytes;
use sui_types::{
    base_types::{ObjectID, SuiAddress},
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{Argument, Command, ObjectArg, ProgrammableTransaction},
    Identifier,
    SUI_CLOCK_OBJECT_ID,
    SUI_CLOCK_OBJECT_SHARED_VERSION,
};
use walrus_core::{
    messages::{ConfirmationCertificate, InvalidBlobCertificate, ProofOfPossession},
    Epoch,
    EpochCount,
};

use super::{
    read_client::Mutability,
    BlobObjectMetadata,
    BlobPersistence,
    CoinType,
    ReadClient,
    SuiClientError,
    SuiClientResult,
    SuiReadClient,
};
use crate::{
    contracts::{self, FunctionTag},
    types::{move_structs::WalExchange, NodeMetadata, NodeRegistrationParams},
    utils::{price_for_encoded_length, write_price_for_encoded_length},
};

const CLOCK_OBJECT_ARG: ObjectArg = ObjectArg::SharedObject {
    id: SUI_CLOCK_OBJECT_ID,
    initial_shared_version: SUI_CLOCK_OBJECT_SHARED_VERSION,
    mutable: false,
};

/// The maximum number of blobs that can be burned in a single PTB.
/// This number is chosen just below the maximum number of commands in a PTB (1024).
// NB: this should be kept in sync with the maximum number of commands in the Sui `ProtocolConfig`.
pub const MAX_BURNS_PER_PTB: usize = 1000;

#[derive(Debug, Clone, Copy)]
/// A wrapper around an [`Argument`] or an [`ObjectID`] for use in [`WalrusPtbBuilder`].
pub enum ArgumentOrOwnedObject {
    /// An [`Argument`].
    Argument(Argument),
    /// An [`ObjectID`].
    Object(ObjectID),
}

impl From<Argument> for ArgumentOrOwnedObject {
    fn from(arg: Argument) -> Self {
        Self::Argument(arg)
    }
}

impl From<&Argument> for ArgumentOrOwnedObject {
    fn from(arg: &Argument) -> Self {
        Self::Argument(*arg)
    }
}

impl From<ObjectID> for ArgumentOrOwnedObject {
    fn from(obj: ObjectID) -> Self {
        Self::Object(obj)
    }
}

impl From<&ObjectID> for ArgumentOrOwnedObject {
    fn from(obj: &ObjectID) -> Self {
        Self::Object(*obj)
    }
}

/// A PTB builder for Walrus transactions.
pub struct WalrusPtbBuilder {
    pt_builder: ProgrammableTransactionBuilder,
    read_client: SuiReadClient,
    tx_wal_balance: u64,
    tx_sui_cost: u64,
    used_wal_coins: BTreeSet<ObjectID>,
    wal_coin_arg: Option<Argument>,
    sender_address: SuiAddress,
    args_to_consume: HashSet<Argument>,
}

impl Debug for WalrusPtbBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalrusPtbBuilder")
            .field("read_client", &self.read_client)
            .field("tx_wal_balance", &self.tx_wal_balance)
            .field("tx_sui_cost", &self.tx_sui_cost)
            .field("used_wal_coins", &self.used_wal_coins)
            .field("wal_coin_arg", &self.wal_coin_arg)
            .field("sender_address", &self.sender_address)
            .field("args_to_consume", &self.args_to_consume)
            .finish()
    }
}

impl WalrusPtbBuilder {
    /// Constructor for [`WalrusPtbBuilder`].
    pub fn new(read_client: SuiReadClient, sender_address: SuiAddress) -> Self {
        Self {
            pt_builder: ProgrammableTransactionBuilder::new(),
            read_client,
            tx_wal_balance: 0,
            tx_sui_cost: 0,
            used_wal_coins: BTreeSet::new(),
            wal_coin_arg: None,
            sender_address,
            args_to_consume: HashSet::new(),
        }
    }

    /// Fills up the WAL coin argument of the PTB to at least `min_balance`.
    ///
    /// This function merges additional coins if necessary and is a no-op if the current available
    /// balance (that has already been added to the PTB and hasn't been consumed yet) is larger than
    /// `min_balance`.
    ///
    /// # Errors
    ///
    /// Returns a [`SuiClientError::NoCompatibleWalCoins`] if no WAL coins with sufficient balance
    /// can be found.
    pub async fn fill_wal_balance(&mut self, min_balance: u64) -> SuiClientResult<()> {
        if min_balance <= self.tx_wal_balance {
            return Ok(());
        }
        let additional_balance = min_balance - self.tx_wal_balance;
        let mut coins = self
            .read_client
            .get_coins_with_total_balance(
                self.sender_address,
                CoinType::Wal,
                additional_balance,
                self.used_wal_coins.iter().cloned().collect(),
            )
            .await?;
        let mut added_balance = 0;
        let main_coin = if let Some(coin_arg) = self.wal_coin_arg {
            coin_arg
        } else {
            let coin = coins
                .pop()
                .ok_or_else(|| SuiClientError::NoCompatibleWalCoins)?;
            added_balance += coin.balance;
            let coin_arg = self.pt_builder.input(coin.object_ref().into())?;
            self.wal_coin_arg = Some(coin_arg);
            coin_arg
        };
        if !coins.is_empty() {
            let coin_args = coins
                .into_iter()
                .map(|coin| {
                    added_balance += coin.balance;
                    self.pt_builder.input(coin.object_ref().into())
                })
                .collect::<Result<Vec<_>, _>>()?;
            self.pt_builder
                .command(Command::MergeCoins(main_coin, coin_args));
        }
        self.tx_wal_balance += added_balance;
        Ok(())
    }

    fn reduce_wal_balance(&mut self, amount: u64) -> SuiClientResult<()> {
        if amount > self.tx_wal_balance {
            return Err(SuiClientError::Internal(anyhow::anyhow!(
                "trying to reduce WAL balance below 0"
            )));
        }
        self.tx_wal_balance -= amount;
        Ok(())
    }

    /// Adds a move call to the PTB.
    ///
    /// Always returns an [`Argument::Result`] if no error is returned.
    pub(crate) fn move_call(
        &mut self,
        function: FunctionTag<'_>,
        arguments: Vec<Argument>,
    ) -> SuiClientResult<Argument> {
        Ok(self.pt_builder.programmable_move_call(
            self.read_client.get_system_package_id(),
            Identifier::from_str(function.module)?,
            Identifier::from_str(function.name)?,
            function.type_params,
            arguments,
        ))
    }

    /// Adds a call to `reserve_space` to the `pt_builder` and returns the result [`Argument`].
    pub async fn reserve_space(
        &mut self,
        encoded_size: u64,
        epochs_ahead: EpochCount,
    ) -> SuiClientResult<Argument> {
        let price = self
            .storage_price_for_encoded_length(encoded_size, epochs_ahead)
            .await?;
        self.fill_wal_balance(price).await?;

        let reserve_arguments = vec![
            self.system_arg(Mutability::Mutable).await?,
            self.pt_builder.pure(encoded_size)?,
            self.pt_builder.pure(epochs_ahead)?,
            self.wal_coin_arg()?,
        ];
        let result_arg = self.move_call(contracts::system::reserve_space, reserve_arguments)?;
        self.reduce_wal_balance(price)?;
        self.add_result_to_be_consumed(result_arg);
        Ok(result_arg)
    }

    /// Adds a call to `register_blob` to the `pt_builder` and returns the result [`Argument`].
    pub async fn register_blob(
        &mut self,
        storage_resource: ArgumentOrOwnedObject,
        blob_metadata: BlobObjectMetadata,
        persistence: BlobPersistence,
    ) -> SuiClientResult<Argument> {
        let price = self
            .write_price_for_encoded_length(blob_metadata.encoded_size)
            .await?;
        self.fill_wal_balance(price).await?;

        let storage_resource_arg = self.argument_from_arg_or_obj(storage_resource).await?;

        let register_arguments = vec![
            self.system_arg(Mutability::Mutable).await?,
            storage_resource_arg,
            self.pt_builder.pure(blob_metadata.blob_id)?,
            self.pt_builder.pure(blob_metadata.root_hash.bytes())?,
            self.pt_builder.pure(blob_metadata.unencoded_size)?,
            self.pt_builder
                .pure(u8::from(blob_metadata.encoding_type))?,
            self.pt_builder.pure(persistence.is_deletable())?,
            self.wal_coin_arg()?,
        ];
        let result_arg = self.move_call(contracts::system::register_blob, register_arguments)?;
        self.reduce_wal_balance(price)?;
        self.mark_arg_as_consumed(&storage_resource_arg);
        self.add_result_to_be_consumed(result_arg);
        Ok(result_arg)
    }

    /// Adds a call to `certify_blob` to the `pt_builder`.
    pub async fn certify_blob(
        &mut self,
        blob_object: ArgumentOrOwnedObject,
        certificate: &ConfirmationCertificate,
    ) -> SuiClientResult<()> {
        #[cfg(not(feature = "walrus-mainnet"))]
        let signers = {
            let mut signers = certificate.signers.clone();
            signers.sort_unstable();
            signers
        };

        #[cfg(feature = "walrus-mainnet")]
        let signers = Self::signers_to_bitmap(&certificate.signers);

        let certify_args = vec![
            self.system_arg(Mutability::Immutable).await?,
            self.argument_from_arg_or_obj(blob_object).await?,
            self.pt_builder.pure(certificate.signature.as_bytes())?,
            self.pt_builder.pure(&signers)?,
            self.pt_builder.pure(&certificate.serialized_message)?,
        ];
        self.move_call(contracts::system::certify_blob, certify_args)?;
        Ok(())
    }

    #[cfg(feature = "walrus-mainnet")]
    fn signers_to_bitmap(signers: &[u16]) -> Vec<u8> {
        let mut bitmap = vec![0; signers.len().div_ceil(8)];
        for signer in signers {
            let byte_index = signer / 8;
            let bit_index = signer % 8;
            bitmap[byte_index as usize] |= 1 << bit_index;
        }
        bitmap
    }

    /// Adds a call to `certify_event_blob` to the `pt_builder`.
    pub async fn certify_event_blob(
        &mut self,
        blob_metadata: BlobObjectMetadata,
        storage_node_cap: ArgumentOrOwnedObject,
        ending_checkpoint_seq_num: u64,
        epoch: u32,
    ) -> SuiClientResult<()> {
        let arguments = vec![
            self.system_arg(Mutability::Mutable).await?,
            self.argument_from_arg_or_obj(storage_node_cap).await?,
            self.pt_builder.pure(blob_metadata.blob_id)?,
            self.pt_builder.pure(blob_metadata.root_hash.bytes())?,
            self.pt_builder.pure(blob_metadata.unencoded_size)?,
            self.pt_builder
                .pure(u8::from(blob_metadata.encoding_type))?,
            self.pt_builder.pure(ending_checkpoint_seq_num)?,
            self.pt_builder.pure(epoch)?,
        ];
        self.move_call(contracts::system::certify_event_blob, arguments)?;
        Ok(())
    }

    /// Adds a call to `delete_blob` to the `pt_builder` and returns the result [`Argument`].
    pub async fn delete_blob(
        &mut self,
        blob_object: ArgumentOrOwnedObject,
    ) -> SuiClientResult<Argument> {
        let blob_arg = self.argument_from_arg_or_obj(blob_object).await?;
        let delete_arguments = vec![self.system_arg(Mutability::Mutable).await?, blob_arg];
        let result_arg = self.move_call(contracts::system::delete_blob, delete_arguments)?;
        self.mark_arg_as_consumed(&blob_arg);
        self.add_result_to_be_consumed(result_arg);
        Ok(result_arg)
    }

    /// Adds a call to `burn` the blob to the `pt_builder`.
    pub async fn burn_blob(&mut self, blob_object: ArgumentOrOwnedObject) -> SuiClientResult<()> {
        let blob_arg = self.argument_from_arg_or_obj(blob_object).await?;
        self.move_call(contracts::blob::burn, vec![blob_arg])?;
        self.mark_arg_as_consumed(&blob_arg);
        Ok(())
    }

    /// Adds a transfer to the PTB. If the recipient is `None`, the sender address is used.
    pub async fn transfer<I: IntoIterator<Item = ArgumentOrOwnedObject>>(
        &mut self,
        recipient: Option<SuiAddress>,
        to_transfer: I,
    ) -> SuiClientResult<()> {
        let mut args = vec![];
        for arg_or_obj in to_transfer {
            args.push(self.argument_from_arg_or_obj(arg_or_obj).await?);
        }
        args.iter().for_each(|arg| self.mark_arg_as_consumed(arg));
        self.pt_builder
            .transfer_args(recipient.unwrap_or(self.sender_address), args);
        Ok(())
    }

    /// Transfers all outputs that have not been consumed yet by another command in the PTB.
    ///
    /// If the recipient is `None`, the sender address is used.
    pub async fn transfer_remaining_outputs(
        &mut self,
        recipient: Option<SuiAddress>,
    ) -> SuiClientResult<()> {
        if self.args_to_consume.is_empty() {
            return Ok(());
        }
        let args: Vec<_> = self.args_to_consume.iter().map(|arg| arg.into()).collect();
        self.transfer(recipient, args).await
    }

    /// Splits off `amount` from the gas coin, adds a call to `exchange_all_for_wal` to the PTB
    /// and merges the WAL coins into the payment coin of the PTB.
    pub async fn exchange_sui_for_wal(
        &mut self,
        exchange_id: ObjectID,
        amount: u64,
    ) -> SuiClientResult<()> {
        let exchange: WalExchange = self
            .read_client
            .sui_client
            .get_sui_object(exchange_id)
            .await?;
        let exchange_arg = self.pt_builder.obj(
            self.read_client
                .object_arg_for_shared_obj(exchange_id, Mutability::Mutable)
                .await?,
        )?;
        self.tx_sui_cost += amount;
        let amount_arg = self.pt_builder.pure(amount)?;

        let split_coin = self
            .pt_builder
            .command(Command::SplitCoins(Argument::GasCoin, vec![amount_arg]));

        let result_arg = self.move_call(
            contracts::wal_exchange::exchange_all_for_wal,
            vec![exchange_arg, split_coin],
        )?;
        let wal_amount = exchange.exchange_rate.sui_to_wal(amount);
        self.tx_wal_balance += wal_amount;
        match self.wal_coin_arg {
            Some(wal_coin_arg) => {
                self.pt_builder
                    .command(Command::MergeCoins(wal_coin_arg, vec![result_arg]));
            }
            None => {
                // This coin needs to be consumed by another function or transferred at the end.
                self.add_result_to_be_consumed(result_arg);
                self.wal_coin_arg = Some(result_arg);
            }
        }
        Ok(())
    }

    /// Adds a call to create a new exchange, funded with `amount` WAL, to the PTB.
    pub async fn create_and_fund_exchange(&mut self, amount: u64) -> SuiClientResult<Argument> {
        self.fill_wal_balance(amount).await?;
        let args = vec![self.wal_coin_arg()?, self.pt_builder.pure(amount)?];
        let result_arg = self.move_call(contracts::wal_exchange::new_funded, args)?;
        self.reduce_wal_balance(amount)?;
        self.add_result_to_be_consumed(result_arg);
        Ok(result_arg)
    }

    /// Adds a call to `invalidate_blob_id` to the PTB.
    pub async fn invalidate_blob_id(
        &mut self,
        certificate: &InvalidBlobCertificate,
    ) -> SuiClientResult<()> {
        #[cfg(not(feature = "walrus-mainnet"))]
        let signers = {
            let mut signers = certificate.signers.clone();
            signers.sort_unstable();
            signers
        };

        #[cfg(feature = "walrus-mainnet")]
        let signers = Self::signers_to_bitmap(&certificate.signers);

        let invalidate_args = vec![
            self.system_arg(Mutability::Immutable).await?,
            self.pt_builder.pure(certificate.signature.as_bytes())?,
            self.pt_builder.pure(&signers)?,
            self.pt_builder.pure(&certificate.serialized_message)?,
        ];
        self.move_call(contracts::system::invalidate_blob_id, invalidate_args)?;
        Ok(())
    }

    /// Adds a call to `epoch_sync_done` to the PTB.
    pub async fn epoch_sync_done(
        &mut self,
        storage_node_cap: ArgumentOrOwnedObject,
        epoch: Epoch,
    ) -> SuiClientResult<()> {
        let args = vec![
            self.staking_arg(Mutability::Mutable).await?,
            self.argument_from_arg_or_obj(storage_node_cap).await?,
            self.pt_builder.pure(epoch)?,
            self.pt_builder.obj(CLOCK_OBJECT_ARG)?,
        ];
        self.move_call(contracts::staking::epoch_sync_done, args)?;
        Ok(())
    }

    /// Adds a call to initiate epoch change to the PTB.
    pub async fn initiate_epoch_change(&mut self) -> SuiClientResult<()> {
        let args = vec![
            self.staking_arg(Mutability::Mutable).await?,
            self.system_arg(Mutability::Mutable).await?,
            self.pt_builder.obj(CLOCK_OBJECT_ARG)?,
        ];
        self.move_call(contracts::staking::initiate_epoch_change, args)?;
        Ok(())
    }

    /// Adds a call to `voting_end` to the PTB.
    pub async fn voting_end(&mut self) -> SuiClientResult<()> {
        let args = vec![
            self.staking_arg(Mutability::Mutable).await?,
            self.pt_builder.obj(CLOCK_OBJECT_ARG)?,
        ];
        self.move_call(contracts::staking::voting_end, args)?;
        Ok(())
    }

    /// Adds a call to `stake_with_pool` to the PTB.
    pub async fn stake_with_pool(
        &mut self,
        amount: u64,
        node_id: ObjectID,
    ) -> SuiClientResult<Argument> {
        self.fill_wal_balance(amount).await?;

        // Split the amount to stake from the main WAL coin.
        let split_main_coin_arg = self.wal_coin_arg()?;
        let split_amount_arg = self.pt_builder.pure(amount)?;
        let split_coin = self.pt_builder.command(Command::SplitCoins(
            split_main_coin_arg,
            vec![split_amount_arg],
        ));

        // Stake the split coin.
        let staking_args = vec![
            self.staking_arg(Mutability::Mutable).await?,
            split_coin,
            self.pt_builder.pure(node_id)?,
        ];
        let result_arg = self.move_call(contracts::staking::stake_with_pool, staking_args)?;
        self.reduce_wal_balance(amount)?;
        self.add_result_to_be_consumed(result_arg);
        Ok(result_arg)
    }

    /// Adds a call to `register_candidate` to the PTB.
    pub async fn register_candidate(
        &mut self,
        node_parameters: &NodeRegistrationParams,
        proof_of_possession: ProofOfPossession,
    ) -> SuiClientResult<Argument> {
        #[cfg(feature = "walrus-mainnet")]
        let node_metadata_arg = self.create_node_metadata(&node_parameters.metadata).await?;
        let args = vec![
            self.staking_arg(Mutability::Mutable).await?,
            self.pt_builder.pure(&node_parameters.name)?,
            self.pt_builder
                .pure(node_parameters.network_address.to_string())?,
            #[cfg(feature = "walrus-mainnet")]
            node_metadata_arg,
            self.pt_builder
                .pure(node_parameters.public_key.as_bytes())?,
            self.pt_builder
                .pure(node_parameters.network_public_key.as_bytes())?,
            self.pt_builder
                .pure(proof_of_possession.signature.as_bytes())?,
            self.pt_builder.pure(node_parameters.commission_rate)?,
            self.pt_builder.pure(node_parameters.storage_price)?,
            self.pt_builder.pure(node_parameters.write_price)?,
            self.pt_builder.pure(node_parameters.node_capacity)?,
        ];
        let result_arg = self.move_call(contracts::staking::register_candidate, args)?;
        self.add_result_to_be_consumed(result_arg);
        Ok(result_arg)
    }

    /// Adds a call to `create_node_metadata` to the PTB and returns the result [`Argument`].
    pub async fn create_node_metadata(
        &mut self,
        node_metadata: &NodeMetadata,
    ) -> SuiClientResult<Argument> {
        let args = vec![
            self.pt_builder.pure(&node_metadata.image_url)?,
            self.pt_builder
                .pure(node_metadata.project_url.to_string())?,
            self.pt_builder
                .pure(node_metadata.description.to_string())?,
        ];
        let result_arg = self.move_call(contracts::node_metadata::new, args)?;
        Ok(result_arg)
    }

    /// Sends `amount` WAL to `recipient`.
    pub async fn pay_wal(&mut self, recipient: SuiAddress, amount: u64) -> SuiClientResult<()> {
        self.fill_wal_balance(amount).await?;
        let amount_arg = self.pt_builder.pure(amount)?;
        let wal_coin_arg = self.wal_coin_arg()?;
        let split_coin = self
            .pt_builder
            .command(Command::SplitCoins(wal_coin_arg, vec![amount_arg]));
        self.transfer(Some(recipient), vec![split_coin.into()])
            .await?;
        self.reduce_wal_balance(amount)?;
        Ok(())
    }

    /// Transfers all remaining outputs and returns the PTB and the SUI balance needed in addition
    /// to the gas cost that needs to be covered by the gas coin.
    pub async fn finish(mut self) -> SuiClientResult<(ProgrammableTransaction, u64)> {
        self.transfer_remaining_outputs(None).await?;
        let sui_cost = self.tx_sui_cost;
        Ok((self.pt_builder.finish(), sui_cost))
    }

    async fn storage_price_for_encoded_length(
        &self,
        encoded_size: u64,
        epochs_ahead: EpochCount,
    ) -> SuiClientResult<u64> {
        Ok(price_for_encoded_length(
            encoded_size,
            self.read_client.storage_price_per_unit_size().await?,
            epochs_ahead,
        ))
    }

    async fn write_price_for_encoded_length(&self, encoded_size: u64) -> SuiClientResult<u64> {
        Ok(write_price_for_encoded_length(
            encoded_size,
            self.read_client.write_price_per_unit_size().await?,
        ))
    }

    async fn argument_from_arg_or_obj(
        &mut self,
        arg_or_obj: ArgumentOrOwnedObject,
    ) -> SuiClientResult<Argument> {
        match arg_or_obj {
            ArgumentOrOwnedObject::Argument(arg) => Ok(arg),
            ArgumentOrOwnedObject::Object(obj) => Ok(self
                .pt_builder
                .obj(self.read_client.object_arg_for_object(obj).await?)?),
        }
    }

    async fn system_arg(&mut self, mutable: Mutability) -> SuiClientResult<Argument> {
        Ok(self
            .pt_builder
            .obj(self.read_client.object_arg_for_system_obj(mutable).await?)?)
    }

    async fn staking_arg(&mut self, mutable: Mutability) -> SuiClientResult<Argument> {
        Ok(self
            .pt_builder
            .obj(self.read_client.object_arg_for_staking_obj(mutable).await?)?)
    }

    fn wal_coin_arg(&mut self) -> SuiClientResult<Argument> {
        self.wal_coin_arg
            .ok_or_else(|| SuiClientError::NoCompatibleWalCoins)
    }

    fn mark_arg_as_consumed(&mut self, arg: &Argument) {
        self.args_to_consume.remove(arg);
    }

    fn add_result_to_be_consumed(&mut self, arg: Argument) {
        self.args_to_consume.insert(arg);
    }
}
