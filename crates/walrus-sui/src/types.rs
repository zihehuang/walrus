// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Walrus move type bindings. Replicates the move types in Rust.
//!

use std::{
    fmt::Display,
    net::{SocketAddr, ToSocketAddrs},
    num::NonZeroU16,
    str::FromStr,
    vec,
};

use anyhow::{anyhow, bail};
use fastcrypto::traits::ToFromBytes;
use move_core_types::u256::U256;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sui_sdk::rpc_types::{SuiEvent, SuiMoveStruct, SuiMoveValue};
use sui_types::{base_types::ObjectID, event::EventID};
use thiserror::Error;
use walrus_core::{ensure, BlobId, EncodingType, Epoch, PublicKey, ShardIndex};

use crate::{
    contracts::{self, AssociatedContractStruct, AssociatedSuiEvent, StructTag},
    utils::{
        blob_id_from_u256,
        get_dynamic_field,
        sui_move_convert_numeric_vec,
        sui_move_convert_struct_vec,
    },
};
/// Sui object for storage resources
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StorageResource {
    /// Object id of the Sui object
    pub id: ObjectID,
    /// The start epoch of the resource (inclusive)
    pub start_epoch: Epoch,
    /// The end epoch of the resource (exclusive)
    pub end_epoch: Epoch,
    /// The total amount of reserved storage
    pub storage_size: u64,
}

impl TryFrom<&SuiMoveStruct> for StorageResource {
    type Error = anyhow::Error;

    fn try_from(sui_move_struct: &SuiMoveStruct) -> Result<Self, Self::Error> {
        let id = get_dynamic_objectid_field!(sui_move_struct)?;
        let start_epoch = get_dynamic_u64_field!(sui_move_struct, "start_epoch")?;
        let end_epoch = get_dynamic_u64_field!(sui_move_struct, "end_epoch")?;
        let storage_size = get_dynamic_u64_field!(sui_move_struct, "storage_size")?;
        Ok(Self {
            id,
            start_epoch,
            end_epoch,
            storage_size,
        })
    }
}

impl TryFrom<SuiMoveStruct> for StorageResource {
    type Error = anyhow::Error;

    fn try_from(sui_move_struct: SuiMoveStruct) -> Result<Self, Self::Error> {
        Self::try_from(&sui_move_struct)
    }
}

impl AssociatedContractStruct for StorageResource {
    const CONTRACT_STRUCT: StructTag<'static> = contracts::storage_resource::Storage;
}

/// Sui object for a blob
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Blob {
    /// Object id of the Sui object
    pub id: ObjectID,
    /// The epoch in which the blob has been registered
    pub stored_epoch: Epoch,
    /// The blob Id
    pub blob_id: BlobId,
    /// The (unencoded) size of the blob
    pub size: u64,
    /// The erasure coding type used for the blob
    pub erasure_code_type: EncodingType,
    /// The epoch in which the blob was first certified, `None` if the blob is uncertified
    pub certified: Option<Epoch>,
    /// The [`StorageResource`] used to store the blob
    pub storage: StorageResource,
}

impl TryFrom<&SuiMoveStruct> for Blob {
    type Error = anyhow::Error;

    fn try_from(sui_move_struct: &SuiMoveStruct) -> Result<Self, Self::Error> {
        let id = get_dynamic_objectid_field!(sui_move_struct)?;

        let stored_epoch = get_dynamic_u64_field!(sui_move_struct, "stored_epoch")?;
        let blob_id = blob_id_from_u256(
            get_dynamic_field!(sui_move_struct, "blob_id", SuiMoveValue::String)?
                .parse::<U256>()?,
        );
        let size = get_dynamic_u64_field!(sui_move_struct, "size")?;
        let erasure_code_type = EncodingType::try_from(u8::try_from(get_dynamic_field!(
            sui_move_struct,
            "erasure_code_type",
            SuiMoveValue::Number
        )?)?)?;
        // `SuiMoveValue::Option` seems to be replaced with `SuiMoveValue::String` directly
        // if it is not `None`.
        let certified = get_dynamic_field!(sui_move_struct, "certified", SuiMoveValue::String)
            .and_then(|s| Ok(Some(s.parse()?)))
            .or_else(|_| {
                match get_dynamic_field!(sui_move_struct, "certified", SuiMoveValue::Option)?
                    .as_ref()
                {
                    None => Ok(None),
                    // Below would be the expected behaviour in the not-None-case, so we capture
                    // this nevertheless
                    Some(SuiMoveValue::String(s)) => Ok(Some(s.parse()?)),
                    Some(smv) => Err(anyhow!("unexpected type for field `certified`: {}", smv)),
                }
            })?;
        let storage = StorageResource::try_from(get_dynamic_field!(
            sui_move_struct,
            "storage",
            SuiMoveValue::Struct
        )?)?;
        Ok(Self {
            id,
            stored_epoch,
            blob_id,
            size,
            erasure_code_type,
            certified,
            storage,
        })
    }
}

impl TryFrom<SuiMoveStruct> for Blob {
    type Error = anyhow::Error;

    fn try_from(sui_move_struct: SuiMoveStruct) -> Result<Self, Self::Error> {
        Self::try_from(&sui_move_struct)
    }
}

impl AssociatedContractStruct for Blob {
    const CONTRACT_STRUCT: StructTag<'static> = contracts::blob::Blob;
}

/// Network address consisting of host name or ip and port
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct NetworkAddress {
    /// Host name or ip address
    pub host: String,
    /// Port
    pub port: u16,
}

impl FromStr for NetworkAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((host, port)) = s.split_once(':') else {
            bail!("invalid network address")
        };
        let port = port.parse()?;
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

impl ToSocketAddrs for NetworkAddress {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        (self.host.as_str(), self.port).to_socket_addrs()
    }
}

impl Display for NetworkAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl From<SocketAddr> for NetworkAddress {
    fn from(value: SocketAddr) -> Self {
        Self {
            host: value.ip().to_string(),
            port: value.port(),
        }
    }
}

/// Sui type for storage node
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct StorageNode {
    /// Name of the storage node
    pub name: String,
    /// The network address of the storage node
    pub network_address: NetworkAddress,
    /// The public key of the storage node
    pub public_key: PublicKey,
    /// The indices of the shards held by the storage node
    pub shard_ids: Vec<ShardIndex>,
}

impl TryFrom<&SuiMoveStruct> for StorageNode {
    type Error = anyhow::Error;

    fn try_from(sui_move_struct: &SuiMoveStruct) -> Result<Self, Self::Error> {
        let name = get_dynamic_field!(sui_move_struct, "name", SuiMoveValue::String)?;
        let network_address =
            get_dynamic_field!(sui_move_struct, "network_address", SuiMoveValue::String)?
                .parse()?;
        let public_key_struct =
            get_dynamic_field!(sui_move_struct, "public_key", SuiMoveValue::Struct)?;
        let public_key = PublicKey::from_bytes(&sui_move_convert_numeric_vec(
            get_dynamic_field!(public_key_struct, "bytes", SuiMoveValue::Vector)?,
        )?)?;
        let shard_ids = sui_move_convert_numeric_vec(get_dynamic_field!(
            sui_move_struct,
            "shard_ids",
            SuiMoveValue::Vector
        )?)?
        .into_iter()
        .map(ShardIndex)
        .collect();
        Ok(Self {
            name,
            network_address,
            public_key,
            shard_ids,
        })
    }
}

impl TryFrom<SuiMoveStruct> for StorageNode {
    type Error = anyhow::Error;

    fn try_from(sui_move_struct: SuiMoveStruct) -> Result<Self, Self::Error> {
        Self::try_from(&sui_move_struct)
    }
}

// TODO(giac): remove if unused in #243
impl Display for StorageNode {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "node-pk: {}", self.public_key)
    }
}

impl AssociatedContractStruct for StorageNode {
    const CONTRACT_STRUCT: StructTag<'static> = contracts::storage_node::StorageNodeInfo;
}

/// Sui type for storage committee
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Committee {
    /// The members of the committee
    members: Vec<StorageNode>,
    /// The current epoch
    pub epoch: Epoch,
    /// The number of shards held by the committee
    n_shards: NonZeroU16,
}

impl Committee {
    /// Create a new committee for `epoch` consisting of `members`. `members` must contain at
    /// least one storage node holding at least one shard.
    pub fn new(members: Vec<StorageNode>, epoch: Epoch) -> Result<Self, InvalidCommittee> {
        let n_shards = members
            .iter()
            .fold(0, |acc, node| node.shard_ids.len() + acc);
        let n_shards = u16::try_from(n_shards).map_err(|_| InvalidCommittee::TooManyShards)?;
        let n_shards = NonZeroU16::new(n_shards).ok_or(InvalidCommittee::EmptyCommittee)?;
        Ok(Self {
            members,
            epoch,
            n_shards,
        })
    }

    /// Checks if the number is large enough to reach a quorum (`n_shards - f`) where `f`
    /// is the maximum number of faulty shards, given `n_shards`.
    #[inline]
    pub fn is_quorum(&self, num: usize) -> bool {
        // Given `n_shards == 3g + 1` with a possibly fractionary `g`, this expression checks
        // that `num >= 2g + 1`. This in turn always implies that `num >= n_shards - f`, where
        // `f == floor(g)` is the maximum number of faulty shards.
        3 * num >= 2 * self.n_shards.get() as usize + 1
    }

    /// Return the shards handed by the specified storage node, based on its index in the committee
    /// list.
    pub fn shards_for_node(&self, node_id: usize) -> Vec<ShardIndex> {
        self.members
            .get(node_id)
            .map(|node| node.shard_ids.clone())
            .unwrap_or_default()
    }

    /// Return the total number of shards in the committee.
    pub fn n_shards(&self) -> NonZeroU16 {
        self.n_shards
    }

    /// Returns the members of the committee
    pub fn members(&self) -> &[StorageNode] {
        &self.members
    }
}

impl TryFrom<&SuiMoveStruct> for Committee {
    type Error = anyhow::Error;

    fn try_from(sui_move_struct: &SuiMoveStruct) -> Result<Self, Self::Error> {
        let epoch = get_dynamic_u64_field!(sui_move_struct, "epoch")?;
        let bls_committee_struct =
            get_dynamic_field!(sui_move_struct, "bls_committee", SuiMoveValue::Struct)?;
        let members = sui_move_convert_struct_vec(get_dynamic_field!(
            bls_committee_struct,
            "members",
            SuiMoveValue::Vector
        )?)?;
        let committee = Self::new(members, epoch)?;
        let n_shards: u16 =
            get_dynamic_field!(bls_committee_struct, "n_shards", SuiMoveValue::Number)?
                .try_into()?;
        ensure!(
            committee.n_shards.get() == n_shards,
            "struct n_shards does not correspond to actual number of shards"
        );
        Ok(committee)
    }
}

impl TryFrom<SuiMoveStruct> for Committee {
    type Error = anyhow::Error;

    fn try_from(sui_move_struct: SuiMoveStruct) -> Result<Self, Self::Error> {
        Self::try_from(&sui_move_struct)
    }
}

impl AssociatedContractStruct for Committee {
    const CONTRACT_STRUCT: StructTag<'static> = contracts::committee::Committee;
}

/// Error returned for an invalid conversion to an EpochStatus.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("the provided value is not a valid EpochStatus")]
pub struct InvalidEpochStatus;

/// Error returned when trying to create a committee with no shards.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InvalidCommittee {
    #[error("too many shards for a valid committee")]
    /// Error resulting if the total number of shards in the committee exceeds u16::MAX.
    TooManyShards,
    #[error("trying to create an empty committee")]
    /// Error resulting if the committee contains no shards.
    EmptyCommittee,
}

/// The status of the epoch
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum EpochStatus {
    /// A sufficient number of the new epoch shards have been transferred
    Done = 0,
    /// The storage nodes are currently transferring shards to the new committee
    Sync = 1,
}

impl From<EpochStatus> for u8 {
    fn from(value: EpochStatus) -> Self {
        value as u8
    }
}

impl TryFrom<u8> for EpochStatus {
    type Error = InvalidEpochStatus;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EpochStatus::Done),
            1 => Ok(EpochStatus::Sync),
            _ => Err(InvalidEpochStatus),
        }
    }
}

/// Sui type for system object
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SystemObject {
    /// Object id of the Sui object
    pub id: ObjectID,
    /// The current committee of the Walrus instance
    pub current_committee: Committee,
    /// The status of the epoch
    pub epoch_status: EpochStatus,
    /// Total storage capacity of the Walrus instance
    pub total_capacity_size: u64,
    /// Used storage capacity of the Walrus instance
    pub used_capacity_size: u64,
    /// The price per unit of storage per epoch
    pub price_per_unit_size: u64,
    /// The object ID of the table storing past committees
    pub past_committees_object: ObjectID,
}

impl TryFrom<&SuiMoveStruct> for SystemObject {
    type Error = anyhow::Error;

    fn try_from(sui_move_struct: &SuiMoveStruct) -> Result<Self, Self::Error> {
        let id = get_dynamic_objectid_field!(sui_move_struct)?;
        let current_committee =
            get_dynamic_field!(sui_move_struct, "current_committee", SuiMoveValue::Struct)?
                .try_into()?;
        let epoch_status = u8::try_from(get_dynamic_field!(
            sui_move_struct,
            "epoch_status",
            SuiMoveValue::Number
        )?)?
        .try_into()?;
        let total_capacity_size = get_dynamic_u64_field!(sui_move_struct, "total_capacity_size")?;
        let used_capacity_size = get_dynamic_u64_field!(sui_move_struct, "used_capacity_size")?;
        let price_per_unit_size = get_dynamic_u64_field!(sui_move_struct, "price_per_unit_size")?;
        let past_committees_object = get_dynamic_objectid_field!(get_dynamic_field!(
            sui_move_struct,
            "past_committees",
            SuiMoveValue::Struct
        )?)?;
        Ok(Self {
            id,
            current_committee,
            epoch_status,
            total_capacity_size,
            used_capacity_size,
            price_per_unit_size,
            past_committees_object,
        })
    }
}

impl TryFrom<SuiMoveStruct> for SystemObject {
    type Error = anyhow::Error;

    fn try_from(sui_move_struct: SuiMoveStruct) -> Result<Self, Self::Error> {
        Self::try_from(&sui_move_struct)
    }
}

impl AssociatedContractStruct for SystemObject {
    const CONTRACT_STRUCT: StructTag<'static> = contracts::system::System;
}

// Events

fn field_map_from_event(sui_event: &SuiEvent) -> anyhow::Result<&Map<String, Value>> {
    let Value::Object(object) = &sui_event.parsed_json else {
        return Err(anyhow!("Event is not of type object"));
    };
    Ok(object)
}

fn ensure_event_type(sui_event: &SuiEvent, struct_tag: &StructTag) -> anyhow::Result<()> {
    ensure!(
        sui_event.type_.name.as_str() == struct_tag.name
            && sui_event.type_.module.as_str() == struct_tag.module,
        "event is not of type {:?}",
        struct_tag
    );
    Ok(())
}

/// Sui event that blob has been registered
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRegistered {
    /// The epoch in which the blob has been registered
    pub epoch: Epoch,
    /// The blob Id
    pub blob_id: BlobId,
    /// The (unencoded) size of the blob
    pub size: u64,
    /// The erasure coding type used for the blob
    pub erasure_code_type: EncodingType,
    /// The end epoch of the associated storage resource (exclusive)
    pub end_epoch: Epoch,
    /// The ID of the event
    pub event_id: EventID,
}

impl TryFrom<SuiEvent> for BlobRegistered {
    type Error = anyhow::Error;

    fn try_from(sui_event: SuiEvent) -> Result<Self, Self::Error> {
        ensure_event_type(&sui_event, &Self::EVENT_STRUCT)?;
        let object = field_map_from_event(&sui_event)?;

        let epoch = get_u64_field_from_event!(object, "epoch")?;

        let blob_id =
            blob_id_from_u256(get_field_from_event!(object, "blob_id", Value::String)?.parse()?);
        let size = get_u64_field_from_event!(object, "size")?;
        let erasure_code_type = EncodingType::try_from(u8::try_from(
            get_field_from_event!(object, "erasure_code_type", Value::Number)?
                .as_u64()
                .ok_or_else(|| anyhow!("value is non-integer"))?,
        )?)?;
        let end_epoch = get_u64_field_from_event!(object, "end_epoch")?;

        Ok(Self {
            epoch,
            blob_id,
            size,
            erasure_code_type,
            end_epoch,
            event_id: sui_event.id,
        })
    }
}

impl AssociatedSuiEvent for BlobRegistered {
    const EVENT_STRUCT: StructTag<'static> = contracts::blob_events::BlobRegistered;
}

/// Sui event that blob has been certified
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobCertified {
    /// The epoch in which the blob was certified
    pub epoch: Epoch,
    /// The blob Id
    pub blob_id: BlobId,
    /// The end epoch of the associated storage resource (exclusive)
    pub end_epoch: Epoch,
    /// The ID of the event
    pub event_id: EventID,
}

impl TryFrom<SuiEvent> for BlobCertified {
    type Error = anyhow::Error;

    fn try_from(sui_event: SuiEvent) -> Result<Self, Self::Error> {
        ensure_event_type(&sui_event, &Self::EVENT_STRUCT)?;
        let object = field_map_from_event(&sui_event)?;

        let epoch = get_u64_field_from_event!(object, "epoch")?;
        let blob_id =
            blob_id_from_u256(get_field_from_event!(object, "blob_id", Value::String)?.parse()?);
        let end_epoch = get_u64_field_from_event!(object, "end_epoch")?;

        Ok(Self {
            epoch,
            blob_id,
            end_epoch,
            event_id: sui_event.id,
        })
    }
}

impl AssociatedSuiEvent for BlobCertified {
    const EVENT_STRUCT: StructTag<'static> = contracts::blob_events::BlobCertified;
}

/// Sui event that a blob id is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBlobID {
    /// The epoch in which the blob was marked as invalid
    pub epoch: Epoch,
    /// The blob Id
    pub blob_id: BlobId,
    /// The ID of the event
    pub event_id: EventID,
}

impl TryFrom<SuiEvent> for InvalidBlobID {
    type Error = anyhow::Error;

    fn try_from(sui_event: SuiEvent) -> Result<Self, Self::Error> {
        ensure_event_type(&sui_event, &Self::EVENT_STRUCT)?;
        let object = field_map_from_event(&sui_event)?;

        let epoch = get_u64_field_from_event!(object, "epoch")?;
        let blob_id =
            blob_id_from_u256(get_field_from_event!(object, "blob_id", Value::String)?.parse()?);

        Ok(Self {
            epoch,
            blob_id,
            event_id: sui_event.id,
        })
    }
}

impl AssociatedSuiEvent for InvalidBlobID {
    const EVENT_STRUCT: StructTag<'static> = contracts::blob_events::InvalidBlobID;
}

/// Enum to wrap blob events
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobEvent {
    /// A registration event
    Registered(BlobRegistered),
    /// A certification event
    Certified(BlobCertified),
    /// An invalid blob id event
    InvalidBlobID(InvalidBlobID),
}

impl From<BlobRegistered> for BlobEvent {
    fn from(value: BlobRegistered) -> Self {
        Self::Registered(value)
    }
}

impl From<BlobCertified> for BlobEvent {
    fn from(value: BlobCertified) -> Self {
        Self::Certified(value)
    }
}

impl From<InvalidBlobID> for BlobEvent {
    fn from(value: InvalidBlobID) -> Self {
        Self::InvalidBlobID(value)
    }
}

impl BlobEvent {
    /// Returns the blob id contained in the wrapped event
    pub fn blob_id(&self) -> BlobId {
        match self {
            BlobEvent::Registered(event) => event.blob_id,
            BlobEvent::Certified(event) => event.blob_id,
            BlobEvent::InvalidBlobID(event) => event.blob_id,
        }
    }

    /// Returns the event id of the wrapped event
    pub fn event_id(&self) -> EventID {
        match self {
            BlobEvent::Registered(event) => event.event_id,
            BlobEvent::Certified(event) => event.event_id,
            BlobEvent::InvalidBlobID(event) => event.event_id,
        }
    }
}

impl TryFrom<SuiEvent> for BlobEvent {
    type Error = anyhow::Error;

    fn try_from(value: SuiEvent) -> Result<Self, Self::Error> {
        match (&value.type_).into() {
            contracts::blob_events::BlobRegistered => Ok(BlobEvent::Registered(value.try_into()?)),
            contracts::blob_events::BlobCertified => Ok(BlobEvent::Certified(value.try_into()?)),
            contracts::blob_events::InvalidBlobID => {
                Ok(BlobEvent::InvalidBlobID(value.try_into()?))
            }
            _ => Err(anyhow!("could not convert event: {}", value)),
        }
    }
}
