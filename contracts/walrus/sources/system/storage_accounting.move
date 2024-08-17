// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module walrus::storage_accounting;

use sui::{balance::{Self, Balance}, sui::SUI};

// Errors
const EIndexOutOfBounds: u64 = 3;

/// Holds information about a future epoch, namely how much
/// storage needs to be reclaimed and the rewards to be distributed.
public struct FutureAccounting has store {
    epoch: u64,
    storage_to_reclaim: u64,
    rewards_to_distribute: Balance<SUI>,
}

/// Constructor for FutureAccounting
public(package) fun new_future_accounting(
    epoch: u64,
    storage_to_reclaim: u64,
    rewards_to_distribute: Balance<SUI>,
): FutureAccounting {
    FutureAccounting { epoch, storage_to_reclaim, rewards_to_distribute }
}

/// Accessor for epoch, read-only
public(package) fun epoch(accounting: &FutureAccounting): u64 {
    *&accounting.epoch
}

/// Accessor for storage_to_reclaim, mutable.
public(package) fun storage_to_reclaim(accounting: &FutureAccounting): u64 {
    accounting.storage_to_reclaim
}

/// Increase storage to reclaim
public(package) fun increase_storage_to_reclaim(accounting: &mut FutureAccounting, amount: u64) {
    accounting.storage_to_reclaim = accounting.storage_to_reclaim + amount;
}

/// Accessor for rewards_to_distribute, mutable.
public(package) fun rewards_balance(accounting: &mut FutureAccounting): &mut Balance<SUI> {
    &mut accounting.rewards_to_distribute
}

/// Destructor for FutureAccounting, when empty.
public(package) fun delete_empty_future_accounting(self: FutureAccounting) {
    self.unwrap_balance().destroy_zero()
}

public(package) fun unwrap_balance(self: FutureAccounting): Balance<SUI> {
    let FutureAccounting {
        rewards_to_distribute,
        ..,
    } = self;
    rewards_to_distribute
}

#[test_only]
public(package) fun burn_for_testing(self: FutureAccounting) {
    let FutureAccounting {
        rewards_to_distribute,
        ..,
    } = self;

    rewards_to_distribute.destroy_for_testing();
}

/// A ring buffer holding future accounts for a continuous range of epochs.
public struct FutureAccountingRingBuffer has store {
    current_index: u64,
    length: u64,
    ring_buffer: vector<FutureAccounting>,
}

/// Constructor for FutureAccountingRingBuffer
public(package) fun ring_new(length: u64): FutureAccountingRingBuffer {
    let ring_buffer = vector::tabulate!(
        length,
        |epoch| FutureAccounting {
            epoch,
            storage_to_reclaim: 0,
            rewards_to_distribute: balance::zero(),
        },
    );

    FutureAccountingRingBuffer { current_index: 0, length: length, ring_buffer: ring_buffer }
}

/// Lookup an entry a number of epochs in the future.
public(package) fun ring_lookup_mut(
    self: &mut FutureAccountingRingBuffer,
    epochs_in_future: u64,
): &mut FutureAccounting {
    // Check for out-of-bounds access.
    assert!(epochs_in_future < self.length, EIndexOutOfBounds);

    let actual_index = (epochs_in_future + self.current_index) % self.length;
    &mut self.ring_buffer[actual_index]
}

public(package) fun ring_pop_expand(self: &mut FutureAccountingRingBuffer): FutureAccounting {
    // Get current epoch
    let current_index = self.current_index;
    let current_epoch = self.ring_buffer[current_index].epoch;

    // Expand the ring buffer
    self
        .ring_buffer
        .push_back(FutureAccounting {
            epoch: current_epoch + self.length,
            storage_to_reclaim: 0,
            rewards_to_distribute: balance::zero(),
        });

    // Now swap remove the current element and increment the current_index
    let accounting = self.ring_buffer.swap_remove(current_index);
    self.current_index = (current_index + 1) % self.length;

    accounting
}
