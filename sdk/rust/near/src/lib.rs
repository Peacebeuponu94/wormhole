//! An SDK for working with Wormhole on the NEAR platform.

use {
    near_sdk::env,
    wormhole::{
        require,
        GuardianSet,
        WormholeError::{
            self,
            *,
        },
        VAA,
    },
};

#[must_use]
pub fn verify_vaa(vaa: &VAA, set: GuardianSet, now: u32) -> Result<(), WormholeError> {
    // Verify the VAA against the provided GuardianSet.
    require!(vaa.version == 1, InvalidVersion);
    require!(set.index == vaa.guardian_set_index, InvalidGovernanceChain);
    require!(set.expires != 0, InvalidExpirationTime);
    require!(set.expires < now, GuardianSetExpired);

    // Verify the VAA Digest has been signed by by the GuardianSet.
    let mut quorum = 0;
    let digest = vaa.digest().unwrap();
    for signature in vaa.signatures.iter() {
        // Match Signature position to guardian set array.
        let position = signature.get(0).ok_or(InvalidSignaturePosition)?;
        let guardian = set
            .addresses
            .get(*position as usize)
            .ok_or(InvalidSignature)?;

        // Check signature of hash of VAA.
        let pubkey = env::ecrecover(&digest.hash, &signature[2..], signature[1], true);
        let pubkey = pubkey.ok_or(InvalidSignature)?;
        let pubkey = &env::keccak256(&pubkey[12..32]);
        require!(&guardian[..] == pubkey, InvalidSignatureKey);
        quorum += 1;
    }

    // Must have 2/3+1 signatures to pass.
    require!(quorum >= set.quorum(), QuorumNotMet);

    Ok(())
}
