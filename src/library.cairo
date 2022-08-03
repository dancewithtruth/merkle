%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.cairo_keccak.keccak import keccak_felts, finalize_keccak
from starkware.starknet.common.cairo_builtins import (
    BitwiseBuiltin,
    HashBuiltin,
)
from starkware.cairo.common.uint256 import Uint256

#
# Storage variables
#

@storage_var
func merkle_root() -> (res : felt):
end

namespace Merkle:
    #
    # Initializer
    #

    func initializer{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
        }(merkle_root_ : felt):
        let (initialized) = merkle_root.read()
        with_attr error_message("Merkle: contract already initialized"):
            assert merkle_root = FALSE
        end
        merkle_root.write(value=merkle_root_)
        return ()
    end

    func assert_valid_leaf{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        bitwise_ptr : BitwiseBuiltin*, 
        range_check_ptr
        }(proof_elements : Uint256*, num_elements : felt, node : Uint256):
        let (root) = merkle_root.read()
        let (computed_hash : Uint256) = compute_hash_from_proof(proof_elements=proof_elements, num_elements=num_elements, node=node)
        assert root = computed_hash
        return ()
    end
end

#
# Internal functions
#

# Recursive function...might need to use dict to re-write values
func compute_hash_from_proof{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    bitwise_ptr : BitwiseBuiltin*, 
    range_check_ptr
    }(proof_elements : Uint256*, num_elements : felt, node : Uint256) -> (computed_hash : Uint256):
    alloc_locals
    let current_hash = node

    if num_elements == 0:
        return (computed_hash=current_hash)
    end

    let (keccak_ptr : felt*) = alloc()
    local keccak_ptr_start : felt* = keccak_ptr
    local elements = alloc()

    # #pseudocode
    # if current_hash < proof_elements[0]:
    #     assert elements[0] = current_hash
    #     assert elements[1] = proof_elements
    # else:
    #     assert elements[0] = proof_elements
    #     assert elements[1] = current_hash
    # end

    let (keccak_hash) = keccak_felts{keccak_ptr=keccak_ptr}(n_elements=2, elements=proof_elements)
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr)

    #Rebind reference
    let current_hash = keccak_hash

    return compute_hash_from_proof(
        proof_elements=proof_elements + 1,
        num_elements=num_elements - 1,
        node=current_hash
    )
end

