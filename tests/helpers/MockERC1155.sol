// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin/token/ERC1155/ERC1155.sol";

contract MockERC1155 is ERC1155 {
    constructor() ERC1155("https://mock.uri/") {}

    /// @notice Mint tokens to an address
    /// @param to Address to mint tokens to
    /// @param id Token ID to mint
    /// @param amount Amount of tokens to mint
    /// @param data Additional data to pass to receiver
    function mint(address to, uint256 id, uint256 amount, bytes memory data) external {
        _mint(to, id, amount, data);
    }

    /// @notice Batch mint tokens to an address
    /// @param to Address to mint tokens to
    /// @param ids Array of token IDs to mint
    /// @param amounts Array of amounts to mint
    /// @param data Additional data to pass to receiver
    function mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) external {
        _mintBatch(to, ids, amounts, data);
    }

    /// @notice Burn tokens from an address
    /// @param from Address to burn tokens from
    /// @param id Token ID to burn
    /// @param amount Amount of tokens to burn
    function burn(address from, uint256 id, uint256 amount) external {
        _burn(from, id, amount);
    }

    /// @notice Batch burn tokens from an address
    /// @param from Address to burn tokens from
    /// @param ids Array of token IDs to burn
    /// @param amounts Array of amounts to burn
    function burnBatch(
        address from,
        uint256[] memory ids,
        uint256[] memory amounts
    ) external {
        _burnBatch(from, ids, amounts);
    }
}