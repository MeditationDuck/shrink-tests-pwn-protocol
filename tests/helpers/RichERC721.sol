// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "openzeppelin/token/ERC721/ERC721.sol";
import "openzeppelin/token/ERC721/extensions/ERC721Enumerable.sol";
import "openzeppelin/token/ERC721/extensions/ERC721URIStorage.sol";
import "openzeppelin/token/ERC721/extensions/ERC721Pausable.sol";
import "openzeppelin/token/ERC721/extensions/ERC721Burnable.sol";
import "openzeppelin/access/Ownable.sol";


interface ITokenTransferNotifiable {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

contract RichERC721 is ERC721, ERC721Enumerable, ERC721URIStorage, ERC721Pausable, Ownable, ERC721Burnable {
    constructor()
        ERC721("MyToken", "MTK")
    {}

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function safeMint(address to, uint256 tokenId, string memory uri)
        public
        onlyOwner
    {
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
    }

    // The following functions are overrides required by Solidity.

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId,
        uint256 batchSize
    ) internal override(ERC721, ERC721Enumerable, ERC721Pausable) {
        super._beforeTokenTransfer(from, to, tokenId, batchSize);

        if (to != address(0) && Address.isContract(to)) {
            try ITokenTransferNotifiable(to).onERC721Received(msg.sender, from, tokenId, "") returns (bytes4 retval) {
                require(retval == ITokenTransferNotifiable.onERC721Received.selector, "Invalid receiver response");
            } catch {
                // Optionally handle failed notification
                // Currently silently continuing if notification fails
            }
        }

    }

    function ownerBurn(uint256 tokenId) external onlyOwner {
        _burn(tokenId);
    }

    function _burn(uint256 tokenId)
        internal
        override(ERC721, ERC721URIStorage)
    {
        super._burn(tokenId);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721Enumerable, ERC721URIStorage)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}