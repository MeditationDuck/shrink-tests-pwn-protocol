import "core/lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";
import { IERC5646 } from "pwn/interfaces/IERC5646.sol";

contract ERC721Mock is ERC721, IERC5646 {
    enum State {
        Default,
        Extended
    }
    mapping(uint256 => State) public states;

    constructor(string memory name_, string memory symbol_) ERC721(name_, symbol_) {}

    function mint(address to, uint256 tokenId) public {
        _mint(to, tokenId);
    }

    function setState(uint256 tokenId, State state) public {
        states[tokenId] = state;
    }

    function getStateFingerprint(uint256 tokenId) external view returns (bytes32) {
        return keccak256(abi.encode(states[tokenId]));
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return super.supportsInterface(interfaceId) ||
            interfaceId == type(IERC5646).interfaceId;
    }
}
