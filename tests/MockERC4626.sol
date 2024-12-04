import "core/lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC4626.sol";
import "core/lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract MockERC4626 is ERC4626 {
    constructor(address _asset) ERC4626(IERC20(_asset)) ERC20("MockERC4626", "M4626") {}
}
