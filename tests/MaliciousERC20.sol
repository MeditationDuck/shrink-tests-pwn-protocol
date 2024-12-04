import "core/lib/openzeppelin-contracts/contracts/token/ERC20/extensions/ERC20Permit.sol";

contract MaliciousERC20 is ERC20Permit {
    address public target;
    bytes public payload;

    constructor() ERC20("Malicious", "MAL") ERC20Permit("Malicious") {}

    function setTarget(address _target, bytes memory _payload) public {
        target = _target;
        payload = _payload;

        this.approve(target, type(uint256).max);
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public override {
        super.permit(owner, spender, value, deadline, v, r, s);
        (bool success, ) = target.call(payload);
        require(success, "MaliciousERC20: target call failed");
    }
}
