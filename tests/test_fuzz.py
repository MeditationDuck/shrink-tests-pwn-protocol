import logging
import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, Union, Tuple, Optional, NamedTuple

from ordered_set import OrderedSet
from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.core.src.hub.PWNHub import PWNHub
from pytypes.core.src.config.PWNConfig import PWNConfig
from pytypes.core.src.loan.token.PWNLOAN import PWNLOAN
from pytypes.core.src.nonce.PWNRevokedNonce import PWNRevokedNonce
from pytypes.core.lib.MultiToken.src.MultiToken import MultiToken
from pytypes.core.lib.MultiToken.src.MultiTokenCategoryRegistry import (
    MultiTokenCategoryRegistry,
)
from pytypes.core.src.loan.terms.simple.loan.PWNSimpleLoan import PWNSimpleLoan
from pytypes.core.src.utilizedcredit.PWNUtilizedCredit import PWNUtilizedCredit

from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanProposal import (
    PWNSimpleLoanProposal,
)
from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanElasticProposal import (
    PWNSimpleLoanElasticProposal,
)
from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanDutchAuctionProposal import (
    PWNSimpleLoanDutchAuctionProposal,
)
from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanSimpleProposal import (
    PWNSimpleLoanSimpleProposal,
)
from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanElasticChainlinkProposal import (
    PWNSimpleLoanElasticChainlinkProposal,
)
from pytypes.core.src.loan.terms.simple.proposal.PWNSimpleLoanListProposal import (
    PWNSimpleLoanListProposal,
)
from pytypes.core.src.loan.vault.Permit import Permit as PWNPermit
from pytypes.core.src.PWNErrors import Expired
from pytypes.core.src.loan.lib.Chainlink import Chainlink
from pytypes.periphery.src.pooladapter.ERC4626Adapter import ERC4626Adapter
from pytypes.periphery.src.pooladapter.AaveAdapter import AaveAdapter, IAavePoolLike
from pytypes.periphery.src.pooladapter.CompoundAdapter import CompoundAdapter, ICometLike
from pytypes.tests.AggregatorV2V3Interface import AggregatorV2V3Interface
from pytypes.wake.interfaces.IERC1155 import IERC1155
from pytypes.wake.interfaces.IERC721 import IERC721
from pytypes.wake.interfaces.IERC20 import IERC20
from pytypes.wake.ERC1967Factory import ERC1967Factory

from pytypes.tests.ERC721Mock import ERC721Mock
from pytypes.tests.FeedRegistryInterface import FeedRegistryInterface
from pytypes.tests.MockERC4626 import MockERC4626
from .keyed_default_dict import KeyedDefaultDict

from .merkle_tree import MerkleTree


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


ACTIVE_LOAN_TAG = keccak256(b"PWN_ACTIVE_LOAN")
LOAN_PROPOSAL_TAG = keccak256(b"PWN_LOAN_PROPOSAL")
NONCE_MANAGER_TAG = keccak256(b"NONCE_MANAGER")

MAX_APR = 160_000
MIN_DURATION = 10 * 60  # 10 minutes

TOKENS: Dict[int, Dict[str, Union[IERC20, IERC721, IERC1155]]] = {
    0: {
        "USDC": IERC20("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
        "USDT": IERC20("0xdac17f958d2ee523a2206206994597c13d831ec7"),
        "BNB": IERC20("0xB8c77482e45F1F44dE1745F52C74426C631bDD52"),
        "DAI": IERC20("0x6b175474e89094c44da98b954eedeac495271d0f"),
        "WETH": IERC20("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
        # "STA": IERC20("0xa7DE087329BFcda5639247F96140f9DAbe3DeED1"),  fee-on-transfer not supported
        "LEND": IERC20("0x80fB784B7eD66730e8b1DBd9820aFD29931aab03"),
        "YAMV2": IERC20("0xaba8cac6866b83ae4eec97dd07ed254282f6ad8a"),
        "MKR": IERC20("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2"),
        "EURS": IERC20("0xdb25f211ab05b1c97d595516f45794528a807ad8"),
        "UNI": IERC20("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"),
        "SHIB": IERC20("0x95ad61b0a150d79219dcf64e1e6cc01f0b64c4ce"),
        "WBTC": IERC20("0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"),
        "FTM": IERC20("0x4E15361FD6b4BB609Fa63C81A2be19d873717870"),
    },
    2: {
        "BARFLIES": IERC1155("0x503AC85cFAB61a1E33DF33c8B26aE81E3c6e3ef2"),
    },
}

MAX_TOKENS: Dict[Account, int] = {
    TOKENS[0]["USDC"]: 5_000,
    TOKENS[0]["USDT"]: 5_000,
    TOKENS[0]["BNB"]: 8,
    TOKENS[0]["DAI"]: 5_000,
    TOKENS[0]["WETH"]: 2,
    TOKENS[0]["LEND"]: 100_000,
    TOKENS[0]["YAMV2"]: 100_000,
    TOKENS[0]["MKR"]: 4,
    TOKENS[0]["EURS"]: 5_000,
    TOKENS[0]["UNI"]: 50,
    TOKENS[0]["SHIB"]: 100_000_000,
    TOKENS[0]["WBTC"]: 1,
    TOKENS[0]["FTM"]: 7_000,
    TOKENS[2]["BARFLIES"]: 100_000,
}

AAVE_POOLS: Dict[Account, IAavePoolLike] = {
    TOKENS[0]["USDC"]: IAavePoolLike("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"),
    TOKENS[0]["USDT"]: IAavePoolLike("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"),
    TOKENS[0]["DAI"]: IAavePoolLike("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"),
    TOKENS[0]["WETH"]: IAavePoolLike("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"),
    TOKENS[0]["UNI"]: IAavePoolLike("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"),
    TOKENS[0]["WBTC"]: IAavePoolLike("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"),
}
AAVE_EXTRA_DEPOSIT = 2

COMP_POOLS: Dict[Account, ICometLike] = {
    TOKENS[0]["USDC"]: ICometLike("0xc3d688B66703497DAA19211EEdff47f25384cdc3"),
    TOKENS[0]["USDT"]: ICometLike("0x3Afdc9BCA9213A35503b077a6072F3D0d5AB0840"),
    TOKENS[0]["WETH"]: ICometLike("0xA17581A9E3356d9A858b789D68B4d866e593aE94"),
}
COMP_EXTRA_DEPOSIT = 2

HAS_CHAINLINK_FEED: Dict[Account, bool] = defaultdict(lambda: False)
HAS_CHAINLINK_FEED[TOKENS[0]["USDC"]] = True
HAS_CHAINLINK_FEED[TOKENS[0]["USDT"]] = True
HAS_CHAINLINK_FEED[TOKENS[0]["DAI"]] = True
HAS_CHAINLINK_FEED[TOKENS[0]["WETH"]] = True
HAS_CHAINLINK_FEED[TOKENS[0]["MKR"]] = True
HAS_CHAINLINK_FEED[TOKENS[0]["UNI"]] = True
HAS_CHAINLINK_FEED[TOKENS[0]["SHIB"]] = True
HAS_CHAINLINK_FEED[TOKENS[0]["WBTC"]] = True
HAS_CHAINLINK_FEED[TOKENS[0]["FTM"]] = True

PermitInfo = NamedTuple("PermitInfo", [("name", str), ("version", Optional[str])])

PERMIT: Dict[Account, PermitInfo] = {}
PERMIT[TOKENS[0]["USDC"]] = PermitInfo(name="USD Coin", version="2")
PERMIT[TOKENS[0]["UNI"]] = PermitInfo(name="Uniswap", version=None)

FEED_REGISTRY = FeedRegistryInterface("0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf")

MAX_CHAINLINK_FEED_PRICE_AGE = 24 * 60 * 60  # 1 day

def get_decimals(token: Account):
    with may_revert():
        return abi.decode(token.call(abi.encode_with_signature("decimals()")), [uint])
    return 0

DECIMALS: Dict[Account, int] = KeyedDefaultDict(get_decimals)


class AggregatorData(NamedTuple):
    round_id: int
    price: int
    timestamp: int


@dataclass
class Permit:
    owner: Address
    spender: Address
    value: uint256
    nonce: uint256
    deadline: uint256


def random_duration_or_date():
    # min duration is 10 minutes
    if random_bool():
        # duration
        return random_int(MIN_DURATION, 1000)
    else:
        return chain.blocks["pending"].timestamp + random_int(MIN_DURATION, 1000)


def random_nonce():
    # small enough to introduce collisions, large enough to prevent complete exhaustion
    return random_int(0, 2**12 - 1)


def random_expiration():
    return chain.blocks["pending"].timestamp + random_int(0, 1000)


@dataclass
class Loan:
    id: uint
    credit: IERC20
    collateral: Account
    lender: Account
    borrower: Account
    fixed_interest_amount: uint
    credit_amount: uint
    collateral_amount: uint
    collateral_category: MultiToken.Category
    collateral_id: uint
    interest_apr: uint
    start_timestamp: uint
    duration: uint
    repaid: bool
    source_of_funds: Account
    extension_proposals: List[PWNSimpleLoan.ExtensionProposal]
    proposal: Union[
        PWNSimpleLoanElasticProposal.Proposal,
        PWNSimpleLoanDutchAuctionProposal.Proposal,
        PWNSimpleLoanSimpleProposal.Proposal,
        PWNSimpleLoanElasticChainlinkProposal.Proposal,
        PWNSimpleLoanListProposal.Proposal,
    ]


class PWNFuzzTest(FuzzTest):
    hub: PWNHub
    vault: PWNSimpleLoan
    config: PWNConfig
    utilized_credit: PWNUtilizedCredit
    revoked_nonce: PWNRevokedNonce
    multi_token_registry: MultiTokenCategoryRegistry
    erc4626_adapter: ERC4626Adapter
    aave_adapter: AaveAdapter
    compound_adapter: CompoundAdapter

    loan_token: PWNLOAN
    fee: int
    fee_collector: Account

    elastic_proposal: PWNSimpleLoanElasticProposal
    dutch_auction_proposal: PWNSimpleLoanDutchAuctionProposal
    simple_proposal: PWNSimpleLoanSimpleProposal
    elastic_chainlink_proposal: PWNSimpleLoanElasticChainlinkProposal
    list_proposal: PWNSimpleLoanListProposal

    simple_proposals: Dict[
        bytes32,
        Tuple[PWNSimpleLoanSimpleProposal.Proposal, Optional[PWNSimpleLoan.LenderSpec]],
    ]
    dutch_auction_proposals: Dict[
        bytes32,
        Tuple[
            PWNSimpleLoanDutchAuctionProposal.Proposal,
            Optional[PWNSimpleLoan.LenderSpec],
        ],
    ]
    elastic_proposals: Dict[
        bytes32,
        Tuple[
            PWNSimpleLoanElasticProposal.Proposal, Optional[PWNSimpleLoan.LenderSpec]
        ],
    ]
    elastic_chainlink_proposals: Dict[
        bytes32,
        Tuple[
            PWNSimpleLoanElasticChainlinkProposal.Proposal,
            Optional[PWNSimpleLoan.LenderSpec],
        ],
    ]
    list_proposals: Dict[
        bytes32,
        Tuple[PWNSimpleLoanListProposal.Proposal, Optional[PWNSimpleLoan.LenderSpec]],
    ]
    whitelisted_collateral_ids: Dict[bytes32, OrderedSet[int]]
    nonce_spaces: Dict[Account, int]
    revoked_nonces: Dict[Account, OrderedSet[int]]
    loans: Dict[int, Loan]
    utilized_credit_ids: Dict[Account, Dict[bytes32, int]]
    utilized_ids: List[bytes32]

    erc20_balances: Dict[IERC20, Dict[Account, int]]
    erc721_owners: Dict[IERC721, Dict[int, Account]]
    erc1155_balances: Dict[IERC1155, Dict[Account, Dict[int, int]]]

    aggregator_data: Dict[Account, AggregatorData]
    erc4626_vaults: Dict[Account, MockERC4626]

    def pre_sequence(self) -> None:
        self.hub = PWNHub.deploy()
        self.utilized_credit = PWNUtilizedCredit.deploy(self.hub, LOAN_PROPOSAL_TAG)
        self.revoked_nonce = PWNRevokedNonce.deploy(self.hub, NONCE_MANAGER_TAG)
        self.multi_token_registry = MultiTokenCategoryRegistry.deploy()
        self.erc4626_adapter = ERC4626Adapter.deploy(self.hub)
        self.aave_adapter = AaveAdapter.deploy(self.hub)
        self.compound_adapter = CompoundAdapter.deploy(self.hub)

        proxy_factory = ERC1967Factory.deploy()

        config = PWNConfig.deploy()
        self.config = PWNConfig(
            proxy_factory.deploy_(config, chain.accounts[0]).return_value
        )
        self.fee = random_int(0, 1_000)
        self.fee_collector = Account(
            random_address()
        )  # random_account() breaks logic due to fee collector vs lender/borrower collision
        self.config.initialize(chain.accounts[0], self.fee, self.fee_collector)

        self.loan_token = PWNLOAN.deploy(self.hub)
        self.vault = PWNSimpleLoan.deploy(
            self.hub,
            self.loan_token,
            self.config,
            self.revoked_nonce,
            self.multi_token_registry,
        )

        self.elastic_proposal = PWNSimpleLoanElasticProposal.deploy(
            self.hub, self.revoked_nonce, self.config, self.utilized_credit
        )
        self.dutch_auction_proposal = PWNSimpleLoanDutchAuctionProposal.deploy(
            self.hub, self.revoked_nonce, self.config, self.utilized_credit
        )
        self.simple_proposal = PWNSimpleLoanSimpleProposal.deploy(
            self.hub, self.revoked_nonce, self.config, self.utilized_credit
        )
        self.elastic_chainlink_proposal = PWNSimpleLoanElasticChainlinkProposal.deploy(
            self.hub,
            self.revoked_nonce,
            self.config,
            self.utilized_credit,
            FEED_REGISTRY,
            Address.ZERO,
            TOKENS[0]["WETH"],
        )
        self.list_proposal = PWNSimpleLoanListProposal.deploy(
            self.hub, self.revoked_nonce, self.config, self.utilized_credit
        )

        self.hub.setTags(
            [
                self.elastic_proposal,
                self.dutch_auction_proposal,
                self.simple_proposal,
                self.elastic_chainlink_proposal,
                self.list_proposal,
            ],
            [LOAN_PROPOSAL_TAG] * 5,
            True,
        )
        self.hub.setTags(
            [
                self.elastic_proposal,
                self.dutch_auction_proposal,
                self.simple_proposal,
                self.elastic_chainlink_proposal,
                self.list_proposal,
            ],
            [NONCE_MANAGER_TAG] * 5,
            True,
        )
        self.hub.setTag(self.vault, NONCE_MANAGER_TAG, True)
        self.hub.setTag(self.vault, ACTIVE_LOAN_TAG, True)

        self.simple_proposals = {}
        self.dutch_auction_proposals = {}
        self.elastic_proposals = {}
        self.elastic_chainlink_proposals = {}
        self.list_proposals = {}
        self.whitelisted_collateral_ids = {}
        self.nonce_spaces = defaultdict(int)
        self.revoked_nonces = defaultdict(lambda: OrderedSet([]))
        self.loans = {}
        self.aggregator_data = {}
        self.erc4626_vaults = KeyedDefaultDict(
            lambda token: self._register_erc4626_vault(token)
        )
        self.utilized_credit_ids = defaultdict(lambda: defaultdict(int))
        self.utilized_ids = [bytes32(random_bytes(32)) for _ in range(100)]

        TOKENS[1] = {
            "MOCK": ERC721Mock.deploy("Mock", "MOCK"),
            self.loan_token.symbol(): self.loan_token,
        }

        self.erc20_balances = defaultdict(lambda: defaultdict(int))

        for acc in chain.accounts:
            for token in TOKENS[0].values():
                self.erc20_balances[token][acc] = token.balanceOf(acc)

        self.erc721_owners = defaultdict(lambda: {})

        self.erc1155_balances = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

        self._register_tokens()

        for pool in AAVE_POOLS.values():
            self.config.registerPoolAdapter(pool, self.aave_adapter)

        for pool in COMP_POOLS.values():
            self.config.registerPoolAdapter(pool, self.compound_adapter)

    def _register_tokens(self):
        for category, tokens in TOKENS.items():
            for token, token_address in tokens.items():
                self.multi_token_registry.registerCategoryValue(token_address, category)

    def _register_erc4626_vault(self, token: Account):
        vault = MockERC4626.deploy(token)
        self.config.registerPoolAdapter(vault, self.erc4626_adapter)
        return vault

    def _get_aggregator_data(self, aggregator: Account) -> AggregatorData:
        if aggregator not in self.aggregator_data:
            round_id, price, _, updated_at, _ = AggregatorV2V3Interface(
                aggregator
            ).latestRoundData()
            self.aggregator_data[aggregator] = AggregatorData(
                round_id, price, updated_at
            )

        return self.aggregator_data[aggregator]

    def _random_lender_spec(
        self,
        lender: Account,
        credit_token: Account,
    ):
        options = [
            lender.address,
            self.erc4626_vaults[credit_token].address,
        ]
        if credit_token in AAVE_POOLS:
            options.append(AAVE_POOLS[credit_token].address)
        if credit_token in COMP_POOLS:
            options.append(COMP_POOLS[credit_token].address)

        return PWNSimpleLoan.LenderSpec(random.choice(options))

    def _random_credit_limit(self, owner: Account, utilized_credit_id: bytes32, credit_amount: int) -> int:
        p = random.random()
        if p < 0.45:
            return 0
        elif p < 0.5:
            return random_int(
                int(self.utilized_credit_ids[owner][utilized_credit_id] * 0.9) + credit_amount,
                int(self.utilized_credit_ids[owner][utilized_credit_id] * 1.1) + credit_amount + 100,
                edge_values_prob=0.01
            )
        else:
            return random_int(
                self.utilized_credit_ids[owner][utilized_credit_id] + credit_amount,
                self.utilized_credit_ids[owner][utilized_credit_id] * 2 + credit_amount + 100,
                edge_values_prob=0.01,
            )

    def _update_aggregator_price(self, aggregator: Account, new_price: int):
        if aggregator not in self.aggregator_data:
            round_id = AggregatorV2V3Interface(aggregator).latestRound()
        else:
            round_id = self.aggregator_data[aggregator].round_id + 1
        timestamp = chain.blocks["latest"].timestamp
        self.aggregator_data[aggregator] = AggregatorData(
            round_id, new_price, timestamp
        )

        write_storage_variable(
            aggregator, "s_hotVars", round_id, keys=["latestAggregatorRoundId"]
        )
        try:
            write_storage_variable(
                aggregator,
                "s_transmissions",
                {"answer": new_price, "timestamp": timestamp},
                keys=[round_id],
            )
        except ValueError:
            # some aggregators have 3-member structs in s_transmissions
            write_storage_variable(
                aggregator,
                "s_transmissions",
                {
                    "answer": new_price,
                    "observationsTimestamp": timestamp,
                    "transmissionTimestamp": timestamp,
                },
                keys=[round_id],
            )

        _, price, _, updated_at, _ = AggregatorV2V3Interface(
            aggregator
        ).latestRoundData()
        assert price == new_price
        assert updated_at == timestamp

    def post_invariants(self) -> None:
        chain.mine(lambda t: t + 50)

    @flow()
    def flow_set_fee(self):
        self.fee = random_int(0, 1_000)
        self.config.setFee(self.fee)

        logger.info(f"Fee set to {self.fee}")

    @flow()
    def flow_set_fee_collector(self):
        self.fee_collector = Account(
            random_address()
        )  # random_account() breaks logic due to fee collector vs lender/borrower collision
        self.config.setFeeCollector(self.fee_collector)

        logger.info(f"Fee collector set to {self.fee_collector}")

    def _new_simple_proposal(
        self,
    ) -> Tuple[
        PWNSimpleLoanSimpleProposal.Proposal, Optional[PWNSimpleLoan.LenderSpec]
    ]:
        if random_bool() and len(self.loans) > 0:
            refinance_id = random.choice(list(self.loans.keys()))
        else:
            refinance_id = 0

        is_offer = random_bool()

        if refinance_id != 0:
            refinance_loan = self.loans[refinance_id]
            collateral_category = refinance_loan.collateral_category
            collateral_token = refinance_loan.collateral
            collateral_id = refinance_loan.collateral_id
            collateral_amount = refinance_loan.collateral_amount

            credit_token = refinance_loan.credit
            state_fingerprint = refinance_loan.proposal.collateralStateFingerprint

            if is_offer:
                allowed_acceptor = refinance_loan.borrower
                proposer = random_account()
            else:
                allowed_acceptor = random_account() if random_bool() else Account(0)
                proposer = refinance_loan.borrower
        else:
            collateral_category = random.choice(
                [MultiToken.Category.ERC20, MultiToken.Category.ERC721, MultiToken.Category.ERC1155]
            )

            if collateral_category == MultiToken.Category.ERC721:
                pwn_tokens = [
                    id
                    for id in self.erc721_owners[IERC721(self.loan_token)].keys()
                    if self.erc721_owners[IERC721(self.loan_token)][id] != self.vault
                ]
                if len(pwn_tokens) > 0 and random_bool(true_prob=0.77):
                    collateral_token = self.loan_token
                    collateral_id = random.choice(pwn_tokens)
                    state_fingerprint = self.loan_token.getStateFingerprint(collateral_id)

                    if is_offer:
                        allowed_acceptor = self.erc721_owners[IERC721(self.loan_token)][
                            collateral_id
                        ]
                        proposer = random_account()
                    else:
                        allowed_acceptor = random_account() if random_bool() else Account(0)
                        proposer = self.erc721_owners[IERC721(self.loan_token)][
                            collateral_id
                        ]
                else:
                    collateral_token = TOKENS[1]["MOCK"]
                    collateral_id = random_int(0, 2**256 - 1)
                    state_fingerprint = keccak256(abi.encode(uint8(0)))
                    allowed_acceptor = random_account() if random_bool() else Account(0)
                    proposer = random_account()
            elif collateral_category == MultiToken.Category.ERC1155:
                collateral_token = random.choice(list(TOKENS[collateral_category.value].values()))
                collateral_id = random_int(0, 2**256 - 1)
                state_fingerprint = bytes32(0)
                allowed_acceptor = random_account() if random_bool() else Account(0)
                proposer = random_account()
            else:
                collateral_token = random.choice(
                    list(TOKENS[collateral_category.value].values())
                )
                collateral_id = 0
                state_fingerprint = bytes(0)
                allowed_acceptor = random_account() if random_bool() else Account(0)
                proposer = random_account()

            collateral_amount = (
                random_int(0, MAX_TOKENS[collateral_token]) * 10 ** DECIMALS[collateral_token]
                if collateral_category != MultiToken.Category.ERC721
                else 0
            )

            credit_token = random.choice(list(TOKENS[0].values()))

        credit_decimals = DECIMALS[credit_token]
        credit_amount = random_int(0, MAX_TOKENS[credit_token]) * 10 ** credit_decimals
        utilized_credit_id = random.choice(self.utilized_ids)
        available_credit_limit = self._random_credit_limit(proposer, utilized_credit_id, credit_amount)

        fixed_interest_amount = random_int(0, MAX_TOKENS[credit_token]) * 10 ** credit_decimals
        interest_apr = random_int(0, MAX_APR)
        duration_or_date = random_duration_or_date()
        expiration = random_expiration()
        lender_spec = (
            self._random_lender_spec(proposer, credit_token) if is_offer else None
        )
        nonce_space = self.nonce_spaces[proposer]
        nonce = random_nonce()

        return (
            PWNSimpleLoanSimpleProposal.Proposal(
                collateralCategory=collateral_category,
                collateralAddress=collateral_token.address,
                collateralId=collateral_id,
                collateralAmount=collateral_amount,
                checkCollateralStateFingerprint=collateral_category
                == MultiToken.Category.ERC721,
                collateralStateFingerprint=state_fingerprint,
                creditAddress=credit_token.address,
                creditAmount=credit_amount,
                availableCreditLimit=available_credit_limit,
                utilizedCreditId=utilized_credit_id,
                fixedInterestAmount=fixed_interest_amount,
                accruingInterestAPR=interest_apr,
                durationOrDate=duration_or_date,
                expiration=expiration,
                allowedAcceptor=allowed_acceptor.address,
                proposer=proposer.address,
                proposerSpecHash=(
                    keccak256(abi.encode(lender_spec)) if lender_spec else bytes32(0)
                ),
                isOffer=is_offer,
                refinancingLoanId=refinance_id,
                nonceSpace=nonce_space,
                nonce=nonce,
                loanContract=self.vault.address,
            ),
            lender_spec,
        )

    @flow()
    def flow_make_simple_proposal(self):
        proposal, lender_spec = self._new_simple_proposal()

        tx = self.simple_proposal.makeProposal(proposal, from_=proposal.proposer)
        proposal_hash = next(
            e
            for e in tx.events
            if isinstance(e, PWNSimpleLoanSimpleProposal.ProposalMade)
        ).proposalHash
        self.simple_proposals[proposal_hash] = (proposal, lender_spec)

        logger.info(f"Proposal made: {proposal}")

    @flow()
    def flow_accept_simple_proposal(self):
        if len(self.simple_proposals) == 0:
            return

        onchain_proposal = random_bool()

        if onchain_proposal:
            proposal_hash = random.choice(list(self.simple_proposals.keys()))
            proposal, lender_spec = self.simple_proposals[proposal_hash]
            signature = b""
            inclusion_proof = []
        else:
            proposal, lender_spec = self._new_simple_proposal()
            proposal_hash = self.simple_proposal.getProposalHash(proposal)

            if random_bool():
                signature = Account(proposal.proposer).sign_structured(
                    proposal,
                    Eip712Domain(
                        name="PWNSimpleLoanSimpleProposal",
                        version="1.3",
                        chainId=chain.chain_id,
                        verifyingContract=self.simple_proposal,
                    ),
                )
                inclusion_proof = []
            else:
                tree = MerkleTree(hash_leaves=False)
                leaves = [random_bytes(32) for _ in range(random_int(1, 10))]
                leaves.append(proposal_hash)
                random.shuffle(leaves)

                for leaf in leaves:
                    tree.add_leaf(leaf)

                multiproposal = PWNSimpleLoanProposal.Multiproposal(tree.root)
                signature = Account(proposal.proposer).sign_structured(
                    multiproposal,
                    Eip712Domain(
                        name="PWNMultiproposal",
                    ),
                )
                inclusion_proof = tree.get_proof(tree.leaves.index(proposal_hash))

        tx = self._accept_proposal(
            proposal,
            abi.encode(proposal),
            self.simple_proposal,
            proposal.collateralAmount,
            proposal.creditAmount,
            proposal.collateralId,
            proposal.expiration,
            signature,
            inclusion_proof,
            chain.blocks["latest"].timestamp + 10,
            lender_spec,
        )

        if tx is None or tx.error is not None:
            self.simple_proposals.pop(proposal_hash, None)
        elif (
            tx.error is None
            and proposal.collateralCategory == MultiToken.Category.ERC721
        ):
            # ERC-721 with given collateral id cannot be minted again
            self.simple_proposals.pop(proposal_hash, None)

    def _new_dutch_auction_proposal(
        self,
    ) -> Tuple[
        PWNSimpleLoanDutchAuctionProposal.Proposal, Optional[PWNSimpleLoan.LenderSpec]
    ]:
        if random_bool() and len(self.loans) > 0:
            refinance_id = random.choice(list(self.loans.keys()))
        else:
            refinance_id = 0

        is_offer = random_bool()

        if refinance_id != 0:
            refinance_loan = self.loans[refinance_id]
            collateral_category = refinance_loan.collateral_category
            collateral_token = refinance_loan.collateral
            collateral_id = refinance_loan.collateral_id
            collateral_amount = refinance_loan.collateral_amount

            credit_token = refinance_loan.credit
            state_fingerprint = refinance_loan.proposal.collateralStateFingerprint

            if is_offer:
                allowed_acceptor = refinance_loan.borrower
                proposer = random_account()
            else:
                allowed_acceptor = random_account() if random_bool() else Account(0)
                proposer = refinance_loan.borrower
        else:
            collateral_category = random.choice(
                [MultiToken.Category.ERC20, MultiToken.Category.ERC721, MultiToken.Category.ERC1155]
            )

            if collateral_category == MultiToken.Category.ERC721:
                pwn_tokens = [
                    id
                    for id in self.erc721_owners[IERC721(self.loan_token)].keys()
                    if self.erc721_owners[IERC721(self.loan_token)][id] != self.vault
                ]
                if len(pwn_tokens) > 0 and random_bool(true_prob=0.77):
                    collateral_token = self.loan_token
                    collateral_id = random.choice(pwn_tokens)
                    state_fingerprint = self.loan_token.getStateFingerprint(collateral_id)

                    if is_offer:
                        allowed_acceptor = self.erc721_owners[IERC721(self.loan_token)][
                            collateral_id
                        ]
                        proposer = random_account()
                    else:
                        allowed_acceptor = random_account() if random_bool() else Account(0)
                        proposer = self.erc721_owners[IERC721(self.loan_token)][
                            collateral_id
                        ]
                else:
                    collateral_token = TOKENS[1]["MOCK"]
                    collateral_id = random_int(0, 2**256 - 1)
                    state_fingerprint = keccak256(abi.encode(uint8(0)))
                    allowed_acceptor = random_account() if random_bool() else Account(0)
                    proposer = random_account()
            elif collateral_category == MultiToken.Category.ERC1155:
                collateral_token = random.choice(list(TOKENS[2].values()))
                collateral_id = random_int(0, 2**256 - 1)
                state_fingerprint = bytes(0)
                allowed_acceptor = random_account() if random_bool() else Account(0)
                proposer = random_account()
            else:
                collateral_token = random.choice(
                    list(TOKENS[collateral_category.value].values())
                )
                collateral_id = 0
                state_fingerprint = bytes(0)
                allowed_acceptor = random_account() if random_bool() else Account(0)
                proposer = random_account()

            collateral_amount = (
                random_int(0, MAX_TOKENS[collateral_token]) * 10 ** DECIMALS[collateral_token]
                if collateral_category != MultiToken.Category.ERC721
                else 0
            )

            credit_token = random.choice(list(TOKENS[0].values()))

        credit_decimals = DECIMALS[credit_token]
        min_credit_amount = random_int(0, MAX_TOKENS[credit_token]) * 10**credit_decimals
        max_credit_amount = random_int(min_credit_amount, MAX_TOKENS[credit_token] * 10**credit_decimals)
        utilized_credit_id = random.choice(self.utilized_ids)
        available_credit_limit = self._random_credit_limit(proposer, utilized_credit_id, max_credit_amount)

        fixed_interest_amount = random_int(0, MAX_TOKENS[credit_token]) * 10**credit_decimals
        interest_apr = random_int(0, MAX_APR)
        duration_or_date = random_duration_or_date()
        auction_start = chain.blocks["pending"].timestamp + random_int(-5, 30)
        auction_duration = random_int(1, 60) * 60 + random_int(0, 1, zero_prob=0.1)
        lender_spec = (
            self._random_lender_spec(proposer, credit_token) if is_offer else None
        )
        nonce_space = self.nonce_spaces[proposer]
        nonce = random_nonce()

        return (
            PWNSimpleLoanDutchAuctionProposal.Proposal(
                collateralCategory=collateral_category,
                collateralAddress=collateral_token.address,
                collateralId=collateral_id,
                collateralAmount=collateral_amount,
                checkCollateralStateFingerprint=collateral_category
                == MultiToken.Category.ERC721,
                collateralStateFingerprint=state_fingerprint,
                creditAddress=credit_token.address,
                minCreditAmount=min_credit_amount,
                maxCreditAmount=max_credit_amount,
                availableCreditLimit=available_credit_limit,
                utilizedCreditId=utilized_credit_id,
                fixedInterestAmount=fixed_interest_amount,
                accruingInterestAPR=interest_apr,
                durationOrDate=duration_or_date,
                auctionStart=auction_start,
                auctionDuration=auction_duration,
                allowedAcceptor=allowed_acceptor.address,
                proposer=proposer.address,
                proposerSpecHash=(
                    keccak256(abi.encode(lender_spec)) if lender_spec else bytes32(0)
                ),
                isOffer=is_offer,
                refinancingLoanId=refinance_id,
                nonceSpace=nonce_space,
                nonce=nonce,
                loanContract=self.vault.address,
            ),
            lender_spec,
        )

    @flow()
    def flow_make_dutch_auction_proposal(self):
        proposal, lender_spec = self._new_dutch_auction_proposal()

        tx = self.dutch_auction_proposal.makeProposal(proposal, from_=proposal.proposer)
        proposal_hash = next(
            e
            for e in tx.events
            if isinstance(e, PWNSimpleLoanDutchAuctionProposal.ProposalMade)
        ).proposalHash
        self.dutch_auction_proposals[proposal_hash] = (proposal, lender_spec)

        logger.info(f"Proposal made: {proposal}")

    @flow()
    def flow_accept_dutch_auction_proposal(self):
        if len(self.dutch_auction_proposals) == 0:
            return

        onchain_proposal = random_bool()

        if onchain_proposal:
            proposal_hash = random.choice(list(self.dutch_auction_proposals.keys()))
            proposal, lender_spec = self.dutch_auction_proposals[proposal_hash]
            signature = b""
            inclusion_proof = []
        else:
            proposal, lender_spec = self._new_dutch_auction_proposal()
            proposal_hash = self.dutch_auction_proposal.getProposalHash(proposal)

            if random_bool():
                signature = Account(proposal.proposer).sign_structured(
                    proposal,
                    Eip712Domain(
                        name="PWNSimpleLoanDutchAuctionProposal",
                        version="1.1",
                        chainId=chain.chain_id,
                        verifyingContract=self.dutch_auction_proposal,
                    ),
                )
                inclusion_proof = []
            else:
                tree = MerkleTree(hash_leaves=False)
                leaves = [random_bytes(32) for _ in range(random_int(1, 10))]
                leaves.append(proposal_hash)
                random.shuffle(leaves)

                for leaf in leaves:
                    tree.add_leaf(leaf)

                multiproposal = PWNSimpleLoanProposal.Multiproposal(tree.root)
                signature = Account(proposal.proposer).sign_structured(
                    multiproposal,
                    Eip712Domain(
                        name="PWNMultiproposal",
                    ),
                )
                inclusion_proof = tree.get_proof(tree.leaves.index(proposal_hash))

        credit_decimals = DECIMALS[IERC20(proposal.creditAddress)]

        target_time = chain.blocks["latest"].timestamp + 10
        credit_change = max(
            0,
            (proposal.maxCreditAmount - proposal.minCreditAmount)
            * ((target_time - proposal.auctionStart) // 60)
            // (proposal.auctionDuration // 60),
        )
        current_credit_amount = max(
            0,
            (
                proposal.minCreditAmount + credit_change
                if proposal.isOffer
                else proposal.maxCreditAmount - credit_change
            ),
        )
        slippage = random_int(0, 1_000) * 10**credit_decimals

        if proposal.isOffer:
            credit_amount = random_int(
                current_credit_amount - slippage, current_credit_amount
            )
        else:
            if slippage >= current_credit_amount:
                slippage = random_int(0, current_credit_amount)
            credit_amount = random_int(
                current_credit_amount, current_credit_amount + slippage
            )

        proposal_values = PWNSimpleLoanDutchAuctionProposal.ProposalValues(
            current_credit_amount, slippage
        )

        def revert_handler(tx: TransactionAbc) -> bool:
            if proposal.auctionDuration < 60:
                assert (
                    tx.error
                    == PWNSimpleLoanDutchAuctionProposal.InvalidAuctionDuration(
                        proposal.auctionDuration, 60
                    )
                )
                return True
            elif proposal.auctionDuration % 60 != 0:
                assert (
                    tx.error
                    == PWNSimpleLoanDutchAuctionProposal.AuctionDurationNotInFullMinutes(
                        proposal.auctionDuration
                    )
                )
                return True
            elif proposal.minCreditAmount >= proposal.maxCreditAmount:
                assert (
                    tx.error
                    == PWNSimpleLoanDutchAuctionProposal.InvalidCreditAmountRange(
                        proposal.minCreditAmount, proposal.maxCreditAmount
                    )
                )
                return True
            elif tx.block.timestamp < proposal.auctionStart:
                assert (
                    tx.error
                    == PWNSimpleLoanDutchAuctionProposal.AuctionNotInProgress(
                        tx.block.timestamp, proposal.auctionStart
                    )
                )
                return True
            elif (
                tx.block.timestamp
                >= proposal.auctionStart + proposal.auctionDuration + 60
            ):
                assert tx.error == Expired(
                    tx.block.timestamp,
                    proposal.auctionStart + proposal.auctionDuration + 60,
                )
                return True
            elif proposal.isOffer and credit_amount + slippage < current_credit_amount:
                assert (
                    tx.error
                    == PWNSimpleLoanDutchAuctionProposal.InvalidCreditAmount(
                        credit_amount, current_credit_amount, slippage
                    )
                )
                return True
            elif (
                not proposal.isOffer
                and credit_amount - slippage > current_credit_amount
            ):
                assert (
                    tx.error
                    == PWNSimpleLoanDutchAuctionProposal.InvalidCreditAmount(
                        credit_amount, current_credit_amount, slippage
                    )
                )
                return True
            else:
                return False

        tx = self._accept_proposal(
            proposal,
            abi.encode(proposal, proposal_values),
            self.dutch_auction_proposal,
            proposal.collateralAmount,
            current_credit_amount,
            proposal.collateralId,
            proposal.auctionStart + proposal.auctionDuration + 60,
            signature,
            inclusion_proof,
            target_time,
            lender_spec,
            revert_handler,
        )

        if tx is None or tx.error is not None:
            self.dutch_auction_proposals.pop(proposal_hash, None)
        elif (
            tx.error is None
            and proposal.collateralCategory == MultiToken.Category.ERC721
        ):
            # ERC-721 with given collateral id cannot be minted again
            self.dutch_auction_proposals.pop(proposal_hash, None)

    def _new_elastic_proposal(
        self,
    ) -> Tuple[
        PWNSimpleLoanElasticProposal.Proposal, Optional[PWNSimpleLoan.LenderSpec]
    ]:
        collateral_category = random.choice(
            [MultiToken.Category.ERC20, MultiToken.Category.ERC1155]
        )
        collateral_token = random.choice(
            list(TOKENS[collateral_category.value].values())
        )
        collateral_id = (
            random_int(0, 2**256 - 1)
            if collateral_category != MultiToken.Category.ERC20
            else 0
        )

        credit_token = random.choice(list(TOKENS[0].values()))
        credit_decimals = DECIMALS[credit_token]
        credit_per_collateral_exponent = random_int(37, 42)  # 10x - 0.0001x
        credit_per_collateral_exponent += (
            credit_decimals - DECIMALS[collateral_token]
        )

        credit_per_collateral_unit = math.ceil(
            random.random() * 10**credit_per_collateral_exponent
        )
        while credit_per_collateral_unit == 0:
            credit_per_collateral_unit = math.ceil(
                random.random() * 10**credit_per_collateral_exponent
            )
        min_credit_amount = random_int(0, MAX_TOKENS[credit_token]) * 10 ** credit_decimals
        proposer = random_account()
        utilized_credit_id = random.choice(self.utilized_ids)
        available_credit_limit = self._random_credit_limit(proposer, utilized_credit_id, min_credit_amount * 2)

        fixed_interest_amount = random_int(0, MAX_TOKENS[credit_token]) * 10 ** credit_decimals
        interest_apr = random_int(0, MAX_APR)
        duration_or_date = random_duration_or_date()
        expiration = random_expiration()
        allowed_acceptor = random_account() if random_bool() else Account(0)
        is_offer = random_bool()
        lender_spec = (
            self._random_lender_spec(proposer, credit_token) if is_offer else None
        )
        refinancing_loan_id = 0  # elastic proposal is not suitable for refinancing as it's hard to hit the exact collateral amount
        nonce_space = self.nonce_spaces[proposer]
        nonce = random_nonce()

        return (
            PWNSimpleLoanElasticProposal.Proposal(
                collateralCategory=collateral_category,
                collateralAddress=collateral_token.address,
                collateralId=collateral_id,
                checkCollateralStateFingerprint=False,  # ERC-721 cannot be collateral
                collateralStateFingerprint=bytes32(0),
                creditAddress=credit_token.address,
                creditPerCollateralUnit=credit_per_collateral_unit,
                minCreditAmount=min_credit_amount,
                availableCreditLimit=available_credit_limit,
                utilizedCreditId=utilized_credit_id,
                fixedInterestAmount=fixed_interest_amount,
                accruingInterestAPR=interest_apr,
                durationOrDate=duration_or_date,
                expiration=expiration,
                allowedAcceptor=allowed_acceptor.address,
                proposer=proposer.address,
                proposerSpecHash=(
                    keccak256(abi.encode(lender_spec)) if lender_spec else bytes32(0)
                ),
                isOffer=is_offer,
                refinancingLoanId=refinancing_loan_id,
                nonceSpace=nonce_space,
                nonce=nonce,
                loanContract=self.vault.address,
            ),
            lender_spec,
        )

    @flow()
    def flow_make_elastic_proposal(self):
        proposal, lender_spec = self._new_elastic_proposal()

        tx = self.elastic_proposal.makeProposal(proposal, from_=proposal.proposer)

        proposal_hash = next(
            e
            for e in tx.events
            if isinstance(e, PWNSimpleLoanElasticProposal.ProposalMade)
        ).proposalHash
        self.elastic_proposals[proposal_hash] = (proposal, lender_spec)

        logger.info(f"Proposal made: {proposal}")

    @flow()
    def flow_accept_elastic_proposal(self):
        if len(self.elastic_proposals) == 0:
            return

        onchain_proposal = random_bool()

        if onchain_proposal:
            proposal_hash = random.choice(list(self.elastic_proposals.keys()))
            proposal, lender_spec = self.elastic_proposals[proposal_hash]
            signature = b""
            inclusion_proof = []
        else:
            proposal, lender_spec = self._new_elastic_proposal()
            proposal_hash = self.elastic_proposal.getProposalHash(proposal)

            if random_bool():
                signature = Account(proposal.proposer).sign_structured(
                    proposal,
                    Eip712Domain(
                        name="PWNSimpleLoanElasticProposal",
                        version="1.1",
                        chainId=chain.chain_id,
                        verifyingContract=self.elastic_proposal,
                    ),
                )
                inclusion_proof = []
            else:
                tree = MerkleTree(hash_leaves=False)
                leaves = [random_bytes(32) for _ in range(random_int(1, 10))]
                leaves.append(proposal_hash)
                random.shuffle(leaves)

                for leaf in leaves:
                    tree.add_leaf(leaf)

                multiproposal = PWNSimpleLoanProposal.Multiproposal(tree.root)
                signature = Account(proposal.proposer).sign_structured(
                    multiproposal,
                    Eip712Domain(
                        name="PWNMultiproposal",
                    ),
                )
                inclusion_proof = tree.get_proof(tree.leaves.index(proposal_hash))

        credit_decimals = DECIMALS[IERC20(proposal.creditAddress)]

        credit_amount = random_int(
            proposal.minCreditAmount, MAX_TOKENS[IERC20(proposal.creditAddress)] * 10**credit_decimals
        )
        proposal_values = PWNSimpleLoanElasticProposal.ProposalValues(credit_amount)

        # different decimals already covered in credit_per_collateral_unit
        collateral_amount = credit_amount * 10**38 // proposal.creditPerCollateralUnit

        def revert_handler(tx: TransactionAbc) -> bool:
            if proposal.minCreditAmount == 0:
                assert tx.error == PWNSimpleLoanElasticProposal.MinCreditAmountNotSet()
                return True
            else:
                return False

        tx = self._accept_proposal(
            proposal,
            abi.encode(proposal, proposal_values),
            self.elastic_proposal,
            collateral_amount,
            credit_amount,
            proposal.collateralId,
            proposal.expiration,
            signature,
            inclusion_proof,
            chain.blocks["latest"].timestamp + 10,
            lender_spec,
            revert_handler,
        )

        if tx is None or tx.error is not None:
            self.elastic_proposals.pop(proposal_hash, None)
        else:
            e = next(
                (e for e in tx.events if isinstance(e, PWNSimpleLoan.LOANCreated)), None
            )
            if e is not None:
                assert e.terms.collateral.amount == collateral_amount

    def _new_elastic_chainlink_proposal(
        self,
    ) -> Tuple[
        PWNSimpleLoanElasticChainlinkProposal.Proposal,
        Optional[PWNSimpleLoan.LenderSpec],
    ]:
        collateral_category = random.choice(
            [MultiToken.Category.ERC20]
        )
        collateral_token = random.choice(
            [
                t
                for t in TOKENS[collateral_category.value].values()
                if HAS_CHAINLINK_FEED[t]
            ]
        )
        collateral_id = (
            random_int(0, 2**256 - 1)
            if collateral_category != MultiToken.Category.ERC20
            else 0
        )

        credit_token = random.choice(
            [t for t in TOKENS[0].values() if HAS_CHAINLINK_FEED[t]]
        )
        credit_decimals = DECIMALS[credit_token]
        loan_to_value = random_int(1, 100_000)
        min_credit_amount = random_int(0, MAX_TOKENS[credit_token]) * 10 ** credit_decimals
        proposer = random_account()
        utilized_credit_id = random.choice(self.utilized_ids)
        available_credit_limit = self._random_credit_limit(proposer, utilized_credit_id, min_credit_amount * 2)

        fixed_interest_amount = random_int(0, MAX_TOKENS[credit_token]) * 10 ** credit_decimals
        interest_apr = random_int(0, MAX_APR)
        duration_or_date = random_duration_or_date()
        expiration = random_expiration()
        allowed_acceptor = random_account() if random_bool() else Account(0)
        is_offer = random_bool()
        lender_spec = (
            self._random_lender_spec(proposer, credit_token) if is_offer else None
        )
        refinancing_loan_id = 0  # elastic proposal is not suitable for refinancing as it's hard to hit the exact collateral amount
        nonce_space = self.nonce_spaces[proposer]
        nonce = random_nonce()

        return (
            PWNSimpleLoanElasticChainlinkProposal.Proposal(
                collateralCategory=collateral_category,
                collateralAddress=collateral_token.address,
                collateralId=collateral_id,
                checkCollateralStateFingerprint=False,  # ERC-721 cannot be collateral
                collateralStateFingerprint=bytes32(0),
                creditAddress=credit_token.address,
                loanToValue=loan_to_value,
                minCreditAmount=min_credit_amount,
                availableCreditLimit=available_credit_limit,
                utilizedCreditId=utilized_credit_id,
                fixedInterestAmount=fixed_interest_amount,
                accruingInterestAPR=interest_apr,
                durationOrDate=duration_or_date,
                expiration=expiration,
                allowedAcceptor=allowed_acceptor.address,
                proposer=proposer.address,
                proposerSpecHash=(
                    keccak256(abi.encode(lender_spec)) if lender_spec else bytes32(0)
                ),
                isOffer=is_offer,
                refinancingLoanId=refinancing_loan_id,
                nonceSpace=nonce_space,
                nonce=nonce,
                loanContract=self.vault.address,
            ),
            lender_spec,
        )

    @flow()
    def flow_make_elastic_chainlink_proposal(self):
        proposal, lender_spec = self._new_elastic_chainlink_proposal()

        tx = self.elastic_chainlink_proposal.makeProposal(
            proposal, from_=proposal.proposer
        )

        proposal_hash = next(
            e
            for e in tx.events
            if isinstance(e, PWNSimpleLoanElasticChainlinkProposal.ProposalMade)
        ).proposalHash
        self.elastic_chainlink_proposals[proposal_hash] = (proposal, lender_spec)

        logger.info(f"Proposal made: {proposal}")

    def _new_list_proposal(
        self,
    ) -> Tuple[
        PWNSimpleLoanListProposal.Proposal,
        Optional[PWNSimpleLoan.LenderSpec],
        Optional[OrderedSet[int]],
    ]:
        loans = [l for l in self.loans.values() if l.collateral_category == MultiToken.Category.ERC721]
        if random_bool() and len(loans) > 0:
            refinance_id = random.choice(loans).id
        else:
            refinance_id = 0

        is_offer = random_bool()

        if refinance_id != 0:
            refinance_loan = self.loans[refinance_id]
            collateral_category = refinance_loan.collateral_category
            collateral_token = refinance_loan.collateral
            collateral_id = refinance_loan.collateral_id
            collateral_amount = refinance_loan.collateral_amount

            whitelisted_ids_tree = MerkleTree()
            whitelisted_collateral_ids = [collateral_id]
            whitelisted_ids_tree.add_leaf(collateral_id.to_bytes(32, "big"))
            root = whitelisted_ids_tree.root

            credit_token = refinance_loan.credit
            state_fingerprint = refinance_loan.proposal.collateralStateFingerprint

            if is_offer:
                allowed_acceptor = refinance_loan.borrower
                proposer = random_account()
            else:
                allowed_acceptor = random_account() if random_bool() else Account(0)
                proposer = refinance_loan.borrower
        else:
            collateral_category = random.choice(
                [MultiToken.Category.ERC20, MultiToken.Category.ERC721, MultiToken.Category.ERC1155]
            )
            if collateral_category == MultiToken.Category.ERC721:
                pwn_tokens = [
                    id
                    for id in self.erc721_owners[IERC721(self.loan_token)].keys()
                    if self.erc721_owners[IERC721(self.loan_token)][id] != self.vault
                ]
                if len(pwn_tokens) > 0 and random_bool(true_prob=0.77):
                    collateral_token = self.loan_token
                    collateral_id = random.choice(pwn_tokens)
                    whitelisted_collateral_ids = [collateral_id]
                    state_fingerprint = self.loan_token.getStateFingerprint(collateral_id)

                    if is_offer:
                        allowed_acceptor = self.erc721_owners[IERC721(self.loan_token)][
                            collateral_id
                        ]
                        proposer = random_account()
                    else:
                        allowed_acceptor = random_account() if random_bool() else Account(0)
                        proposer = self.erc721_owners[IERC721(self.loan_token)][
                            collateral_id
                        ]
                else:
                    collateral_token = TOKENS[1]["MOCK"]
                    collateral_id = random_int(0, 2**256 - 1)
                    state_fingerprint = keccak256(abi.encode(uint8(0)))
                    allowed_acceptor = random_account() if random_bool() else Account(0)
                    proposer = random_account()
                    whitelisted_collateral_ids = [
                        random_int(0, uint256.max) for _ in range(random_int(1, 10))
                    ]

                whitelisted_ids_tree = MerkleTree()

                for id in whitelisted_collateral_ids:
                    whitelisted_ids_tree.add_leaf(id.to_bytes(32, "big"))

                root = whitelisted_ids_tree.root
            elif collateral_category == MultiToken.Category.ERC1155:
                collateral_token = random.choice(list(TOKENS[collateral_category.value].values()))
                state_fingerprint = bytes(0)
                allowed_acceptor = random_account() if random_bool() else Account(0)
                proposer = random_account()

                whitelisted_collateral_ids = [
                    random_int(0, uint256.max) for _ in range(random_int(1, 10))
                ]

                whitelisted_ids_tree = MerkleTree()
                for id in whitelisted_collateral_ids:
                    whitelisted_ids_tree.add_leaf(id.to_bytes(32, "big"))

                root = whitelisted_ids_tree.root
            else:
                collateral_token = random.choice(
                    list(TOKENS[collateral_category.value].values())
                )
                collateral_id = 0
                state_fingerprint = bytes(0)
                allowed_acceptor = random_account() if random_bool() else Account(0)
                proposer = random_account()

                # either root must be 0 or tree must contain 0
                if random_bool():
                    whitelisted_collateral_ids = None
                    root = bytes32(0)
                else:
                    whitelisted_ids_tree = MerkleTree()
                    whitelisted_collateral_ids = [0] + [
                        random_int(0, uint256.max) for _ in range(random_int(0, 10))
                    ]

                    for id in whitelisted_collateral_ids:
                        whitelisted_ids_tree.add_leaf(id.to_bytes(32, "big"))

                    root = whitelisted_ids_tree.root

            collateral_amount = (
                random_int(0, MAX_TOKENS[collateral_token]) * 10 ** DECIMALS[collateral_token]
                if collateral_category != MultiToken.Category.ERC721
                else 0
            )

            credit_token = random.choice(list(TOKENS[0].values()))

        credit_decimals = DECIMALS[credit_token]
        credit_amount = random_int(0, MAX_TOKENS[credit_token]) * 10 ** credit_decimals
        utilized_credit_id = random.choice(self.utilized_ids)
        available_credit_limit = self._random_credit_limit(proposer, utilized_credit_id, credit_amount)

        fixed_interest_amount = random_int(0, MAX_TOKENS[credit_token]) * 10 ** credit_decimals
        interest_apr = random_int(0, MAX_APR)
        duration_or_date = random_duration_or_date()
        expiration = random_expiration()
        lender_spec = (
            self._random_lender_spec(proposer, credit_token) if is_offer else None
        )
        nonce_space = self.nonce_spaces[proposer]
        nonce = random_nonce()

        return (
            PWNSimpleLoanListProposal.Proposal(
                collateralCategory=collateral_category,
                collateralAddress=collateral_token.address,
                collateralIdsWhitelistMerkleRoot=root,
                collateralAmount=collateral_amount,
                checkCollateralStateFingerprint=collateral_category
                == MultiToken.Category.ERC721,
                collateralStateFingerprint=state_fingerprint,
                creditAddress=credit_token.address,
                creditAmount=credit_amount,
                availableCreditLimit=available_credit_limit,
                utilizedCreditId=utilized_credit_id,
                fixedInterestAmount=fixed_interest_amount,
                accruingInterestAPR=interest_apr,
                durationOrDate=duration_or_date,
                expiration=expiration,
                allowedAcceptor=allowed_acceptor.address,
                proposer=proposer.address,
                proposerSpecHash=(
                    keccak256(abi.encode(lender_spec)) if lender_spec else bytes32(0)
                ),
                isOffer=is_offer,
                refinancingLoanId=refinance_id,
                nonceSpace=nonce_space,
                nonce=nonce,
                loanContract=self.vault.address,
            ),
            lender_spec,
            (
                OrderedSet(whitelisted_collateral_ids)
                if whitelisted_collateral_ids is not None
                else None
            ),
        )

    @flow()
    def flow_make_list_proposal(self):
        proposal, lender_spec, whitelisted_collateral_ids = self._new_list_proposal()

        tx = self.list_proposal.makeProposal(proposal, from_=proposal.proposer)

        proposal_hash = next(
            e
            for e in tx.events
            if isinstance(e, PWNSimpleLoanListProposal.ProposalMade)
        ).proposalHash
        self.list_proposals[proposal_hash] = (proposal, lender_spec)

        if whitelisted_collateral_ids is not None:
            self.whitelisted_collateral_ids[proposal_hash] = OrderedSet(
                whitelisted_collateral_ids
            )

        logger.info(f"Proposal made: {proposal}")

    def _get_chainlink_latest_round_data(self, asset: Address):
        if asset == TOKENS[0]["WETH"].address:
            asset = Address("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE")

        with may_revert("Feed not found"):
            feed = FEED_REGISTRY.getFeed(asset, Address(840))  # USD
            return feed.latestRoundData()[1], feed.decimals(), Address(840)

        with may_revert("Feed not found"):
            feed = FEED_REGISTRY.getFeed(
                asset, Address("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE")
            )  # ETH
            return (
                feed.latestAnswer(),
                feed.decimals(),
                Address("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"),
            )

        feed = FEED_REGISTRY.getFeed(
            asset, Address("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")
        )  # BTC
        return (
            feed.latestAnswer(),
            feed.decimals(),
            Address("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"),
        )

    def _convert_price_denominator(
        self,
        price: int,
        price_decimals: int,
        original_denominator: Address,
        new_denominator: Address,
    ):
        feed = FEED_REGISTRY.getFeed(new_denominator, original_denominator)
        new_price = feed.latestAnswer()
        new_price_decimals = feed.decimals()

        if new_price_decimals < price_decimals:
            new_price *= 10 ** (price_decimals - new_price_decimals)
        else:
            price *= 10 ** (new_price_decimals - price_decimals)

        return (price * 10 ** price_decimals) // new_price, max(price_decimals, new_price_decimals)

    @flow()
    def flow_accept_elastic_chainlink_proposal(self):
        if len(self.elastic_chainlink_proposals) == 0:
            return

        onchain_proposal = random_bool()

        if onchain_proposal:
            proposal_hash = random.choice(list(self.elastic_chainlink_proposals.keys()))
            proposal, lender_spec = self.elastic_chainlink_proposals[proposal_hash]
            signature = b""
            inclusion_proof = []
        else:
            proposal, lender_spec = self._new_elastic_chainlink_proposal()
            proposal_hash = self.elastic_chainlink_proposal.getProposalHash(proposal)

            if random_bool():
                signature = Account(proposal.proposer).sign_structured(
                    proposal,
                    Eip712Domain(
                        name="PWNSimpleLoanElasticChainlinkProposal",
                        version="1.0",
                        chainId=chain.chain_id,
                        verifyingContract=self.elastic_chainlink_proposal,
                    ),
                )
                inclusion_proof = []
            else:
                tree = MerkleTree(hash_leaves=False)
                leaves = [random_bytes(32) for _ in range(random_int(1, 10))]
                leaves.append(proposal_hash)
                random.shuffle(leaves)

                for leaf in leaves:
                    tree.add_leaf(leaf)

                multiproposal = PWNSimpleLoanProposal.Multiproposal(tree.root)
                signature = Account(proposal.proposer).sign_structured(
                    multiproposal,
                    Eip712Domain(
                        name="PWNMultiproposal",
                    ),
                )
                inclusion_proof = tree.get_proof(tree.leaves.index(proposal_hash))

        collateral_decimals = DECIMALS[IERC20(proposal.collateralAddress)]
        credit_decimals = DECIMALS[IERC20(proposal.creditAddress)]

        credit_amount = random_int(
            proposal.minCreditAmount, MAX_TOKENS[IERC20(proposal.creditAddress)] * 10**credit_decimals
        )
        proposal_values = PWNSimpleLoanElasticChainlinkProposal.ProposalValues(
            credit_amount
        )

        collateral_price, collateral_price_decimals, collateral_denominator = (
            self._get_chainlink_latest_round_data(proposal.collateralAddress)
        )
        credit_price, credit_price_decimals, credit_denominator = (
            self._get_chainlink_latest_round_data(proposal.creditAddress)
        )

        if collateral_denominator != credit_denominator:
            if credit_denominator == Address(840):
                credit_price, credit_price_decimals = self._convert_price_denominator(
                    credit_price, credit_price_decimals, credit_denominator, collateral_denominator
                )
            elif collateral_denominator == Address(840):
                collateral_price, collateral_price_decimals = self._convert_price_denominator(
                    collateral_price, collateral_price_decimals, collateral_denominator, credit_denominator
                )
            elif credit_denominator == Address("0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE"):
                credit_price, credit_price_decimals = self._convert_price_denominator(
                    credit_price, credit_price_decimals, credit_denominator, collateral_denominator
                )
            else:
                collateral_price, collateral_price_decimals = self._convert_price_denominator(
                    collateral_price, collateral_price_decimals, collateral_denominator, credit_denominator
                )

        # same denominator
        if collateral_price_decimals > credit_price_decimals:
            credit_price *= 10 ** (collateral_price_decimals - credit_price_decimals)
        else:
            collateral_price *= 10 ** (
                credit_price_decimals - collateral_price_decimals
            )

        collateral_amount = (
            credit_amount
            * credit_price
            * 10_000
            * 10 ** max(0, collateral_decimals - credit_decimals)
            // (collateral_price * proposal.loanToValue)
        )
        if collateral_decimals < credit_decimals:
            collateral_amount //= 10 ** (credit_decimals - collateral_decimals)

        def revert_handler(tx: TransactionAbc) -> bool:
            if proposal.minCreditAmount == 0:
                assert (
                    tx.error
                    == PWNSimpleLoanElasticChainlinkProposal.MinCreditAmountNotSet()
                )
                return True
            elif isinstance(tx.error, Chainlink.ChainlinkFeedPriceTooOld):
                aggregator = FEED_REGISTRY.getFeed(tx.error.asset, tx.error.denominator)
                latest_data = self._get_aggregator_data(aggregator)
                assert (
                    latest_data.timestamp + MAX_CHAINLINK_FEED_PRICE_AGE
                    < tx.block.timestamp
                )

                # update Chainlink feed so it doesn't fail next time
                self._update_aggregator_price(
                    aggregator, round(latest_data.price * random.uniform(0.9, 1.1))
                )
                return True
            else:
                return False

        tx = self._accept_proposal(
            proposal,
            abi.encode(proposal, proposal_values),
            self.elastic_chainlink_proposal,
            collateral_amount,
            credit_amount,
            0,
            proposal.expiration,
            signature,
            inclusion_proof,
            chain.blocks["latest"].timestamp + 10,
            lender_spec,
            revert_handler,
        )

        if tx is None or tx.error is not None:
            self.elastic_chainlink_proposals.pop(proposal_hash, None)
        else:
            e = next(
                (e for e in tx.events if isinstance(e, PWNSimpleLoan.LOANCreated)), None
            )
            if e is not None:
                assert e.terms.collateral.amount == collateral_amount

    def _mint_erc4626_vault(self, token: IERC20, lender: Account, vault: MockERC4626, amount: int):
        mint_erc20(token, lender, amount)

        if amount > 0:
            with may_revert():
                token.approve(vault, 0, from_=lender)
            token.approve(vault, amount, from_=lender)

            vault.deposit(amount, lender, from_=lender)
            vault.approve(self.erc4626_adapter, amount, from_=lender)

        self.erc20_balances[token][vault] += amount

    def _mint_aave_pool(self, token: IERC20, lender: Account, pool: IAavePoolLike, amount: int):
        mint_erc20(token, lender, amount)

        if amount > 0:
            # mint a bit more because of rounding errors
            mint_erc20(token, lender, AAVE_EXTRA_DEPOSIT)

            with may_revert():
                token.approve(pool, 0, from_=lender)
            token.approve(pool, amount + AAVE_EXTRA_DEPOSIT, from_=lender)

            pool.supply(token, amount + AAVE_EXTRA_DEPOSIT, lender, 0, from_=lender)

        IERC20(pool.getReserveData(token).aTokenAddress).approve(self.aave_adapter, amount, from_=lender)
        # tokens inside Aave are not tracked

    def _mint_compound_pool(self, token: IERC20, lender: Account, pool: ICometLike, amount: int):
        mint_erc20(token, lender, amount)

        if amount > 0:
            # mint a bit more because of rounding errors
            mint_erc20(token, lender, COMP_EXTRA_DEPOSIT)

            with may_revert():
                token.approve(pool, 0, from_=lender)
            token.approve(pool, amount + COMP_EXTRA_DEPOSIT, from_=lender)

            pool.supply(token, amount + COMP_EXTRA_DEPOSIT, from_=lender)

        pool.allow(self.compound_adapter, True, from_=lender)
        # tokens inside Compound are not tracked

    def _permit(self, token: IERC20, owner: Account, amount: int) -> bytes:
        nonce = abi.decode(
            token.call(abi.encode_with_signature("nonces(address)", owner)),
            [uint],
        )
        permit = Permit(
            owner.address, self.vault.address, amount, nonce, uint256.max
        )
        domain = Eip712Domain(
            name=PERMIT[token].name,
            chainId=chain.chain_id,
            verifyingContract=token,
        )
        if PERMIT[token].version is not None:
            domain["version"] = PERMIT[token].version

        permit_signature = owner.sign_structured(permit, domain)
        return abi.encode(
            PWNPermit(
                token.address,
                owner.address,
                amount,
                uint256.max,
                permit_signature[64],
                permit_signature[:32],
                permit_signature[32:64],
            )
        )

    def _accept_proposal(
        self,
        proposal: Union[
            PWNSimpleLoanSimpleProposal.Proposal,
            PWNSimpleLoanDutchAuctionProposal.Proposal,
            PWNSimpleLoanElasticProposal.Proposal,
            PWNSimpleLoanElasticChainlinkProposal.Proposal,
            PWNSimpleLoanListProposal.Proposal,
        ],
        proposal_payload: bytes,
        proposal_contract: Account,
        collateral_amount: int,
        credit_amount: int,
        collateral_id: int,
        expiration: int,
        signature: bytes,
        inclusion_proof: List[bytes],
        target_time: int,
        lender_spec: Optional[PWNSimpleLoan.LenderSpec],
        pre_revert_handler: Optional[Callable[[TransactionAbc], bool]] = None,
    ) -> Optional[TransactionAbc]:
        acceptor = (
            random_account()
            if proposal.allowedAcceptor == Address.ZERO
            else Account(proposal.allowedAcceptor)
        )

        if lender_spec is None:
            lender_spec = self._random_lender_spec(
                acceptor, Account(proposal.creditAddress)
            )

        proposer = Account(proposal.proposer)

        borrower = acceptor if proposal.isOffer else proposer
        lender = proposer if proposal.isOffer else acceptor

        if proposal.refinancingLoanId == 0:
            # mint collateral
            if proposal.collateralCategory == MultiToken.Category.ERC20:
                collateral = IERC20(proposal.collateralAddress)

                if collateral_amount > 0:
                    mint_erc20(collateral, borrower, collateral_amount)
                    with may_revert():
                        collateral.approve(self.vault.address, 0, from_=borrower)
                    collateral.approve(self.vault.address, collateral_amount, from_=borrower)
                    self.erc20_balances[collateral][borrower] += collateral_amount
            elif proposal.collateralCategory == MultiToken.Category.ERC721:
                collateral = IERC721(proposal.collateralAddress)

                if collateral == self.loan_token:
                    try:
                        if collateral.ownerOf(collateral_id) != borrower.address:
                            return None
                    except Error:
                        return None
                else:
                    ERC721Mock(proposal.collateralAddress).mint(borrower, collateral_id)

                collateral.approve(self.vault.address, collateral_id, from_=borrower)

                self.erc721_owners[collateral][collateral_id] = borrower
            elif proposal.collateralCategory == MultiToken.Category.ERC1155:
                collateral = IERC1155(proposal.collateralAddress)
                mint_erc1155(collateral, borrower, collateral_id, collateral_amount)

                collateral.setApprovalForAll(self.vault, True, from_=borrower)
                self.erc1155_balances[collateral][borrower][collateral_id] += collateral_amount
            else:
                raise ValueError(
                    f"Unsupported collateral category: {proposal.collateralCategory}"
                )
        else:
            if proposal.refinancingLoanId not in self.loans:
                return None

            collateral = Account(proposal.collateralAddress)

        fee = credit_amount * self.fee // 10_000

        # mint credit
        credit = IERC20(proposal.creditAddress)

        if proposal.refinancingLoanId == 0:
            lender_credit_amount = credit_amount
            borrower_credit_amount = 0
            repayment_amount = 0
        else:
            repayment_amount = self._get_repayment_amount(self.loans[proposal.refinancingLoanId], target_time)
            prev_loan_owner = self.erc721_owners[IERC721(self.loan_token)][proposal.refinancingLoanId]

            # either old loan owner and new lender are different or they are the same, old loan owner did not change but source of funds did
            settle_lenders = (
                prev_loan_owner != lender or (
                    prev_loan_owner == self.loans[proposal.refinancingLoanId].lender and
                    self.loans[proposal.refinancingLoanId].source_of_funds.address != lender_spec.sourceOfFunds
                )
            )

            if settle_lenders:
                lender_credit_amount = credit_amount
            else:
                lender_credit_amount = fee + max(0, credit_amount - fee - repayment_amount)

            if repayment_amount > credit_amount - fee:
                # borrower needs to provide more funds
                borrower_credit_amount = repayment_amount - (credit_amount - fee)
            else:
                borrower_credit_amount = 0

        if lender_spec.sourceOfFunds == lender.address:
            mint_erc20(credit, lender, lender_credit_amount)
            self.erc20_balances[credit][lender] += lender_credit_amount
        elif (
            lender_spec.sourceOfFunds
            == self.erc4626_vaults[Account(proposal.creditAddress)].address
        ):
            vault = self.erc4626_vaults[Account(proposal.creditAddress)]
            self._mint_erc4626_vault(credit, lender, vault, lender_credit_amount)
        elif (
            Account(lender_spec.sourceOfFunds)
            == AAVE_POOLS.get(Account(proposal.creditAddress), None)
        ):
            pool = AAVE_POOLS[Account(proposal.creditAddress)]
            self._mint_aave_pool(credit, lender, pool, lender_credit_amount)
        elif (
            Account(lender_spec.sourceOfFunds)
            == COMP_POOLS.get(Account(proposal.creditAddress), None)
        ):
            pool = COMP_POOLS[Account(proposal.creditAddress)]
            self._mint_compound_pool(credit, lender, pool, lender_credit_amount)
        else:
            raise ValueError(f"Unsupported lender spec: {lender_spec.sourceOfFunds}")

        if borrower_credit_amount > 0:
            mint_erc20(credit, borrower, borrower_credit_amount)
            self.erc20_balances[credit][borrower] += borrower_credit_amount

        permit_data = b""
        if credit in PERMIT and acceptor == lender and lender_credit_amount > 0 and random_bool():
            permit_data = self._permit(credit, lender, lender_credit_amount)
        else:
            # approve
            if lender_credit_amount > 0:
                with may_revert():
                    credit.approve(self.vault, 0, from_=lender)
                credit.approve(self.vault, lender_credit_amount, from_=lender)

        if credit in PERMIT and acceptor == borrower and borrower_credit_amount > 0 and random_bool():
            permit_data = self._permit(credit, borrower, borrower_credit_amount)
        else:
            if borrower_credit_amount > 0:
                with may_revert():
                    credit.approve(self.vault, 0, from_=borrower)
                credit.approve(self.vault, borrower_credit_amount, from_=borrower)

        caller_spec = PWNSimpleLoan.CallerSpec(
            refinancingLoanId=proposal.refinancingLoanId,
            revokeNonce=random_bool(),
            nonce=random_nonce(),
            permitData=permit_data,
        )

        if proposal.collateralAddress == TOKENS[1]["MOCK"].address and random_bool():
            ERC721Mock(proposal.collateralAddress).setState(
                collateral_id, ERC721Mock.State.Extended
            )

        chain.set_next_block_timestamp(target_time)
        with may_revert() as ex:
            tx = self.vault.createLOAN(
                PWNSimpleLoan.ProposalSpec(
                    proposal_contract.address,
                    proposal_payload,
                    inclusion_proof,
                    signature,
                ),
                lender_spec,
                caller_spec,
                b"",
                from_=acceptor,
            )

        tx = ex.value.tx if ex.value is not None else tx

        if (
            ex.value is not None and
            lender_credit_amount > 0
        ):
            # withdraw back to prevent supply shock
            if Account(lender_spec.sourceOfFunds) == AAVE_POOLS.get(Account(proposal.creditAddress), None):
                pool = AAVE_POOLS[Account(proposal.creditAddress)]
                pool.withdraw(credit, lender_credit_amount, lender, from_=lender)

                self.erc20_balances[credit][lender] += lender_credit_amount
            elif Account(lender_spec.sourceOfFunds) == COMP_POOLS.get(Account(proposal.creditAddress), None):
                pool = COMP_POOLS[Account(proposal.creditAddress)]
                pool.withdraw(credit, lender_credit_amount, from_=lender)

                self.erc20_balances[credit][lender] += lender_credit_amount

        if (
            caller_spec.revokeNonce
            and caller_spec.nonce in self.revoked_nonces[acceptor]
        ):
            assert ex.value == PWNRevokedNonce.NonceAlreadyRevoked(
                acceptor.address, self.nonce_spaces[acceptor], caller_spec.nonce
            )
        elif (
            proposal.refinancingLoanId != 0 and (
                self.loans[proposal.refinancingLoanId].repaid or
                self.loans[proposal.refinancingLoanId].start_timestamp + self.loans[proposal.refinancingLoanId].duration <= tx.block.timestamp
        )):
            assert ex.value == PWNSimpleLoan.LoanDefaulted(
                self.loans[proposal.refinancingLoanId].start_timestamp + self.loans[proposal.refinancingLoanId].duration
            )
        elif pre_revert_handler is not None and pre_revert_handler(tx):
            # pre-revert handler handled the revert
            return tx
        elif lender == borrower:
            assert ex.value == PWNSimpleLoanProposal.AcceptorIsProposer(lender.address)
        elif tx.block.timestamp >= expiration:
            assert ex.value == Expired(tx.block.timestamp, expiration)
        elif (
            self.nonce_spaces[proposer] != proposal.nonceSpace
            or proposal.nonce in self.revoked_nonces[proposer]
        ):
            assert ex.value == PWNRevokedNonce.NonceNotUsable(
                proposer.address, proposal.nonceSpace, proposal.nonce
            )
        elif (
            proposal.availableCreditLimit != 0 and
            self.utilized_credit_ids[proposer][proposal.utilizedCreditId] + credit_amount > proposal.availableCreditLimit
        ):
            assert ex.value == PWNUtilizedCredit.AvailableCreditLimitExceeded(
                proposer.address, proposal.utilizedCreditId, self.utilized_credit_ids[proposer][proposal.utilizedCreditId] + credit_amount, proposal.availableCreditLimit
            )
        elif (
            proposal.collateralAddress == TOKENS[1]["MOCK"].address
            and ERC721Mock(proposal.collateralAddress).states(collateral_id)
            != ERC721Mock.State.Default
        ):
            assert ex.value == PWNSimpleLoanProposal.InvalidCollateralStateFingerprint(
                keccak256(abi.encode(uint8(1))),
                keccak256(abi.encode(uint8(0))),
            )
        elif (
            proposal.collateralAddress == self.loan_token.address
            and self.loan_token.getStateFingerprint(collateral_id)
            != proposal.collateralStateFingerprint
        ):
            assert ex.value == PWNSimpleLoanProposal.InvalidCollateralStateFingerprint(
                self.loan_token.getStateFingerprint(collateral_id),
                proposal.collateralStateFingerprint,
            )
        elif (
            proposal.durationOrDate > 10**9
            and proposal.durationOrDate <= tx.block.timestamp
        ):
            assert ex.value == PWNSimpleLoanProposal.DefaultDateInPast(
                proposal.durationOrDate, uint32(tx.block.timestamp)
            )
        elif (
            proposal.durationOrDate > 10**9
            and proposal.durationOrDate - tx.block.timestamp
            < MIN_DURATION
        ):
            assert ex.value == PWNSimpleLoan.InvalidDuration(
                proposal.durationOrDate - tx.block.timestamp, MIN_DURATION
            )
        elif ex.value is not None:
            assert collateral_amount == 0 or credit_amount == 0 or ex.value == Error('32')
        else:
            assert ex.value is None

            if caller_spec.revokeNonce:
                self.revoked_nonces[acceptor].add(caller_spec.nonce)

            if proposal.availableCreditLimit == 0:
                self.revoked_nonces[proposer].add(proposal.nonce)
            else:
                self.utilized_credit_ids[proposer][proposal.utilizedCreditId] += credit_amount

            if proposal.refinancingLoanId == 0:
                if proposal.collateralCategory == MultiToken.Category.ERC20:
                    self.erc20_balances[IERC20(collateral)][borrower] -= collateral_amount
                    self.erc20_balances[IERC20(collateral)][self.vault] += collateral_amount
                elif proposal.collateralCategory == MultiToken.Category.ERC721:
                    self.erc721_owners[IERC721(collateral)][collateral_id] = self.vault
                elif proposal.collateralCategory == MultiToken.Category.ERC1155:
                    self.erc1155_balances[IERC1155(collateral)][borrower][collateral_id] -= collateral_amount
                    self.erc1155_balances[IERC1155(collateral)][self.vault][collateral_id] += collateral_amount
                else:
                    raise ValueError(f"Unsupported collateral category: {proposal.collateralCategory}")

            if lender_spec.sourceOfFunds == lender.address:
                self.erc20_balances[credit][lender] -= lender_credit_amount
            elif (
                lender_spec.sourceOfFunds
                == self.erc4626_vaults[Account(proposal.creditAddress)].address
            ):
                self.erc20_balances[credit][vault] -= lender_credit_amount
            elif (
                Account(lender_spec.sourceOfFunds) in {
                    AAVE_POOLS.get(Account(proposal.creditAddress), None),
                    COMP_POOLS.get(Account(proposal.creditAddress), None),
                }
            ):
                pass
                # assets inside Aave are not tracked
            else:
                raise ValueError(f"Unsupported source of funds: {lender_spec.sourceOfFunds}")

            self.erc20_balances[credit][borrower] += credit_amount - fee - repayment_amount
            self.erc20_balances[credit][self.fee_collector] += fee
            self.erc721_owners[IERC721(self.loan_token)][tx.return_value] = lender

            if proposal.refinancingLoanId != 0:
                old_loan = self.loans[proposal.refinancingLoanId]

                if settle_lenders:
                    old_lender_repayment = repayment_amount
                else:
                    old_lender_repayment = max(0, repayment_amount - (credit_amount - fee))

                if prev_loan_owner == old_loan.lender:
                    # old lender did not change
                    if old_loan.source_of_funds == old_loan.lender:
                        self.erc20_balances[credit][old_loan.lender] += old_lender_repayment
                    elif old_loan.source_of_funds == self.erc4626_vaults[credit]:
                        self.erc20_balances[credit][self.erc4626_vaults[credit]] += old_lender_repayment
                    elif old_loan.source_of_funds in {
                        AAVE_POOLS.get(credit, None),
                        COMP_POOLS.get(credit, None),
                    }:
                        pass
                        # assets inside Aave and Compound are not tracked
                    else:
                        raise ValueError(f"Unsupported source of funds: {old_loan.source_of_funds}")
                else:
                    self.erc20_balances[credit][self.vault] += old_lender_repayment

                del self.erc721_owners[IERC721(self.loan_token)][proposal.refinancingLoanId]
                del self.loans[proposal.refinancingLoanId]

            self.loans[tx.return_value] = Loan(
                tx.return_value,
                credit,
                collateral,
                lender,
                borrower,
                proposal.fixedInterestAmount,
                credit_amount,
                collateral_amount,
                proposal.collateralCategory,
                collateral_id,
                proposal.accruingInterestAPR,
                tx.block.timestamp,
                (
                    proposal.durationOrDate
                    if proposal.durationOrDate <= 10**9
                    else proposal.durationOrDate - tx.block.timestamp
                ),
                False,
                Account(lender_spec.sourceOfFunds),
                [],
                proposal,
            )

            logger.info(f"Loan created")

        return tx

    @flow()
    def flow_accept_list_proposal(self):
        if len(self.list_proposals) == 0:
            return

        onchain_proposal = random_bool()

        if onchain_proposal:
            proposal_hash = random.choice(list(self.list_proposals.keys()))
            whitelisted_collateral_ids = self.whitelisted_collateral_ids.get(
                proposal_hash, None
            )
            proposal, lender_spec = self.list_proposals[proposal_hash]

            signature = b""
            inclusion_proof = []
        else:
            proposal, lender_spec, whitelisted_collateral_ids = (
                self._new_list_proposal()
            )
            proposal_hash = self.list_proposal.getProposalHash(proposal)

            if random_bool():
                signature = Account(proposal.proposer).sign_structured(
                    proposal,
                    Eip712Domain(
                        name="PWNSimpleLoanListProposal",
                        version="1.3",
                        chainId=chain.chain_id,
                        verifyingContract=self.list_proposal,
                    ),
                )
                inclusion_proof = []
            else:
                tree = MerkleTree(hash_leaves=False)
                leaves = [random_bytes(32) for _ in range(random_int(1, 10))]
                leaves.append(proposal_hash)
                random.shuffle(leaves)

                for leaf in leaves:
                    tree.add_leaf(leaf)

                multiproposal = PWNSimpleLoanProposal.Multiproposal(tree.root)
                signature = Account(proposal.proposer).sign_structured(
                    multiproposal,
                    Eip712Domain(
                        name="PWNMultiproposal",
                    ),
                )
                inclusion_proof = tree.get_proof(tree.leaves.index(proposal_hash))

        if whitelisted_collateral_ids is None:
            collateral_id = 0
            proposal_values = PWNSimpleLoanListProposal.ProposalValues(
                collateralId=collateral_id,
                merkleInclusionProof=[],
            )
        else:
            if proposal.refinancingLoanId == 0:
                try:
                    collateral_id = (
                        random.choice(
                            list(
                                whitelisted_collateral_ids
                                - OrderedSet(
                                    self.erc721_owners[
                                        IERC721(proposal.collateralAddress)
                                    ].keys()
                                )
                            )
                        )  # only can mint new ERC-721s
                        if proposal.collateralCategory != MultiToken.Category.ERC20
                        else 0
                    )
                except IndexError:
                    # ran out of whitelisted collateral ids
                    self.list_proposals.pop(proposal_hash, None)
                    return "no whitelisted collateral ids left"
            else:
                collateral_id = whitelisted_collateral_ids[0]

            tree = MerkleTree()
            for id in whitelisted_collateral_ids:
                tree.add_leaf(id.to_bytes(32, "big"))

            proposal_values = PWNSimpleLoanListProposal.ProposalValues(
                collateralId=collateral_id,
                merkleInclusionProof=tree.get_proof(
                    whitelisted_collateral_ids.index(collateral_id)
                ),
            )

        tx = self._accept_proposal(
            proposal,
            abi.encode(proposal, proposal_values),
            self.list_proposal,
            proposal.collateralAmount,
            proposal.creditAmount,
            collateral_id,
            proposal.expiration,
            signature,
            inclusion_proof,
            chain.blocks["latest"].timestamp + 10,
            lender_spec,
        )

        if tx is None or tx.error is not None:
            self.list_proposals.pop(proposal_hash, None)

    def _get_repayment_amount(self, loan: Loan, t: uint) -> int:
        # accrue in minutes, APR has 2 decimals
        mins_passed = (t - loan.start_timestamp) // 60
        return loan.credit_amount + loan.fixed_interest_amount + loan.credit_amount * loan.interest_apr * mins_passed // (365 * 24 * 60 * 100 * 100)

    @flow()
    def flow_repay_loan(self):
        if len(self.loans) == 0:
            return

        loan = random.choice(list(self.loans.values()))
        sender = random_account()

        # repay tx time may be different based on approval txs, set fixed
        t = chain.blocks["latest"].timestamp + 10
        credit_amount = self._get_repayment_amount(loan, t)

        mint_erc20(loan.credit, sender, credit_amount)
        self.erc20_balances[loan.credit][sender] += credit_amount

        if loan.credit in PERMIT and random_bool():
            nonce = abi.decode(
                loan.credit.call(abi.encode_with_signature("nonces(address)", sender)),
                [uint],
            )
            permit = Permit(
                sender.address, self.vault.address, credit_amount, nonce, uint256.max
            )
            domain = Eip712Domain(
                name=PERMIT[loan.credit].name,
                chainId=chain.chain_id,
                verifyingContract=loan.credit,
            )
            if PERMIT[loan.credit].version is not None:
                domain["version"] = PERMIT[loan.credit].version

            permit_signature = sender.sign_structured(permit, domain)
            permit_data = abi.encode(
                PWNPermit(
                    loan.credit.address,
                    sender.address,
                    credit_amount,
                    uint256.max,
                    permit_signature[64],
                    permit_signature[:32],
                    permit_signature[32:64],
                )
            )
        else:
            # approve
            if credit_amount > 0:
                with may_revert():
                    loan.credit.approve(self.vault, 0, from_=sender)
                loan.credit.approve(self.vault, credit_amount, from_=sender)

            permit_data = b""

        loan_owner = Account(self.loan_token.ownerOf(loan.id))

        chain.set_next_block_timestamp(t)
        with may_revert(PWNSimpleLoan.LoanDefaulted) as ex:
            tx = self.vault.repayLOAN(loan.id, permit_data, from_=sender)

        if chain.blocks["latest"].timestamp >= loan.start_timestamp + loan.duration:
            assert ex.value == PWNSimpleLoan.LoanDefaulted(
                loan.start_timestamp + loan.duration
            )
        else:
            assert ex.value is None

            self.erc20_balances[loan.credit][sender] -= credit_amount
            if loan_owner == loan.lender:
                if loan.source_of_funds == loan.lender:
                    self.erc20_balances[loan.credit][loan_owner] += credit_amount
                elif loan.source_of_funds == self.erc4626_vaults[loan.credit]:
                    self.erc20_balances[loan.credit][
                        self.erc4626_vaults[loan.credit]
                    ] += credit_amount
                elif loan.source_of_funds in {
                    AAVE_POOLS.get(loan.credit, None),
                    COMP_POOLS.get(loan.credit, None),
                }:
                    pass
                    # assets inside Aave and Compound are not tracked
                else:
                    raise ValueError(
                        f"Unsupported source of funds: {loan.source_of_funds}"
                    )
            else:
                self.erc20_balances[loan.credit][self.vault] += credit_amount

            if loan.collateral_category == MultiToken.Category.ERC20:
                self.erc20_balances[IERC20(loan.collateral)][
                    self.vault
                ] -= loan.collateral_amount
                self.erc20_balances[IERC20(loan.collateral)][
                    loan.borrower
                ] += loan.collateral_amount
            elif loan.collateral_category == MultiToken.Category.ERC721:
                self.erc721_owners[IERC721(loan.collateral)][
                    loan.collateral_id
                ] = loan.borrower
            elif loan.collateral_category == MultiToken.Category.ERC1155:
                self.erc1155_balances[IERC1155(loan.collateral)][
                    self.vault
                ][loan.collateral_id] -= loan.collateral_amount
                self.erc1155_balances[IERC1155(loan.collateral)][
                    loan.borrower
                ][loan.collateral_id] += loan.collateral_amount
            else:
                raise ValueError(
                    f"Unsupported collateral category: {loan.collateral_category}"
                )

            del self.loans[loan.id]
            del self.erc721_owners[IERC721(self.loan_token)][loan.id]

            logger.info(f"Loan repaid")

    @flow()
    def flow_claim_repaid_loan(self):
        loans = [
            l
            for l in self.loans.values()
            if l.repaid
            and self.erc721_owners[IERC721(self.loan_token)][l.id] != self.vault
        ]
        if len(loans) == 0:
            return

        loan = random.choice(loans)
        loan_owner = self.erc721_owners[IERC721(self.loan_token)][loan.id]

        tx = self.vault.claimLOAN(loan.id, from_=loan_owner)

        self.erc20_balances[loan.credit][self.vault] -= loan.credit_amount
        self.erc20_balances[loan.credit][loan_owner] += loan.credit_amount

        del self.loans[loan.id]
        del self.erc721_owners[IERC721(self.loan_token)][loan.id]

        logger.info(f"Repaid loan {loan.id} claimed")

    @flow()
    def flow_claim_expired_loan(self):
        t = chain.blocks["pending"].timestamp
        loans = [
            l
            for l in self.loans.values()
            if l.start_timestamp + l.duration < t
            and not l.repaid
            and self.erc721_owners[IERC721(self.loan_token)][l.id] != self.vault
        ]
        if len(loans) == 0:
            return

        loan = random.choice(loans)
        loan_owner = Account(self.loan_token.ownerOf(loan.id))

        tx = self.vault.claimLOAN(loan.id, from_=loan_owner)

        if loan.collateral_category == MultiToken.Category.ERC20:
            self.erc20_balances[IERC20(loan.collateral)][
                self.vault
            ] -= loan.collateral_amount
            self.erc20_balances[IERC20(loan.collateral)][
                loan_owner
            ] += loan.collateral_amount
        elif loan.collateral_category == MultiToken.Category.ERC721:
            self.erc721_owners[IERC721(loan.collateral)][
                loan.collateral_id
            ] = loan_owner
        elif loan.collateral_category == MultiToken.Category.ERC1155:
            self.erc1155_balances[IERC1155(loan.collateral)][
                self.vault
            ][loan.collateral_id] -= loan.collateral_amount
            self.erc1155_balances[IERC1155(loan.collateral)][
                loan_owner
            ][loan.collateral_id] += loan.collateral_amount
        else:
            raise ValueError(
                f"Unsupported collateral category: {loan.collateral_category}"
            )

        del self.loans[loan.id]
        del self.erc721_owners[IERC721(self.loan_token)][loan.id]

        logger.info(f"Expired loan {loan.id} claimed")

    @flow()
    def flow_transfer_loan_token(self):
        ids = [
            id
            for id in self.erc721_owners[IERC721(self.loan_token)].keys()
            if self.erc721_owners[IERC721(self.loan_token)][id] != self.vault
        ]
        if len(ids) == 0:
            return

        id = random.choice(ids)
        owner = self.erc721_owners[IERC721(self.loan_token)][id]
        recipient = random_account()

        tx = self.loan_token.transferFrom(owner, recipient, id, from_=owner)

        self.erc721_owners[IERC721(self.loan_token)][id] = recipient

        logger.info(f"Loan token {id} transferred from {owner} to {recipient}")

    def _new_extension_proposal(self, loan: Loan) -> PWNSimpleLoan.ExtensionProposal:
        loan_owner = self.erc721_owners[IERC721(self.loan_token)][loan.id]

        if random_bool() and loan_owner != loan.borrower:
            compensation_token = IERC20(random.choice(list(TOKENS[0].values())).address)
            compensation_amount = (
                random_int(1, MAX_TOKENS[compensation_token]) * DECIMALS[compensation_token]
            )
        else:
            compensation_token = Account(0)
            compensation_amount = 0

        proposer = random.choice([loan.borrower, loan_owner])

        return PWNSimpleLoan.ExtensionProposal(
            loanId=loan.id,
            compensationAddress=compensation_token.address,
            compensationAmount=compensation_amount,
            duration=random_int(1, 90) * 24 * 60 * 60,  # 1-90 days
            expiration=random_expiration(),
            proposer=proposer.address,
            nonceSpace=self.nonce_spaces[proposer],
            nonce=random_nonce(),
        )

    @flow()
    def flow_make_extension_proposal(self):
        loans = [
            l
            for l in self.loans.values()
            if self.erc721_owners[IERC721(self.loan_token)][l.id] != self.vault
        ]
        if len(loans) == 0:
            return

        loan = random.choice(loans)
        proposal = self._new_extension_proposal(loan)

        tx = self.vault.makeExtensionProposal(proposal, from_=proposal.proposer)

        loan.extension_proposals.append(proposal)

        logger.info(f"Extension proposal made")

    @flow()
    def flow_extend_loan(self):
        loans = [
            l
            for l in self.loans.values()
            if self.erc721_owners[IERC721(self.loan_token)][l.id] != self.vault
        ]
        if len(loans) == 0:
            return

        loan = random.choice(loans)

        if len(loan.extension_proposals) == 0 or random_bool():
            onchain_proposal = False
            proposal = self._new_extension_proposal(loan)

            signature = Account(proposal.proposer).sign_structured(
                proposal,
                Eip712Domain(
                    name="PWNSimpleLoan",
                    version="1.2",
                    chainId=chain.chain_id,
                    verifyingContract=self.vault,
                ),
            )
        else:
            onchain_proposal = True
            proposal = random.choice(loan.extension_proposals)
            signature = b""

        loan_owner = self.erc721_owners[IERC721(self.loan_token)][loan.id]
        proposer = Account(proposal.proposer)
        acceptor = (
            loan_owner if proposer == loan.borrower else loan.borrower
        )

        if proposal.compensationAmount > 0:
            compensation_token = IERC20(proposal.compensationAddress)
            mint_erc20(compensation_token, loan.borrower, proposal.compensationAmount)

            self.erc20_balances[compensation_token][
                loan.borrower
            ] += proposal.compensationAmount

            if (
                acceptor == loan.borrower
                and compensation_token in PERMIT
                and random_bool()
            ):
                # only accepting borrower can use permit
                nonce = abi.decode(
                    compensation_token.call(
                        abi.encode_with_signature("nonces(address)", loan.borrower)
                    ),
                    [uint],
                )
                permit = Permit(
                    loan.borrower.address,
                    self.vault.address,
                    proposal.compensationAmount,
                    nonce,
                    uint256.max,
                )
                domain = Eip712Domain(
                    name=PERMIT[compensation_token].name,
                    chainId=chain.chain_id,
                    verifyingContract=compensation_token,
                )
                if PERMIT[compensation_token].version is not None:
                    domain["version"] = PERMIT[compensation_token].version

                permit_signature = loan.borrower.sign_structured(permit, domain)
                permit_data = abi.encode(
                    PWNPermit(
                        compensation_token.address,
                        loan.borrower.address,
                        proposal.compensationAmount,
                        uint256.max,
                        permit_signature[64],
                        permit_signature[:32],
                        permit_signature[32:64],
                    )
                )
            else:
                with may_revert():
                    compensation_token.approve(self.vault, 0, from_=loan.borrower)
                compensation_token.approve(
                    self.vault, proposal.compensationAmount, from_=loan.borrower
                )

                permit_data = b""
        else:
            permit_data = b""

        with may_revert() as ex:
            tx = self.vault.extendLOAN(proposal, signature, permit_data, from_=acceptor)

        if chain.blocks["latest"].timestamp >= proposal.expiration:
            assert ex.value == Expired(
                chain.blocks["latest"].timestamp, proposal.expiration
            )
        elif (
            self.nonce_spaces[proposer] != proposal.nonceSpace
            or proposal.nonce in self.revoked_nonces[proposer]
        ):
            assert ex.value == PWNRevokedNonce.NonceNotUsable(
                proposer.address, proposal.nonceSpace, proposal.nonce
            )
        elif proposer not in {loan.borrower, loan_owner}:
            # loan token transferred in between making proposal and accepting it
            assert ex.value == PWNSimpleLoan.InvalidExtensionSigner(
                loan_owner.address,
                proposer.address,
            )
        elif loan_owner == loan.borrower and proposal.compensationAmount > 0:
            assert ex.value == PWNSimpleLoan.IncompleteTransfer()
        else:
            assert ex.value is None

            self.revoked_nonces[proposer].add(proposal.nonce)
            loan.duration += proposal.duration

            if proposal.compensationAmount > 0:
                self.erc20_balances[compensation_token][
                    loan.borrower
                ] -= proposal.compensationAmount
                self.erc20_balances[compensation_token][
                    loan_owner
                ] += proposal.compensationAmount

        if onchain_proposal:
            loan.extension_proposals.remove(proposal)

    @flow()
    def flow_revoke_nonce(self):
        account = random_account()
        nonce = random_nonce()

        with may_revert(PWNRevokedNonce.NonceAlreadyRevoked) as ex:
            tx = self.revoked_nonce.revokeNonce_(self.nonce_spaces[account], nonce, from_=account)

        if nonce in self.revoked_nonces[account]:
            assert ex.value is not None
        else:
            assert ex.value is None

            self.revoked_nonces[account].add(nonce)

            logger.info(f"Nonce {nonce} revoked")

    @flow(weight=30)
    def flow_revoke_nonce_space(self):
        account = random_account()

        tx = self.revoked_nonce.revokeNonceSpace(from_=account)

        self.nonce_spaces[account] += 1
        self.revoked_nonces[account].clear()

        logger.info(f"Nonce space revoked")

    @invariant(period=30)
    def invariant_erc20_balances(self):
        for contract in self.erc20_balances:
            for acc in self.erc20_balances[contract]:
                assert contract.balanceOf(acc) == self.erc20_balances[contract][acc]

    @invariant()
    def invariant_erc721_owners(self):
        for contract in self.erc721_owners:
            for token_id in self.erc721_owners[contract]:
                assert (
                    contract.ownerOf(token_id)
                    == self.erc721_owners[contract][token_id].address
                )

    @invariant()
    def invariant_erc1155_balances(self):
        for contract in self.erc1155_balances:
            for acc in self.erc1155_balances[contract]:
                for token_id in self.erc1155_balances[contract][acc]:
                    assert contract.balanceOf(acc, token_id) == self.erc1155_balances[contract][acc][token_id]


@chain.connect(fork="http://localhost:8545")
@on_revert(lambda e: print(e.tx.call_trace if e.tx is not None else None))
def test_fuzz():
    PWNFuzzTest().run(100, 2_000)
