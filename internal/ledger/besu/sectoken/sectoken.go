// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package sectoken

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
	_ = time.Tick
	_ = context.Background
)

// SecurityTokenAccount is an auto generated low-level Go binding around an user-defined struct.
type SecurityTokenAccount struct {
	Registered    bool
	Restricted    bool
	InstitutionId string
}

// SecurityTokenMetaData contains all meta data concerning the SecurityToken contract.
var SecurityTokenMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"name_\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"symbol_\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"admin\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"CONTROLLER_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"DEFAULT_ADMIN_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"ISSUER_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"TRANSFER_AGENT_ROLE\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"accountOf\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"tuple\",\"internalType\":\"structSecurityToken.Account\",\"components\":[{\"name\":\"registered\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"restricted\",\"type\":\"bool\",\"internalType\":\"bool\"},{\"name\":\"institutionId\",\"type\":\"string\",\"internalType\":\"string\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"agentInstitution\",\"inputs\":[{\"name\":\"agent\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"balanceOf\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"circulationActive\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"decimals\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"getRoleAdmin\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"grantRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"hasRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"issue\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"name\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"pause\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"paused\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"redeem\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"registerAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"institutionId\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"renounceRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"callerConfirmation\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"revokeRole\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setAccountRestricted\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"restricted\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setAgentInstitution\",\"inputs\":[{\"name\":\"agent\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"institutionId\",\"type\":\"string\",\"internalType\":\"string\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"setCirculation\",\"inputs\":[{\"name\":\"active\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"supportsInterface\",\"inputs\":[{\"name\":\"interfaceId\",\"type\":\"bytes4\",\"internalType\":\"bytes4\"}],\"outputs\":[{\"name\":\"\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"symbol\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"totalSupply\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"transferByAgent\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"unpause\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"event\",\"name\":\"AccountRegistered\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"institutionId\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"AccountRestrictionChanged\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"restricted\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"AgentInstitutionSet\",\"inputs\":[{\"name\":\"agent\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"institutionId\",\"type\":\"string\",\"indexed\":false,\"internalType\":\"string\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"CirculationChanged\",\"inputs\":[{\"name\":\"active\",\"type\":\"bool\",\"indexed\":false,\"internalType\":\"bool\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Issued\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Paused\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Redeemed\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleAdminChanged\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"previousAdminRole\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"newAdminRole\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleGranted\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"sender\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"RoleRevoked\",\"inputs\":[{\"name\":\"role\",\"type\":\"bytes32\",\"indexed\":true,\"internalType\":\"bytes32\"},{\"name\":\"account\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"sender\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Transferred\",\"inputs\":[{\"name\":\"from\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"to\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"amount\",\"type\":\"uint256\",\"indexed\":false,\"internalType\":\"uint256\"},{\"name\":\"agent\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Unpaused\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"indexed\":false,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AccessControlBadConfirmation\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"AccessControlUnauthorizedAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"neededRole\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"AccountAlreadyRegistered\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"AccountNotRegistered\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"AccountRestricted\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"CirculationHalted\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"EmptyInstitution\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"EnforcedPause\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ExpectedPause\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InstitutionMismatch\",\"inputs\":[{\"name\":\"agent\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"InsufficientBalance\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"balance\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"amount\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"SameAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ZeroAddress\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"ZeroAmount\",\"inputs\":[]}]",
	Bin: "0x608060405234801561000f575f5ffd5b50604051611bd9380380611bd983398101604081905261002e916101d5565b6001600160a01b0381166100555760405163d92e233d60e01b815260040160405180910390fd5b600261006184826102e9565b50600361006e83826102e9565b506005805460ff191660011790556100865f8261008f565b505050506103a7565b5f828152602081815260408083206001600160a01b038516845290915281205460ff1661012f575f838152602081815260408083206001600160a01b03861684529091529020805460ff191660011790556100e73390565b6001600160a01b0316826001600160a01b0316847f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d60405160405180910390a4506001610132565b505f5b92915050565b634e487b7160e01b5f52604160045260245ffd5b5f82601f83011261015b575f5ffd5b81516001600160401b0381111561017457610174610138565b604051601f8201601f19908116603f011681016001600160401b03811182821017156101a2576101a2610138565b6040528181528382016020018510156101b9575f5ffd5b8160208501602083015e5f918101602001919091529392505050565b5f5f5f606084860312156101e7575f5ffd5b83516001600160401b038111156101fc575f5ffd5b6102088682870161014c565b602086015190945090506001600160401b03811115610225575f5ffd5b6102318682870161014c565b604086015190935090506001600160a01b038116811461024f575f5ffd5b809150509250925092565b600181811c9082168061026e57607f821691505b60208210810361028c57634e487b7160e01b5f52602260045260245ffd5b50919050565b601f8211156102e457828211156102e457805f5260205f20601f840160051c60208510156102bd57505f5b90810190601f840160051c035f5b818110156102e0575f838201556001016102cb565b5050505b505050565b81516001600160401b0381111561030257610302610138565b61031681610310845461025a565b84610292565b6020601f821160018114610348575f83156103315750848201515b5f19600385901b1c1916600184901b1784556103a0565b5f84815260208120601f198516915b828110156103775787850151825560209485019460019092019101610357565b508482101561039457868401515f19600387901b60f8161c191681555b505060018360011b0184555b5050505050565b611825806103b45f395ff3fe608060405234801561000f575f5ffd5b50600436106101bb575f3560e01c80635c975abb116100f357806391d1485411610093578063a5775f661161006e578063a5775f66146103aa578063d547741f146103bd578063db1c13d8146103d0578063e61f69f3146103e4575f5ffd5b806391d148541461038857806395d89b411461039b578063a217fddf146103a3575f5ffd5b806382aefa24116100ce57806382aefa24146103335780638456cb591461035a578063867904b4146103625780638aa435b214610375575f5ffd5b80635c975abb146102e057806370a08231146102eb5780638086b8ba14610313575f5ffd5b8063248a9ca31161015e57806336568abe1161013957806336568abe146102a55780633c223604146102b85780633f4ba83a146102cb57806345040ecf146102d3575f5ffd5b8063248a9ca3146102625780632f2ff15d14610284578063313ce56714610297575f5ffd5b806310ff38821161019957806310ff38821461021e57806317bf50131461023357806318160ddd146102465780631e9a69501461024f575f5ffd5b806301ffc9a7146101bf57806306fdde03146101e7578063092c5b3b146101fc575b5f5ffd5b6101d26101cd36600461132f565b6103f7565b60405190151581526020015b60405180910390f35b6101ef61042d565b6040516101de919061138b565b6102105f5160206117e55f395f51905f5281565b6040519081526020016101de565b61023161022c3660046113b8565b6104b9565b005b6102316102413660046113b8565b61075b565b61021060045481565b61023161025d366004611436565b6107ea565b61021061027036600461145e565b5f9081526020819052604090206001015490565b610231610292366004611475565b6108ee565b6040515f81526020016101de565b6102316102b3366004611475565b610918565b6102316102c63660046114ae565b610950565b6102316109af565b6005546101d29060ff1681565b60015460ff166101d2565b6102106102f93660046114c7565b6001600160a01b03165f9081526006602052604090205490565b6103266103213660046114c7565b6109d1565b6040516101de91906114e0565b6102107f114e74f6ea3bd819998f78687bfcb11b140da08e9b7d222fa9c1f1ba1f2aa12281565b610231610ac3565b610231610370366004611436565b610ae2565b61023161038336600461151a565b610bc3565b6101d2610396366004611475565b610c4a565b6101ef610c72565b6102105f81565b6101ef6103b83660046114c7565b610c7f565b6102316103cb366004611475565b610d28565b6102105f5160206118055f395f51905f5281565b6102316103f2366004611542565b610d4c565b5f6001600160e01b03198216637965db0b60e01b148061042757506301ffc9a760e01b6001600160e01b03198316145b92915050565b6002805461043a9061157c565b80601f01602080910402602001604051908101604052809291908181526020018280546104669061157c565b80156104b15780601f10610488576101008083540402835291602001916104b1565b820191905f5260205f20905b81548152906001019060200180831161049457829003601f168201915b505050505081565b5f5160206118055f395f51905f526104d081610f28565b6001600160a01b0384166104f75760405163d92e233d60e01b815260040160405180910390fd5b5f829003610518576040516305f903ab60e01b815260040160405180910390fd5b6001600160a01b0384165f9081526007602052604090205460ff16156105615760405163486ef2d560e01b81526001600160a01b03851660048201526024015b60405180910390fd5b335f9081526008602052604090208054610636919061057f9061157c565b80601f01602080910402602001604051908101604052809291908181526020018280546105ab9061157c565b80156105f65780601f106105cd576101008083540402835291602001916105f6565b820191905f5260205f20905b8154815290600101906020018083116105d957829003601f168201915b505050505084848080601f0160208091040260200160405190810160405280939291908181526020018383808284375f92019190915250610f3292505050565b610664576040516379e6d22360e01b81523360048201526001600160a01b0385166024820152604401610558565b60405180606001604052806001151581526020015f1515815260200184848080601f0160208091040260200160405190810160405280939291908181526020018383808284375f9201829052509390945250506001600160a01b038716815260076020908152604091829020845181549286015161ffff1990931690151561ff001916176101009215159290920291909117815590830151909150600182019061070e908261161e565b50905050836001600160a01b03167f64f73046f77686e7ba3aebcaac09e4568d436c6968f446459528ce3ac8ccb60f848460405161074d9291906116dd565b60405180910390a250505050565b5f61076581610f28565b6001600160a01b03841661078c5760405163d92e233d60e01b815260040160405180910390fd5b6001600160a01b0384165f9081526008602052604090206107ae83858361170b565b50836001600160a01b03167f0a1043062bac78e0695d04a5f7b52d00c670f37212ff1a47d79cbf0ed4695a5a848460405161074d9291906116dd565b7f114e74f6ea3bd819998f78687bfcb11b140da08e9b7d222fa9c1f1ba1f2aa12261081481610f28565b61081c610f48565b815f0361083c57604051631f2a200560e01b815260040160405180910390fd5b61084583610f6e565b6001600160a01b0383165f90815260066020526040902054828110156108975760405163db42144d60e01b81526001600160a01b03851660048201526024810182905260448101849052606401610558565b6001600160a01b0384165f81815260066020526040908190208584039055600480548690039055517f4896181ff8f4543cc00db9fe9b6fb7e6f032b7eb772c72ab1ec1b4d2e03b93699061074d9086815260200190565b5f8281526020819052604090206001015461090881610f28565b6109128383610fb1565b50505050565b6001600160a01b03811633146109415760405163334bd91960e11b815260040160405180910390fd5b61094b8282611040565b505050565b5f5160206117e55f395f51905f5261096781610f28565b6005805460ff19168315159081179091556040519081527fdf4bf5b5390cf25ed671cc034d403491ffb6d1ef903d9c98709f92a59f1d2a8b9060200160405180910390a15050565b5f5160206117e55f395f51905f526109c681610f28565b6109ce6110a9565b50565b60408051606080820183525f80835260208084018290528385018390526001600160a01b0386168252600781529084902084519283018552805460ff8082161515855261010090910416151591830191909152600181018054939492939192840191610a3c9061157c565b80601f0160208091040260200160405190810160405280929190818152602001828054610a689061157c565b8015610ab35780601f10610a8a57610100808354040283529160200191610ab3565b820191905f5260205f20905b815481529060010190602001808311610a9657829003601f168201915b5050505050815250509050919050565b5f5160206117e55f395f51905f52610ada81610f28565b6109ce6110fb565b7f114e74f6ea3bd819998f78687bfcb11b140da08e9b7d222fa9c1f1ba1f2aa122610b0c81610f28565b610b14610f48565b815f03610b3457604051631f2a200560e01b815260040160405180910390fd5b610b3d83610f6e565b8160045f828254610b4e91906117c5565b90915550506001600160a01b0383165f9081526006602052604081208054849290610b7a9084906117c5565b90915550506040518281526001600160a01b038416907fa59f12e354e8cd10bb74c559844c2dd69a5458e31fe56c7594c62ca57480509a906020015b60405180910390a2505050565b5f5160206118055f395f51905f52610bda81610f28565b610be383610f6e565b610bec83611136565b6001600160a01b0383165f818152600760205260409081902080548515156101000261ff0019909116179055517f71e88be0e3db9d5ce7b5fbbb61cac85e312d6bc1bdf89360d0ab5dd3dd8e551790610bb690851515815260200190565b5f918252602082815260408084206001600160a01b0393909316845291905290205460ff1690565b6003805461043a9061157c565b6001600160a01b0381165f908152600860205260409020805460609190610ca59061157c565b80601f0160208091040260200160405190810160405280929190818152602001828054610cd19061157c565b8015610d1c5780601f10610cf357610100808354040283529160200191610d1c565b820191905f5260205f20905b815481529060010190602001808311610cff57829003601f168201915b50505050509050919050565b5f82815260208190526040902060010154610d4281610f28565b6109128383611040565b5f5160206118055f395f51905f52610d6381610f28565b610d6b610f48565b60055460ff16610d8e576040516364f74a1d60e01b815260040160405180910390fd5b815f03610dae57604051631f2a200560e01b815260040160405180910390fd5b826001600160a01b0316846001600160a01b031603610deb576040516396eab70d60e01b81526001600160a01b0385166004820152602401610558565b610df484610f6e565b610dfd83610f6e565b610e0684611136565b6001600160a01b0384165f90815260076020526040902054610100900460ff1615610e4f57604051634b5bafbd60e11b81526001600160a01b0385166004820152602401610558565b6001600160a01b0384165f9081526006602052604090205482811015610ea15760405163db42144d60e01b81526001600160a01b03861660048201526024810182905260448101849052606401610558565b6001600160a01b038086165f90815260066020526040808220868503905591861681529081208054859290610ed79084906117c5565b909155505060405183815233906001600160a01b0386811691908816907f0fb52b545faa9c90e004f29604a41ad8cdbb14e921764129b963b88a85416f4f9060200160405180910390a45050505050565b6109ce81336112d3565b8051602091820120825192909101919091201490565b60015460ff1615610f6c5760405163d93c066560e01b815260040160405180910390fd5b565b6001600160a01b0381165f9081526007602052604090205460ff166109ce5760405163a3f7445d60e01b81526001600160a01b0382166004820152602401610558565b5f610fbc8383610c4a565b611039575f838152602081815260408083206001600160a01b03861684529091529020805460ff19166001179055610ff13390565b6001600160a01b0316826001600160a01b0316847f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d60405160405180910390a4506001610427565b505f610427565b5f61104b8383610c4a565b15611039575f838152602081815260408083206001600160a01b0386168085529252808320805460ff1916905551339286917ff6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b9190a4506001610427565b6110b161130c565b6001805460ff191690557f5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa335b6040516001600160a01b03909116815260200160405180910390a1565b611103610f48565b6001805460ff1916811790557f62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258336110de565b335f908152600860205260409020805481906111519061157c565b159050806112a0575061129e8180546111699061157c565b80601f01602080910402602001604051908101604052809291908181526020018280546111959061157c565b80156111e05780601f106111b7576101008083540402835291602001916111e0565b820191905f5260205f20905b8154815290600101906020018083116111c357829003601f168201915b5050506001600160a01b0386165f908152600760205260409020600101805490925061120c915061157c565b80601f01602080910402602001604051908101604052809291908181526020018280546112389061157c565b80156112835780601f1061125a57610100808354040283529160200191611283565b820191905f5260205f20905b81548152906001019060200180831161126657829003601f168201915b50505050508051602091820120825192909101919091201490565b155b156112cf576040516379e6d22360e01b81523360048201526001600160a01b0383166024820152604401610558565b5050565b6112dd8282610c4a565b6112cf5760405163e2517d3f60e01b81526001600160a01b038216600482015260248101839052604401610558565b60015460ff16610f6c57604051638dfc202b60e01b815260040160405180910390fd5b5f6020828403121561133f575f5ffd5b81356001600160e01b031981168114611356575f5ffd5b9392505050565b5f81518084528060208401602086015e5f602082860101526020601f19601f83011685010191505092915050565b602081525f611356602083018461135d565b80356001600160a01b03811681146113b3575f5ffd5b919050565b5f5f5f604084860312156113ca575f5ffd5b6113d38461139d565b9250602084013567ffffffffffffffff8111156113ee575f5ffd5b8401601f810186136113fe575f5ffd5b803567ffffffffffffffff811115611414575f5ffd5b866020828401011115611425575f5ffd5b939660209190910195509293505050565b5f5f60408385031215611447575f5ffd5b6114508361139d565b946020939093013593505050565b5f6020828403121561146e575f5ffd5b5035919050565b5f5f60408385031215611486575f5ffd5b823591506114966020840161139d565b90509250929050565b803580151581146113b3575f5ffd5b5f602082840312156114be575f5ffd5b6113568261149f565b5f602082840312156114d7575f5ffd5b6113568261139d565b602081528151151560208201526020820151151560408201525f6040830151606080840152611512608084018261135d565b949350505050565b5f5f6040838503121561152b575f5ffd5b6115348361139d565b91506114966020840161149f565b5f5f5f60608486031215611554575f5ffd5b61155d8461139d565b925061156b6020850161139d565b929592945050506040919091013590565b600181811c9082168061159057607f821691505b6020821081036115ae57634e487b7160e01b5f52602260045260245ffd5b50919050565b634e487b7160e01b5f52604160045260245ffd5b601f82111561094b578282111561094b57805f5260205f20601f840160051c60208510156115f357505f5b90810190601f840160051c035f5b81811015611616575f83820155600101611601565b505050505050565b815167ffffffffffffffff811115611638576116386115b4565b61164c81611646845461157c565b846115c8565b6020601f82116001811461167e575f83156116675750848201515b5f19600385901b1c1916600184901b1784556116d6565b5f84815260208120601f198516915b828110156116ad578785015182556020948501946001909201910161168d565b50848210156116ca57868401515f19600387901b60f8161c191681555b505060018360011b0184555b5050505050565b60208152816020820152818360408301375f818301604090810191909152601f909201601f19160101919050565b67ffffffffffffffff831115611723576117236115b4565b61173783611731835461157c565b836115c8565b5f601f841160018114611768575f85156117515750838201355b5f19600387901b1c1916600186901b1783556116d6565b5f83815260208120601f198716915b828110156117975786850135825560209485019460019092019101611777565b50868210156117b3575f1960f88860031b161c19848701351681555b505060018560011b0183555050505050565b8082018082111561042757634e487b7160e01b5f52601160045260245ffdfe7b765e0e932d348852a6f810bfa1ab891e259123f02db8cdcde614c57022335790601cb45097851a246a5f8a72fbb27b3ef393b2a92d8fdd7aa24b1be6b2ed3b",
}

// SecurityTokenABI is the input ABI used to generate the binding from.
// Deprecated: Use SecurityTokenMetaData.ABI instead.
var SecurityTokenABI = SecurityTokenMetaData.ABI

// SecurityTokenBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use SecurityTokenMetaData.Bin instead.
var SecurityTokenBin = SecurityTokenMetaData.Bin

// DeploySecurityToken deploys a new Ethereum contract, binding an instance of SecurityToken to it.
func DeploySecurityToken(auth *bind.TransactOpts, backend bind.ContractBackend, name_ string, symbol_ string, admin common.Address) (common.Address, *types.Transaction, *SecurityToken, error) {
	parsed, err := SecurityTokenMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(SecurityTokenBin), backend, name_, symbol_, admin)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &SecurityToken{SecurityTokenCaller: SecurityTokenCaller{contract: contract}, SecurityTokenTransactor: SecurityTokenTransactor{contract: contract}, SecurityTokenFilterer: SecurityTokenFilterer{contract: contract}}, nil
}

// SecurityToken is an auto generated Go binding around an Ethereum contract.
type SecurityToken struct {
	SecurityTokenCaller     // Read-only binding to the contract
	SecurityTokenTransactor // Write-only binding to the contract
	SecurityTokenFilterer   // Log filterer for contract events
}

// SecurityTokenCaller is an auto generated read-only Go binding around an Ethereum contract.
type SecurityTokenCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SecurityTokenTransactor is an auto generated write-only Go binding around an Ethereum contract.
type SecurityTokenTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SecurityTokenFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type SecurityTokenFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// SecurityTokenSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type SecurityTokenSession struct {
	Contract     *SecurityToken    // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// SecurityTokenCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type SecurityTokenCallerSession struct {
	Contract *SecurityTokenCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts        // Call options to use throughout this session
}

// SecurityTokenTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type SecurityTokenTransactorSession struct {
	Contract     *SecurityTokenTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts        // Transaction auth options to use throughout this session
}

// SecurityTokenRaw is an auto generated low-level Go binding around an Ethereum contract.
type SecurityTokenRaw struct {
	Contract *SecurityToken // Generic contract binding to access the raw methods on
}

// SecurityTokenCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type SecurityTokenCallerRaw struct {
	Contract *SecurityTokenCaller // Generic read-only contract binding to access the raw methods on
}

// SecurityTokenTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type SecurityTokenTransactorRaw struct {
	Contract *SecurityTokenTransactor // Generic write-only contract binding to access the raw methods on
}

// NewSecurityToken creates a new instance of SecurityToken, bound to a specific deployed contract.
func NewSecurityToken(address common.Address, backend bind.ContractBackend) (*SecurityToken, error) {
	contract, err := bindSecurityToken(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &SecurityToken{SecurityTokenCaller: SecurityTokenCaller{contract: contract}, SecurityTokenTransactor: SecurityTokenTransactor{contract: contract}, SecurityTokenFilterer: SecurityTokenFilterer{contract: contract}}, nil
}

// NewSecurityTokenCaller creates a new read-only instance of SecurityToken, bound to a specific deployed contract.
func NewSecurityTokenCaller(address common.Address, caller bind.ContractCaller) (*SecurityTokenCaller, error) {
	contract, err := bindSecurityToken(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenCaller{contract: contract}, nil
}

// NewSecurityTokenTransactor creates a new write-only instance of SecurityToken, bound to a specific deployed contract.
func NewSecurityTokenTransactor(address common.Address, transactor bind.ContractTransactor) (*SecurityTokenTransactor, error) {
	contract, err := bindSecurityToken(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenTransactor{contract: contract}, nil
}

// NewSecurityTokenFilterer creates a new log filterer instance of SecurityToken, bound to a specific deployed contract.
func NewSecurityTokenFilterer(address common.Address, filterer bind.ContractFilterer) (*SecurityTokenFilterer, error) {
	contract, err := bindSecurityToken(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenFilterer{contract: contract}, nil
}

// bindSecurityToken binds a generic wrapper to an already deployed contract.
func bindSecurityToken(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := SecurityTokenMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SecurityToken *SecurityTokenRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SecurityToken.Contract.SecurityTokenCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SecurityToken *SecurityTokenRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SecurityToken.Contract.SecurityTokenTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SecurityToken *SecurityTokenRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SecurityToken.Contract.SecurityTokenTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_SecurityToken *SecurityTokenCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _SecurityToken.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_SecurityToken *SecurityTokenTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SecurityToken.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_SecurityToken *SecurityTokenTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _SecurityToken.Contract.contract.Transact(opts, method, params...)
}

// CONTROLLERROLE is a free data retrieval call binding the contract method 0x092c5b3b.
//
// Solidity: function CONTROLLER_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenCaller) CONTROLLERROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "CONTROLLER_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// CONTROLLERROLE is a free data retrieval call binding the contract method 0x092c5b3b.
//
// Solidity: function CONTROLLER_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenSession) CONTROLLERROLE() ([32]byte, error) {
	return _SecurityToken.Contract.CONTROLLERROLE(&_SecurityToken.CallOpts)
}

// CONTROLLERROLE is a free data retrieval call binding the contract method 0x092c5b3b.
//
// Solidity: function CONTROLLER_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenCallerSession) CONTROLLERROLE() ([32]byte, error) {
	return _SecurityToken.Contract.CONTROLLERROLE(&_SecurityToken.CallOpts)
}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenCaller) DEFAULTADMINROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "DEFAULT_ADMIN_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenSession) DEFAULTADMINROLE() ([32]byte, error) {
	return _SecurityToken.Contract.DEFAULTADMINROLE(&_SecurityToken.CallOpts)
}

// DEFAULTADMINROLE is a free data retrieval call binding the contract method 0xa217fddf.
//
// Solidity: function DEFAULT_ADMIN_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenCallerSession) DEFAULTADMINROLE() ([32]byte, error) {
	return _SecurityToken.Contract.DEFAULTADMINROLE(&_SecurityToken.CallOpts)
}

// ISSUERROLE is a free data retrieval call binding the contract method 0x82aefa24.
//
// Solidity: function ISSUER_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenCaller) ISSUERROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "ISSUER_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ISSUERROLE is a free data retrieval call binding the contract method 0x82aefa24.
//
// Solidity: function ISSUER_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenSession) ISSUERROLE() ([32]byte, error) {
	return _SecurityToken.Contract.ISSUERROLE(&_SecurityToken.CallOpts)
}

// ISSUERROLE is a free data retrieval call binding the contract method 0x82aefa24.
//
// Solidity: function ISSUER_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenCallerSession) ISSUERROLE() ([32]byte, error) {
	return _SecurityToken.Contract.ISSUERROLE(&_SecurityToken.CallOpts)
}

// TRANSFERAGENTROLE is a free data retrieval call binding the contract method 0xdb1c13d8.
//
// Solidity: function TRANSFER_AGENT_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenCaller) TRANSFERAGENTROLE(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "TRANSFER_AGENT_ROLE")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// TRANSFERAGENTROLE is a free data retrieval call binding the contract method 0xdb1c13d8.
//
// Solidity: function TRANSFER_AGENT_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenSession) TRANSFERAGENTROLE() ([32]byte, error) {
	return _SecurityToken.Contract.TRANSFERAGENTROLE(&_SecurityToken.CallOpts)
}

// TRANSFERAGENTROLE is a free data retrieval call binding the contract method 0xdb1c13d8.
//
// Solidity: function TRANSFER_AGENT_ROLE() view returns(bytes32)
func (_SecurityToken *SecurityTokenCallerSession) TRANSFERAGENTROLE() ([32]byte, error) {
	return _SecurityToken.Contract.TRANSFERAGENTROLE(&_SecurityToken.CallOpts)
}

// AccountOf is a free data retrieval call binding the contract method 0x8086b8ba.
//
// Solidity: function accountOf(address account) view returns((bool,bool,string))
func (_SecurityToken *SecurityTokenCaller) AccountOf(opts *bind.CallOpts, account common.Address) (SecurityTokenAccount, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "accountOf", account)

	if err != nil {
		return *new(SecurityTokenAccount), err
	}

	out0 := *abi.ConvertType(out[0], new(SecurityTokenAccount)).(*SecurityTokenAccount)

	return out0, err

}

// AccountOf is a free data retrieval call binding the contract method 0x8086b8ba.
//
// Solidity: function accountOf(address account) view returns((bool,bool,string))
func (_SecurityToken *SecurityTokenSession) AccountOf(account common.Address) (SecurityTokenAccount, error) {
	return _SecurityToken.Contract.AccountOf(&_SecurityToken.CallOpts, account)
}

// AccountOf is a free data retrieval call binding the contract method 0x8086b8ba.
//
// Solidity: function accountOf(address account) view returns((bool,bool,string))
func (_SecurityToken *SecurityTokenCallerSession) AccountOf(account common.Address) (SecurityTokenAccount, error) {
	return _SecurityToken.Contract.AccountOf(&_SecurityToken.CallOpts, account)
}

// AgentInstitution is a free data retrieval call binding the contract method 0xa5775f66.
//
// Solidity: function agentInstitution(address agent) view returns(string)
func (_SecurityToken *SecurityTokenCaller) AgentInstitution(opts *bind.CallOpts, agent common.Address) (string, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "agentInstitution", agent)

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// AgentInstitution is a free data retrieval call binding the contract method 0xa5775f66.
//
// Solidity: function agentInstitution(address agent) view returns(string)
func (_SecurityToken *SecurityTokenSession) AgentInstitution(agent common.Address) (string, error) {
	return _SecurityToken.Contract.AgentInstitution(&_SecurityToken.CallOpts, agent)
}

// AgentInstitution is a free data retrieval call binding the contract method 0xa5775f66.
//
// Solidity: function agentInstitution(address agent) view returns(string)
func (_SecurityToken *SecurityTokenCallerSession) AgentInstitution(agent common.Address) (string, error) {
	return _SecurityToken.Contract.AgentInstitution(&_SecurityToken.CallOpts, agent)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_SecurityToken *SecurityTokenCaller) BalanceOf(opts *bind.CallOpts, account common.Address) (*big.Int, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "balanceOf", account)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_SecurityToken *SecurityTokenSession) BalanceOf(account common.Address) (*big.Int, error) {
	return _SecurityToken.Contract.BalanceOf(&_SecurityToken.CallOpts, account)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(address account) view returns(uint256)
func (_SecurityToken *SecurityTokenCallerSession) BalanceOf(account common.Address) (*big.Int, error) {
	return _SecurityToken.Contract.BalanceOf(&_SecurityToken.CallOpts, account)
}

// CirculationActive is a free data retrieval call binding the contract method 0x45040ecf.
//
// Solidity: function circulationActive() view returns(bool)
func (_SecurityToken *SecurityTokenCaller) CirculationActive(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "circulationActive")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// CirculationActive is a free data retrieval call binding the contract method 0x45040ecf.
//
// Solidity: function circulationActive() view returns(bool)
func (_SecurityToken *SecurityTokenSession) CirculationActive() (bool, error) {
	return _SecurityToken.Contract.CirculationActive(&_SecurityToken.CallOpts)
}

// CirculationActive is a free data retrieval call binding the contract method 0x45040ecf.
//
// Solidity: function circulationActive() view returns(bool)
func (_SecurityToken *SecurityTokenCallerSession) CirculationActive() (bool, error) {
	return _SecurityToken.Contract.CirculationActive(&_SecurityToken.CallOpts)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() pure returns(uint8)
func (_SecurityToken *SecurityTokenCaller) Decimals(opts *bind.CallOpts) (uint8, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "decimals")

	if err != nil {
		return *new(uint8), err
	}

	out0 := *abi.ConvertType(out[0], new(uint8)).(*uint8)

	return out0, err

}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() pure returns(uint8)
func (_SecurityToken *SecurityTokenSession) Decimals() (uint8, error) {
	return _SecurityToken.Contract.Decimals(&_SecurityToken.CallOpts)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() pure returns(uint8)
func (_SecurityToken *SecurityTokenCallerSession) Decimals() (uint8, error) {
	return _SecurityToken.Contract.Decimals(&_SecurityToken.CallOpts)
}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_SecurityToken *SecurityTokenCaller) GetRoleAdmin(opts *bind.CallOpts, role [32]byte) ([32]byte, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "getRoleAdmin", role)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_SecurityToken *SecurityTokenSession) GetRoleAdmin(role [32]byte) ([32]byte, error) {
	return _SecurityToken.Contract.GetRoleAdmin(&_SecurityToken.CallOpts, role)
}

// GetRoleAdmin is a free data retrieval call binding the contract method 0x248a9ca3.
//
// Solidity: function getRoleAdmin(bytes32 role) view returns(bytes32)
func (_SecurityToken *SecurityTokenCallerSession) GetRoleAdmin(role [32]byte) ([32]byte, error) {
	return _SecurityToken.Contract.GetRoleAdmin(&_SecurityToken.CallOpts, role)
}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_SecurityToken *SecurityTokenCaller) HasRole(opts *bind.CallOpts, role [32]byte, account common.Address) (bool, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "hasRole", role, account)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_SecurityToken *SecurityTokenSession) HasRole(role [32]byte, account common.Address) (bool, error) {
	return _SecurityToken.Contract.HasRole(&_SecurityToken.CallOpts, role, account)
}

// HasRole is a free data retrieval call binding the contract method 0x91d14854.
//
// Solidity: function hasRole(bytes32 role, address account) view returns(bool)
func (_SecurityToken *SecurityTokenCallerSession) HasRole(role [32]byte, account common.Address) (bool, error) {
	return _SecurityToken.Contract.HasRole(&_SecurityToken.CallOpts, role, account)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_SecurityToken *SecurityTokenCaller) Name(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "name")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_SecurityToken *SecurityTokenSession) Name() (string, error) {
	return _SecurityToken.Contract.Name(&_SecurityToken.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() view returns(string)
func (_SecurityToken *SecurityTokenCallerSession) Name() (string, error) {
	return _SecurityToken.Contract.Name(&_SecurityToken.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_SecurityToken *SecurityTokenCaller) Paused(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "paused")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_SecurityToken *SecurityTokenSession) Paused() (bool, error) {
	return _SecurityToken.Contract.Paused(&_SecurityToken.CallOpts)
}

// Paused is a free data retrieval call binding the contract method 0x5c975abb.
//
// Solidity: function paused() view returns(bool)
func (_SecurityToken *SecurityTokenCallerSession) Paused() (bool, error) {
	return _SecurityToken.Contract.Paused(&_SecurityToken.CallOpts)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_SecurityToken *SecurityTokenCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_SecurityToken *SecurityTokenSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _SecurityToken.Contract.SupportsInterface(&_SecurityToken.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_SecurityToken *SecurityTokenCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _SecurityToken.Contract.SupportsInterface(&_SecurityToken.CallOpts, interfaceId)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_SecurityToken *SecurityTokenCaller) Symbol(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "symbol")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_SecurityToken *SecurityTokenSession) Symbol() (string, error) {
	return _SecurityToken.Contract.Symbol(&_SecurityToken.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() view returns(string)
func (_SecurityToken *SecurityTokenCallerSession) Symbol() (string, error) {
	return _SecurityToken.Contract.Symbol(&_SecurityToken.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_SecurityToken *SecurityTokenCaller) TotalSupply(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _SecurityToken.contract.Call(opts, &out, "totalSupply")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_SecurityToken *SecurityTokenSession) TotalSupply() (*big.Int, error) {
	return _SecurityToken.Contract.TotalSupply(&_SecurityToken.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() view returns(uint256)
func (_SecurityToken *SecurityTokenCallerSession) TotalSupply() (*big.Int, error) {
	return _SecurityToken.Contract.TotalSupply(&_SecurityToken.CallOpts)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_SecurityToken *SecurityTokenTransactor) GrantRole(opts *bind.TransactOpts, role [32]byte, account common.Address) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "grantRole", role, account)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_SecurityToken *SecurityTokenSession) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _SecurityToken.Contract.GrantRole(&_SecurityToken.TransactOpts, role, account)
}

// GrantRole is a paid mutator transaction binding the contract method 0x2f2ff15d.
//
// Solidity: function grantRole(bytes32 role, address account) returns()
func (_SecurityToken *SecurityTokenTransactorSession) GrantRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _SecurityToken.Contract.GrantRole(&_SecurityToken.TransactOpts, role, account)
}

// Issue is a paid mutator transaction binding the contract method 0x867904b4.
//
// Solidity: function issue(address account, uint256 amount) returns()
func (_SecurityToken *SecurityTokenTransactor) Issue(opts *bind.TransactOpts, account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "issue", account, amount)
}

// Issue is a paid mutator transaction binding the contract method 0x867904b4.
//
// Solidity: function issue(address account, uint256 amount) returns()
func (_SecurityToken *SecurityTokenSession) Issue(account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SecurityToken.Contract.Issue(&_SecurityToken.TransactOpts, account, amount)
}

// Issue is a paid mutator transaction binding the contract method 0x867904b4.
//
// Solidity: function issue(address account, uint256 amount) returns()
func (_SecurityToken *SecurityTokenTransactorSession) Issue(account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SecurityToken.Contract.Issue(&_SecurityToken.TransactOpts, account, amount)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_SecurityToken *SecurityTokenTransactor) Pause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "pause")
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_SecurityToken *SecurityTokenSession) Pause() (*types.Transaction, error) {
	return _SecurityToken.Contract.Pause(&_SecurityToken.TransactOpts)
}

// Pause is a paid mutator transaction binding the contract method 0x8456cb59.
//
// Solidity: function pause() returns()
func (_SecurityToken *SecurityTokenTransactorSession) Pause() (*types.Transaction, error) {
	return _SecurityToken.Contract.Pause(&_SecurityToken.TransactOpts)
}

// Redeem is a paid mutator transaction binding the contract method 0x1e9a6950.
//
// Solidity: function redeem(address account, uint256 amount) returns()
func (_SecurityToken *SecurityTokenTransactor) Redeem(opts *bind.TransactOpts, account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "redeem", account, amount)
}

// Redeem is a paid mutator transaction binding the contract method 0x1e9a6950.
//
// Solidity: function redeem(address account, uint256 amount) returns()
func (_SecurityToken *SecurityTokenSession) Redeem(account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SecurityToken.Contract.Redeem(&_SecurityToken.TransactOpts, account, amount)
}

// Redeem is a paid mutator transaction binding the contract method 0x1e9a6950.
//
// Solidity: function redeem(address account, uint256 amount) returns()
func (_SecurityToken *SecurityTokenTransactorSession) Redeem(account common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SecurityToken.Contract.Redeem(&_SecurityToken.TransactOpts, account, amount)
}

// RegisterAccount is a paid mutator transaction binding the contract method 0x10ff3882.
//
// Solidity: function registerAccount(address account, string institutionId) returns()
func (_SecurityToken *SecurityTokenTransactor) RegisterAccount(opts *bind.TransactOpts, account common.Address, institutionId string) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "registerAccount", account, institutionId)
}

// RegisterAccount is a paid mutator transaction binding the contract method 0x10ff3882.
//
// Solidity: function registerAccount(address account, string institutionId) returns()
func (_SecurityToken *SecurityTokenSession) RegisterAccount(account common.Address, institutionId string) (*types.Transaction, error) {
	return _SecurityToken.Contract.RegisterAccount(&_SecurityToken.TransactOpts, account, institutionId)
}

// RegisterAccount is a paid mutator transaction binding the contract method 0x10ff3882.
//
// Solidity: function registerAccount(address account, string institutionId) returns()
func (_SecurityToken *SecurityTokenTransactorSession) RegisterAccount(account common.Address, institutionId string) (*types.Transaction, error) {
	return _SecurityToken.Contract.RegisterAccount(&_SecurityToken.TransactOpts, account, institutionId)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_SecurityToken *SecurityTokenTransactor) RenounceRole(opts *bind.TransactOpts, role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "renounceRole", role, callerConfirmation)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_SecurityToken *SecurityTokenSession) RenounceRole(role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _SecurityToken.Contract.RenounceRole(&_SecurityToken.TransactOpts, role, callerConfirmation)
}

// RenounceRole is a paid mutator transaction binding the contract method 0x36568abe.
//
// Solidity: function renounceRole(bytes32 role, address callerConfirmation) returns()
func (_SecurityToken *SecurityTokenTransactorSession) RenounceRole(role [32]byte, callerConfirmation common.Address) (*types.Transaction, error) {
	return _SecurityToken.Contract.RenounceRole(&_SecurityToken.TransactOpts, role, callerConfirmation)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_SecurityToken *SecurityTokenTransactor) RevokeRole(opts *bind.TransactOpts, role [32]byte, account common.Address) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "revokeRole", role, account)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_SecurityToken *SecurityTokenSession) RevokeRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _SecurityToken.Contract.RevokeRole(&_SecurityToken.TransactOpts, role, account)
}

// RevokeRole is a paid mutator transaction binding the contract method 0xd547741f.
//
// Solidity: function revokeRole(bytes32 role, address account) returns()
func (_SecurityToken *SecurityTokenTransactorSession) RevokeRole(role [32]byte, account common.Address) (*types.Transaction, error) {
	return _SecurityToken.Contract.RevokeRole(&_SecurityToken.TransactOpts, role, account)
}

// SetAccountRestricted is a paid mutator transaction binding the contract method 0x8aa435b2.
//
// Solidity: function setAccountRestricted(address account, bool restricted) returns()
func (_SecurityToken *SecurityTokenTransactor) SetAccountRestricted(opts *bind.TransactOpts, account common.Address, restricted bool) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "setAccountRestricted", account, restricted)
}

// SetAccountRestricted is a paid mutator transaction binding the contract method 0x8aa435b2.
//
// Solidity: function setAccountRestricted(address account, bool restricted) returns()
func (_SecurityToken *SecurityTokenSession) SetAccountRestricted(account common.Address, restricted bool) (*types.Transaction, error) {
	return _SecurityToken.Contract.SetAccountRestricted(&_SecurityToken.TransactOpts, account, restricted)
}

// SetAccountRestricted is a paid mutator transaction binding the contract method 0x8aa435b2.
//
// Solidity: function setAccountRestricted(address account, bool restricted) returns()
func (_SecurityToken *SecurityTokenTransactorSession) SetAccountRestricted(account common.Address, restricted bool) (*types.Transaction, error) {
	return _SecurityToken.Contract.SetAccountRestricted(&_SecurityToken.TransactOpts, account, restricted)
}

// SetAgentInstitution is a paid mutator transaction binding the contract method 0x17bf5013.
//
// Solidity: function setAgentInstitution(address agent, string institutionId) returns()
func (_SecurityToken *SecurityTokenTransactor) SetAgentInstitution(opts *bind.TransactOpts, agent common.Address, institutionId string) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "setAgentInstitution", agent, institutionId)
}

// SetAgentInstitution is a paid mutator transaction binding the contract method 0x17bf5013.
//
// Solidity: function setAgentInstitution(address agent, string institutionId) returns()
func (_SecurityToken *SecurityTokenSession) SetAgentInstitution(agent common.Address, institutionId string) (*types.Transaction, error) {
	return _SecurityToken.Contract.SetAgentInstitution(&_SecurityToken.TransactOpts, agent, institutionId)
}

// SetAgentInstitution is a paid mutator transaction binding the contract method 0x17bf5013.
//
// Solidity: function setAgentInstitution(address agent, string institutionId) returns()
func (_SecurityToken *SecurityTokenTransactorSession) SetAgentInstitution(agent common.Address, institutionId string) (*types.Transaction, error) {
	return _SecurityToken.Contract.SetAgentInstitution(&_SecurityToken.TransactOpts, agent, institutionId)
}

// SetCirculation is a paid mutator transaction binding the contract method 0x3c223604.
//
// Solidity: function setCirculation(bool active) returns()
func (_SecurityToken *SecurityTokenTransactor) SetCirculation(opts *bind.TransactOpts, active bool) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "setCirculation", active)
}

// SetCirculation is a paid mutator transaction binding the contract method 0x3c223604.
//
// Solidity: function setCirculation(bool active) returns()
func (_SecurityToken *SecurityTokenSession) SetCirculation(active bool) (*types.Transaction, error) {
	return _SecurityToken.Contract.SetCirculation(&_SecurityToken.TransactOpts, active)
}

// SetCirculation is a paid mutator transaction binding the contract method 0x3c223604.
//
// Solidity: function setCirculation(bool active) returns()
func (_SecurityToken *SecurityTokenTransactorSession) SetCirculation(active bool) (*types.Transaction, error) {
	return _SecurityToken.Contract.SetCirculation(&_SecurityToken.TransactOpts, active)
}

// TransferByAgent is a paid mutator transaction binding the contract method 0xe61f69f3.
//
// Solidity: function transferByAgent(address from, address to, uint256 amount) returns()
func (_SecurityToken *SecurityTokenTransactor) TransferByAgent(opts *bind.TransactOpts, from common.Address, to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "transferByAgent", from, to, amount)
}

// TransferByAgent is a paid mutator transaction binding the contract method 0xe61f69f3.
//
// Solidity: function transferByAgent(address from, address to, uint256 amount) returns()
func (_SecurityToken *SecurityTokenSession) TransferByAgent(from common.Address, to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SecurityToken.Contract.TransferByAgent(&_SecurityToken.TransactOpts, from, to, amount)
}

// TransferByAgent is a paid mutator transaction binding the contract method 0xe61f69f3.
//
// Solidity: function transferByAgent(address from, address to, uint256 amount) returns()
func (_SecurityToken *SecurityTokenTransactorSession) TransferByAgent(from common.Address, to common.Address, amount *big.Int) (*types.Transaction, error) {
	return _SecurityToken.Contract.TransferByAgent(&_SecurityToken.TransactOpts, from, to, amount)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_SecurityToken *SecurityTokenTransactor) Unpause(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _SecurityToken.contract.Transact(opts, "unpause")
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_SecurityToken *SecurityTokenSession) Unpause() (*types.Transaction, error) {
	return _SecurityToken.Contract.Unpause(&_SecurityToken.TransactOpts)
}

// Unpause is a paid mutator transaction binding the contract method 0x3f4ba83a.
//
// Solidity: function unpause() returns()
func (_SecurityToken *SecurityTokenTransactorSession) Unpause() (*types.Transaction, error) {
	return _SecurityToken.Contract.Unpause(&_SecurityToken.TransactOpts)
}

// SecurityTokenAccountRegisteredIterator is returned from FilterAccountRegistered and is used to iterate over the raw logs and unpacked data for AccountRegistered events raised by the SecurityToken contract.
type SecurityTokenAccountRegisteredIterator struct {
	Event *SecurityTokenAccountRegistered // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenAccountRegisteredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenAccountRegistered)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenAccountRegistered)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenAccountRegisteredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenAccountRegisteredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenAccountRegistered represents a AccountRegistered event raised by the SecurityToken contract.
type SecurityTokenAccountRegistered struct {
	Account       common.Address
	InstitutionId string
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterAccountRegistered is a free log retrieval operation binding the contract event 0x64f73046f77686e7ba3aebcaac09e4568d436c6968f446459528ce3ac8ccb60f.
//
// Solidity: event AccountRegistered(address indexed account, string institutionId)
func (_SecurityToken *SecurityTokenFilterer) FilterAccountRegistered(opts *bind.FilterOpts, account []common.Address) (*SecurityTokenAccountRegisteredIterator, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "AccountRegistered", accountRule)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenAccountRegisteredIterator{contract: _SecurityToken.contract, event: "AccountRegistered", logs: logs, sub: sub}, nil
}

// WatchAccountRegistered is a free log subscription operation binding the contract event 0x64f73046f77686e7ba3aebcaac09e4568d436c6968f446459528ce3ac8ccb60f.
//
// Solidity: event AccountRegistered(address indexed account, string institutionId)
func (_SecurityToken *SecurityTokenFilterer) WatchAccountRegistered(opts *bind.WatchOpts, sink chan<- *SecurityTokenAccountRegistered, account []common.Address) (event.Subscription, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "AccountRegistered", accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenAccountRegistered)
				if err := _SecurityToken.contract.UnpackLog(event, "AccountRegistered", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAccountRegistered is a log parse operation binding the contract event 0x64f73046f77686e7ba3aebcaac09e4568d436c6968f446459528ce3ac8ccb60f.
//
// Solidity: event AccountRegistered(address indexed account, string institutionId)
func (_SecurityToken *SecurityTokenFilterer) ParseAccountRegistered(log types.Log) (*SecurityTokenAccountRegistered, error) {
	event := new(SecurityTokenAccountRegistered)
	if err := _SecurityToken.contract.UnpackLog(event, "AccountRegistered", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenAccountRestrictionChangedIterator is returned from FilterAccountRestrictionChanged and is used to iterate over the raw logs and unpacked data for AccountRestrictionChanged events raised by the SecurityToken contract.
type SecurityTokenAccountRestrictionChangedIterator struct {
	Event *SecurityTokenAccountRestrictionChanged // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenAccountRestrictionChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenAccountRestrictionChanged)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenAccountRestrictionChanged)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenAccountRestrictionChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenAccountRestrictionChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenAccountRestrictionChanged represents a AccountRestrictionChanged event raised by the SecurityToken contract.
type SecurityTokenAccountRestrictionChanged struct {
	Account    common.Address
	Restricted bool
	Raw        types.Log // Blockchain specific contextual infos
}

// FilterAccountRestrictionChanged is a free log retrieval operation binding the contract event 0x71e88be0e3db9d5ce7b5fbbb61cac85e312d6bc1bdf89360d0ab5dd3dd8e5517.
//
// Solidity: event AccountRestrictionChanged(address indexed account, bool restricted)
func (_SecurityToken *SecurityTokenFilterer) FilterAccountRestrictionChanged(opts *bind.FilterOpts, account []common.Address) (*SecurityTokenAccountRestrictionChangedIterator, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "AccountRestrictionChanged", accountRule)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenAccountRestrictionChangedIterator{contract: _SecurityToken.contract, event: "AccountRestrictionChanged", logs: logs, sub: sub}, nil
}

// WatchAccountRestrictionChanged is a free log subscription operation binding the contract event 0x71e88be0e3db9d5ce7b5fbbb61cac85e312d6bc1bdf89360d0ab5dd3dd8e5517.
//
// Solidity: event AccountRestrictionChanged(address indexed account, bool restricted)
func (_SecurityToken *SecurityTokenFilterer) WatchAccountRestrictionChanged(opts *bind.WatchOpts, sink chan<- *SecurityTokenAccountRestrictionChanged, account []common.Address) (event.Subscription, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "AccountRestrictionChanged", accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenAccountRestrictionChanged)
				if err := _SecurityToken.contract.UnpackLog(event, "AccountRestrictionChanged", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAccountRestrictionChanged is a log parse operation binding the contract event 0x71e88be0e3db9d5ce7b5fbbb61cac85e312d6bc1bdf89360d0ab5dd3dd8e5517.
//
// Solidity: event AccountRestrictionChanged(address indexed account, bool restricted)
func (_SecurityToken *SecurityTokenFilterer) ParseAccountRestrictionChanged(log types.Log) (*SecurityTokenAccountRestrictionChanged, error) {
	event := new(SecurityTokenAccountRestrictionChanged)
	if err := _SecurityToken.contract.UnpackLog(event, "AccountRestrictionChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenAgentInstitutionSetIterator is returned from FilterAgentInstitutionSet and is used to iterate over the raw logs and unpacked data for AgentInstitutionSet events raised by the SecurityToken contract.
type SecurityTokenAgentInstitutionSetIterator struct {
	Event *SecurityTokenAgentInstitutionSet // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenAgentInstitutionSetIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenAgentInstitutionSet)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenAgentInstitutionSet)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenAgentInstitutionSetIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenAgentInstitutionSetIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenAgentInstitutionSet represents a AgentInstitutionSet event raised by the SecurityToken contract.
type SecurityTokenAgentInstitutionSet struct {
	Agent         common.Address
	InstitutionId string
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterAgentInstitutionSet is a free log retrieval operation binding the contract event 0x0a1043062bac78e0695d04a5f7b52d00c670f37212ff1a47d79cbf0ed4695a5a.
//
// Solidity: event AgentInstitutionSet(address indexed agent, string institutionId)
func (_SecurityToken *SecurityTokenFilterer) FilterAgentInstitutionSet(opts *bind.FilterOpts, agent []common.Address) (*SecurityTokenAgentInstitutionSetIterator, error) {

	var agentRule []interface{}
	for _, agentItem := range agent {
		agentRule = append(agentRule, agentItem)
	}

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "AgentInstitutionSet", agentRule)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenAgentInstitutionSetIterator{contract: _SecurityToken.contract, event: "AgentInstitutionSet", logs: logs, sub: sub}, nil
}

// WatchAgentInstitutionSet is a free log subscription operation binding the contract event 0x0a1043062bac78e0695d04a5f7b52d00c670f37212ff1a47d79cbf0ed4695a5a.
//
// Solidity: event AgentInstitutionSet(address indexed agent, string institutionId)
func (_SecurityToken *SecurityTokenFilterer) WatchAgentInstitutionSet(opts *bind.WatchOpts, sink chan<- *SecurityTokenAgentInstitutionSet, agent []common.Address) (event.Subscription, error) {

	var agentRule []interface{}
	for _, agentItem := range agent {
		agentRule = append(agentRule, agentItem)
	}

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "AgentInstitutionSet", agentRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenAgentInstitutionSet)
				if err := _SecurityToken.contract.UnpackLog(event, "AgentInstitutionSet", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseAgentInstitutionSet is a log parse operation binding the contract event 0x0a1043062bac78e0695d04a5f7b52d00c670f37212ff1a47d79cbf0ed4695a5a.
//
// Solidity: event AgentInstitutionSet(address indexed agent, string institutionId)
func (_SecurityToken *SecurityTokenFilterer) ParseAgentInstitutionSet(log types.Log) (*SecurityTokenAgentInstitutionSet, error) {
	event := new(SecurityTokenAgentInstitutionSet)
	if err := _SecurityToken.contract.UnpackLog(event, "AgentInstitutionSet", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenCirculationChangedIterator is returned from FilterCirculationChanged and is used to iterate over the raw logs and unpacked data for CirculationChanged events raised by the SecurityToken contract.
type SecurityTokenCirculationChangedIterator struct {
	Event *SecurityTokenCirculationChanged // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenCirculationChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenCirculationChanged)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenCirculationChanged)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenCirculationChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenCirculationChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenCirculationChanged represents a CirculationChanged event raised by the SecurityToken contract.
type SecurityTokenCirculationChanged struct {
	Active bool
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterCirculationChanged is a free log retrieval operation binding the contract event 0xdf4bf5b5390cf25ed671cc034d403491ffb6d1ef903d9c98709f92a59f1d2a8b.
//
// Solidity: event CirculationChanged(bool active)
func (_SecurityToken *SecurityTokenFilterer) FilterCirculationChanged(opts *bind.FilterOpts) (*SecurityTokenCirculationChangedIterator, error) {

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "CirculationChanged")
	if err != nil {
		return nil, err
	}
	return &SecurityTokenCirculationChangedIterator{contract: _SecurityToken.contract, event: "CirculationChanged", logs: logs, sub: sub}, nil
}

// WatchCirculationChanged is a free log subscription operation binding the contract event 0xdf4bf5b5390cf25ed671cc034d403491ffb6d1ef903d9c98709f92a59f1d2a8b.
//
// Solidity: event CirculationChanged(bool active)
func (_SecurityToken *SecurityTokenFilterer) WatchCirculationChanged(opts *bind.WatchOpts, sink chan<- *SecurityTokenCirculationChanged) (event.Subscription, error) {

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "CirculationChanged")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenCirculationChanged)
				if err := _SecurityToken.contract.UnpackLog(event, "CirculationChanged", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseCirculationChanged is a log parse operation binding the contract event 0xdf4bf5b5390cf25ed671cc034d403491ffb6d1ef903d9c98709f92a59f1d2a8b.
//
// Solidity: event CirculationChanged(bool active)
func (_SecurityToken *SecurityTokenFilterer) ParseCirculationChanged(log types.Log) (*SecurityTokenCirculationChanged, error) {
	event := new(SecurityTokenCirculationChanged)
	if err := _SecurityToken.contract.UnpackLog(event, "CirculationChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenIssuedIterator is returned from FilterIssued and is used to iterate over the raw logs and unpacked data for Issued events raised by the SecurityToken contract.
type SecurityTokenIssuedIterator struct {
	Event *SecurityTokenIssued // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenIssuedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenIssued)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenIssued)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenIssuedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenIssuedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenIssued represents a Issued event raised by the SecurityToken contract.
type SecurityTokenIssued struct {
	Account common.Address
	Amount  *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterIssued is a free log retrieval operation binding the contract event 0xa59f12e354e8cd10bb74c559844c2dd69a5458e31fe56c7594c62ca57480509a.
//
// Solidity: event Issued(address indexed account, uint256 amount)
func (_SecurityToken *SecurityTokenFilterer) FilterIssued(opts *bind.FilterOpts, account []common.Address) (*SecurityTokenIssuedIterator, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "Issued", accountRule)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenIssuedIterator{contract: _SecurityToken.contract, event: "Issued", logs: logs, sub: sub}, nil
}

// WatchIssued is a free log subscription operation binding the contract event 0xa59f12e354e8cd10bb74c559844c2dd69a5458e31fe56c7594c62ca57480509a.
//
// Solidity: event Issued(address indexed account, uint256 amount)
func (_SecurityToken *SecurityTokenFilterer) WatchIssued(opts *bind.WatchOpts, sink chan<- *SecurityTokenIssued, account []common.Address) (event.Subscription, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "Issued", accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenIssued)
				if err := _SecurityToken.contract.UnpackLog(event, "Issued", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseIssued is a log parse operation binding the contract event 0xa59f12e354e8cd10bb74c559844c2dd69a5458e31fe56c7594c62ca57480509a.
//
// Solidity: event Issued(address indexed account, uint256 amount)
func (_SecurityToken *SecurityTokenFilterer) ParseIssued(log types.Log) (*SecurityTokenIssued, error) {
	event := new(SecurityTokenIssued)
	if err := _SecurityToken.contract.UnpackLog(event, "Issued", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenPausedIterator is returned from FilterPaused and is used to iterate over the raw logs and unpacked data for Paused events raised by the SecurityToken contract.
type SecurityTokenPausedIterator struct {
	Event *SecurityTokenPaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenPausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenPaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenPaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenPausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenPausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenPaused represents a Paused event raised by the SecurityToken contract.
type SecurityTokenPaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterPaused is a free log retrieval operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_SecurityToken *SecurityTokenFilterer) FilterPaused(opts *bind.FilterOpts) (*SecurityTokenPausedIterator, error) {

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return &SecurityTokenPausedIterator{contract: _SecurityToken.contract, event: "Paused", logs: logs, sub: sub}, nil
}

// WatchPaused is a free log subscription operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_SecurityToken *SecurityTokenFilterer) WatchPaused(opts *bind.WatchOpts, sink chan<- *SecurityTokenPaused) (event.Subscription, error) {

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "Paused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenPaused)
				if err := _SecurityToken.contract.UnpackLog(event, "Paused", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParsePaused is a log parse operation binding the contract event 0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258.
//
// Solidity: event Paused(address account)
func (_SecurityToken *SecurityTokenFilterer) ParsePaused(log types.Log) (*SecurityTokenPaused, error) {
	event := new(SecurityTokenPaused)
	if err := _SecurityToken.contract.UnpackLog(event, "Paused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenRedeemedIterator is returned from FilterRedeemed and is used to iterate over the raw logs and unpacked data for Redeemed events raised by the SecurityToken contract.
type SecurityTokenRedeemedIterator struct {
	Event *SecurityTokenRedeemed // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenRedeemedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenRedeemed)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenRedeemed)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenRedeemedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenRedeemedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenRedeemed represents a Redeemed event raised by the SecurityToken contract.
type SecurityTokenRedeemed struct {
	Account common.Address
	Amount  *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRedeemed is a free log retrieval operation binding the contract event 0x4896181ff8f4543cc00db9fe9b6fb7e6f032b7eb772c72ab1ec1b4d2e03b9369.
//
// Solidity: event Redeemed(address indexed account, uint256 amount)
func (_SecurityToken *SecurityTokenFilterer) FilterRedeemed(opts *bind.FilterOpts, account []common.Address) (*SecurityTokenRedeemedIterator, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "Redeemed", accountRule)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenRedeemedIterator{contract: _SecurityToken.contract, event: "Redeemed", logs: logs, sub: sub}, nil
}

// WatchRedeemed is a free log subscription operation binding the contract event 0x4896181ff8f4543cc00db9fe9b6fb7e6f032b7eb772c72ab1ec1b4d2e03b9369.
//
// Solidity: event Redeemed(address indexed account, uint256 amount)
func (_SecurityToken *SecurityTokenFilterer) WatchRedeemed(opts *bind.WatchOpts, sink chan<- *SecurityTokenRedeemed, account []common.Address) (event.Subscription, error) {

	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "Redeemed", accountRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenRedeemed)
				if err := _SecurityToken.contract.UnpackLog(event, "Redeemed", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRedeemed is a log parse operation binding the contract event 0x4896181ff8f4543cc00db9fe9b6fb7e6f032b7eb772c72ab1ec1b4d2e03b9369.
//
// Solidity: event Redeemed(address indexed account, uint256 amount)
func (_SecurityToken *SecurityTokenFilterer) ParseRedeemed(log types.Log) (*SecurityTokenRedeemed, error) {
	event := new(SecurityTokenRedeemed)
	if err := _SecurityToken.contract.UnpackLog(event, "Redeemed", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenRoleAdminChangedIterator is returned from FilterRoleAdminChanged and is used to iterate over the raw logs and unpacked data for RoleAdminChanged events raised by the SecurityToken contract.
type SecurityTokenRoleAdminChangedIterator struct {
	Event *SecurityTokenRoleAdminChanged // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenRoleAdminChangedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenRoleAdminChanged)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenRoleAdminChanged)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenRoleAdminChangedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenRoleAdminChangedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenRoleAdminChanged represents a RoleAdminChanged event raised by the SecurityToken contract.
type SecurityTokenRoleAdminChanged struct {
	Role              [32]byte
	PreviousAdminRole [32]byte
	NewAdminRole      [32]byte
	Raw               types.Log // Blockchain specific contextual infos
}

// FilterRoleAdminChanged is a free log retrieval operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_SecurityToken *SecurityTokenFilterer) FilterRoleAdminChanged(opts *bind.FilterOpts, role [][32]byte, previousAdminRole [][32]byte, newAdminRole [][32]byte) (*SecurityTokenRoleAdminChangedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var previousAdminRoleRule []interface{}
	for _, previousAdminRoleItem := range previousAdminRole {
		previousAdminRoleRule = append(previousAdminRoleRule, previousAdminRoleItem)
	}
	var newAdminRoleRule []interface{}
	for _, newAdminRoleItem := range newAdminRole {
		newAdminRoleRule = append(newAdminRoleRule, newAdminRoleItem)
	}

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "RoleAdminChanged", roleRule, previousAdminRoleRule, newAdminRoleRule)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenRoleAdminChangedIterator{contract: _SecurityToken.contract, event: "RoleAdminChanged", logs: logs, sub: sub}, nil
}

// WatchRoleAdminChanged is a free log subscription operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_SecurityToken *SecurityTokenFilterer) WatchRoleAdminChanged(opts *bind.WatchOpts, sink chan<- *SecurityTokenRoleAdminChanged, role [][32]byte, previousAdminRole [][32]byte, newAdminRole [][32]byte) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var previousAdminRoleRule []interface{}
	for _, previousAdminRoleItem := range previousAdminRole {
		previousAdminRoleRule = append(previousAdminRoleRule, previousAdminRoleItem)
	}
	var newAdminRoleRule []interface{}
	for _, newAdminRoleItem := range newAdminRole {
		newAdminRoleRule = append(newAdminRoleRule, newAdminRoleItem)
	}

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "RoleAdminChanged", roleRule, previousAdminRoleRule, newAdminRoleRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenRoleAdminChanged)
				if err := _SecurityToken.contract.UnpackLog(event, "RoleAdminChanged", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRoleAdminChanged is a log parse operation binding the contract event 0xbd79b86ffe0ab8e8776151514217cd7cacd52c909f66475c3af44e129f0b00ff.
//
// Solidity: event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)
func (_SecurityToken *SecurityTokenFilterer) ParseRoleAdminChanged(log types.Log) (*SecurityTokenRoleAdminChanged, error) {
	event := new(SecurityTokenRoleAdminChanged)
	if err := _SecurityToken.contract.UnpackLog(event, "RoleAdminChanged", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenRoleGrantedIterator is returned from FilterRoleGranted and is used to iterate over the raw logs and unpacked data for RoleGranted events raised by the SecurityToken contract.
type SecurityTokenRoleGrantedIterator struct {
	Event *SecurityTokenRoleGranted // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenRoleGrantedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenRoleGranted)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenRoleGranted)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenRoleGrantedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenRoleGrantedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenRoleGranted represents a RoleGranted event raised by the SecurityToken contract.
type SecurityTokenRoleGranted struct {
	Role    [32]byte
	Account common.Address
	Sender  common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRoleGranted is a free log retrieval operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_SecurityToken *SecurityTokenFilterer) FilterRoleGranted(opts *bind.FilterOpts, role [][32]byte, account []common.Address, sender []common.Address) (*SecurityTokenRoleGrantedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "RoleGranted", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenRoleGrantedIterator{contract: _SecurityToken.contract, event: "RoleGranted", logs: logs, sub: sub}, nil
}

// WatchRoleGranted is a free log subscription operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_SecurityToken *SecurityTokenFilterer) WatchRoleGranted(opts *bind.WatchOpts, sink chan<- *SecurityTokenRoleGranted, role [][32]byte, account []common.Address, sender []common.Address) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "RoleGranted", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenRoleGranted)
				if err := _SecurityToken.contract.UnpackLog(event, "RoleGranted", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRoleGranted is a log parse operation binding the contract event 0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d.
//
// Solidity: event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
func (_SecurityToken *SecurityTokenFilterer) ParseRoleGranted(log types.Log) (*SecurityTokenRoleGranted, error) {
	event := new(SecurityTokenRoleGranted)
	if err := _SecurityToken.contract.UnpackLog(event, "RoleGranted", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenRoleRevokedIterator is returned from FilterRoleRevoked and is used to iterate over the raw logs and unpacked data for RoleRevoked events raised by the SecurityToken contract.
type SecurityTokenRoleRevokedIterator struct {
	Event *SecurityTokenRoleRevoked // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenRoleRevokedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenRoleRevoked)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenRoleRevoked)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenRoleRevokedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenRoleRevokedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenRoleRevoked represents a RoleRevoked event raised by the SecurityToken contract.
type SecurityTokenRoleRevoked struct {
	Role    [32]byte
	Account common.Address
	Sender  common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterRoleRevoked is a free log retrieval operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_SecurityToken *SecurityTokenFilterer) FilterRoleRevoked(opts *bind.FilterOpts, role [][32]byte, account []common.Address, sender []common.Address) (*SecurityTokenRoleRevokedIterator, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "RoleRevoked", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenRoleRevokedIterator{contract: _SecurityToken.contract, event: "RoleRevoked", logs: logs, sub: sub}, nil
}

// WatchRoleRevoked is a free log subscription operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_SecurityToken *SecurityTokenFilterer) WatchRoleRevoked(opts *bind.WatchOpts, sink chan<- *SecurityTokenRoleRevoked, role [][32]byte, account []common.Address, sender []common.Address) (event.Subscription, error) {

	var roleRule []interface{}
	for _, roleItem := range role {
		roleRule = append(roleRule, roleItem)
	}
	var accountRule []interface{}
	for _, accountItem := range account {
		accountRule = append(accountRule, accountItem)
	}
	var senderRule []interface{}
	for _, senderItem := range sender {
		senderRule = append(senderRule, senderItem)
	}

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "RoleRevoked", roleRule, accountRule, senderRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenRoleRevoked)
				if err := _SecurityToken.contract.UnpackLog(event, "RoleRevoked", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseRoleRevoked is a log parse operation binding the contract event 0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b.
//
// Solidity: event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
func (_SecurityToken *SecurityTokenFilterer) ParseRoleRevoked(log types.Log) (*SecurityTokenRoleRevoked, error) {
	event := new(SecurityTokenRoleRevoked)
	if err := _SecurityToken.contract.UnpackLog(event, "RoleRevoked", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenTransferredIterator is returned from FilterTransferred and is used to iterate over the raw logs and unpacked data for Transferred events raised by the SecurityToken contract.
type SecurityTokenTransferredIterator struct {
	Event *SecurityTokenTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenTransferred represents a Transferred event raised by the SecurityToken contract.
type SecurityTokenTransferred struct {
	From   common.Address
	To     common.Address
	Amount *big.Int
	Agent  common.Address
	Raw    types.Log // Blockchain specific contextual infos
}

// FilterTransferred is a free log retrieval operation binding the contract event 0x0fb52b545faa9c90e004f29604a41ad8cdbb14e921764129b963b88a85416f4f.
//
// Solidity: event Transferred(address indexed from, address indexed to, uint256 amount, address indexed agent)
func (_SecurityToken *SecurityTokenFilterer) FilterTransferred(opts *bind.FilterOpts, from []common.Address, to []common.Address, agent []common.Address) (*SecurityTokenTransferredIterator, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	var agentRule []interface{}
	for _, agentItem := range agent {
		agentRule = append(agentRule, agentItem)
	}

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "Transferred", fromRule, toRule, agentRule)
	if err != nil {
		return nil, err
	}
	return &SecurityTokenTransferredIterator{contract: _SecurityToken.contract, event: "Transferred", logs: logs, sub: sub}, nil
}

// WatchTransferred is a free log subscription operation binding the contract event 0x0fb52b545faa9c90e004f29604a41ad8cdbb14e921764129b963b88a85416f4f.
//
// Solidity: event Transferred(address indexed from, address indexed to, uint256 amount, address indexed agent)
func (_SecurityToken *SecurityTokenFilterer) WatchTransferred(opts *bind.WatchOpts, sink chan<- *SecurityTokenTransferred, from []common.Address, to []common.Address, agent []common.Address) (event.Subscription, error) {

	var fromRule []interface{}
	for _, fromItem := range from {
		fromRule = append(fromRule, fromItem)
	}
	var toRule []interface{}
	for _, toItem := range to {
		toRule = append(toRule, toItem)
	}

	var agentRule []interface{}
	for _, agentItem := range agent {
		agentRule = append(agentRule, agentItem)
	}

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "Transferred", fromRule, toRule, agentRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenTransferred)
				if err := _SecurityToken.contract.UnpackLog(event, "Transferred", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseTransferred is a log parse operation binding the contract event 0x0fb52b545faa9c90e004f29604a41ad8cdbb14e921764129b963b88a85416f4f.
//
// Solidity: event Transferred(address indexed from, address indexed to, uint256 amount, address indexed agent)
func (_SecurityToken *SecurityTokenFilterer) ParseTransferred(log types.Log) (*SecurityTokenTransferred, error) {
	event := new(SecurityTokenTransferred)
	if err := _SecurityToken.contract.UnpackLog(event, "Transferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// SecurityTokenUnpausedIterator is returned from FilterUnpaused and is used to iterate over the raw logs and unpacked data for Unpaused events raised by the SecurityToken contract.
type SecurityTokenUnpausedIterator struct {
	Event *SecurityTokenUnpaused // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *SecurityTokenUnpausedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(SecurityTokenUnpaused)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(SecurityTokenUnpaused)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *SecurityTokenUnpausedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *SecurityTokenUnpausedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// SecurityTokenUnpaused represents a Unpaused event raised by the SecurityToken contract.
type SecurityTokenUnpaused struct {
	Account common.Address
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterUnpaused is a free log retrieval operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_SecurityToken *SecurityTokenFilterer) FilterUnpaused(opts *bind.FilterOpts) (*SecurityTokenUnpausedIterator, error) {

	logs, sub, err := _SecurityToken.contract.FilterLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return &SecurityTokenUnpausedIterator{contract: _SecurityToken.contract, event: "Unpaused", logs: logs, sub: sub}, nil
}

// WatchUnpaused is a free log subscription operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_SecurityToken *SecurityTokenFilterer) WatchUnpaused(opts *bind.WatchOpts, sink chan<- *SecurityTokenUnpaused) (event.Subscription, error) {

	logs, sub, err := _SecurityToken.contract.WatchLogs(opts, "Unpaused")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(SecurityTokenUnpaused)
				if err := _SecurityToken.contract.UnpackLog(event, "Unpaused", log); err != nil {
					// If the signature doesn't match, skip this log.
					if errors.Is(err, bind.ErrEventSignatureMismatch) {
						continue
					}
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUnpaused is a log parse operation binding the contract event 0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a5e8aa4e537bd38aeae4b073aa.
//
// Solidity: event Unpaused(address account)
func (_SecurityToken *SecurityTokenFilterer) ParseUnpaused(log types.Log) (*SecurityTokenUnpaused, error) {
	event := new(SecurityTokenUnpaused)
	if err := _SecurityToken.contract.UnpackLog(event, "Unpaused", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
