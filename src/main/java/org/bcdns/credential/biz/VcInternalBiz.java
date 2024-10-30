package org.bcdns.credential.biz;


import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import cn.ac.caict.bid.model.BIDDocumentOperation;
import cn.ac.caict.bid.model.BIDpublicKeyOperation;
import cn.bif.api.BIFSDK;
import cn.bif.common.JsonUtils;
import cn.bif.exception.EncException;
import cn.bif.model.crypto.KeyPairEntity;
import cn.bif.model.request.BIFContractCreateRequest;
import cn.bif.model.request.BIFContractGetAddressRequest;
import cn.bif.model.request.BIFContractInvokeRequest;
import cn.bif.model.request.BIFTransactionGetInfoRequest;
import cn.bif.model.response.BIFContractCreateResponse;
import cn.bif.model.response.BIFContractGetAddressResponse;
import cn.bif.model.response.BIFContractInvokeResponse;
import cn.bif.model.response.BIFTransactionGetInfoResponse;
import cn.bif.module.encryption.key.PrivateKeyManager;
import cn.bif.module.encryption.model.KeyType;
import cn.hutool.core.date.DateUtil;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.ObjectUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.crypto.digest.SM3;
import com.alibaba.druid.filter.config.ConfigTools;
import com.alibaba.druid.filter.config.ConfigTools;
import com.alipay.antchain.bridge.commons.bbc.syscontract.ContractStatusEnum;
import com.alipay.antchain.bridge.commons.bbc.syscontract.SDPContract;
import com.alipay.antchain.bridge.commons.bcdns.*;
import com.alipay.antchain.bridge.commons.bcdns.utils.BIDHelper;
import com.alipay.antchain.bridge.commons.bcdns.utils.CrossChainCertificateUtil;
import com.alipay.antchain.bridge.commons.core.base.CrossChainDomain;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentity;
import com.alipay.antchain.bridge.commons.core.base.ObjectIdentityType;
import com.alipay.antchain.bridge.commons.utils.crypto.HashAlgoEnum;
import com.alipay.antchain.bridge.commons.utils.crypto.SignAlgoEnum;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.bcdns.credential.common.constant.Constants;
import org.bcdns.credential.common.utils.AppUtils;
import org.bcdns.credential.common.utils.JwtUtil;
import org.bcdns.credential.common.utils.RedisUtil;
import org.bcdns.credential.common.utils.Tools;
import org.bcdns.credential.dto.req.VcApplyDetailReqDto;
import org.bcdns.credential.dto.req.VcApplyListReqDto;
import org.bcdns.credential.dto.req.VcIssueAuditReqDto;
import org.bcdns.credential.dto.req.VcRevocationReqDto;
import org.bcdns.credential.dto.resp.*;
import org.bcdns.credential.enums.ExceptionEnum;
import org.bcdns.credential.enums.StatusEnum;
import org.bcdns.credential.exception.APIException;
import org.bcdns.credential.model.*;
import org.bcdns.credential.service.ApiKeyService;
import org.bcdns.credential.service.VcAuditService;
import org.bcdns.credential.service.VcRecordService;
import org.bcdns.credential.service.VcRootService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;


@Component
public class VcInternalBiz {

    @Value("${object-identity.supernode.bid-private-key}")
    private String encryptSuperNodeBidPrivateKey;

    @Value("${object-identity.issuer.bid-private-key}")
    private String encryptIssuerBidPrivateKey;

    @Value("${ptc.contract.address}")
    private String ptcContractAddress;

    @Value("${relay.contract.address}")
    private String relayContractAddress;

    @Value("${domain-name.contract.address}")
    private String domainNameContractAddress;

    @Value("${sdk.url}")
    private String sdkUrl;

    private static final String PTC_BYTE_CODE = "608060405234801561000f575f80fd5b505f80546001600160c01b031916339081178255604051909182917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0908290a3506109db8061005d5f395ff3fe608060405234801561000f575f80fd5b506004361061007a575f3560e01c8063597239a711610058578063597239a7146100cf578063715018a6146100f25780638da5cb5b146100fa578063f2fde38b14610114575f80fd5b8063142e15421461007e578063165caccc146100935780632d16473f146100bc575b5f80fd5b61009161008c366004610694565b610127565b005b6100a66100a1366004610694565b610247565b6040516100b3919061071b565b60405180910390f35b6100916100ca36600461072d565b6102f6565b6100e26100dd366004610694565b610445565b60405190151581526020016100b3565b610091610472565b5f546040516001600160c01b0390911681526020016100b3565b6100916101223660046107a0565b6104f2565b336101395f546001600160c01b031690565b6001600160c01b0316146101685760405162461bcd60e51b815260040161015f906107c6565b60405180910390fd5b60018160405161017891906107fb565b9081526040519081900360200190206001015460ff166101da5760405162461bcd60e51b815260206004820152601c60248201527f636572746966696361746520686173206265656e207265766f6b656400000000604482015260640161015f565b5f6001826040516101eb91906107fb565b908152604051908190036020018120600101805492151560ff19909316929092179091557fe565ddda66e7404ad75b2e7d05d14eac00057e873ea7d6e5439d67b999ba255c9061023c90839061071b565b60405180910390a150565b606060018260405161025991906107fb565b908152604051908190036020019020805461027390610816565b80601f016020809104026020016040519081016040528092919081815260200182805461029f90610816565b80156102ea5780601f106102c1576101008083540402835291602001916102ea565b820191905f5260205f20905b8154815290600101906020018083116102cd57829003601f168201915b50505050509050919050565b336103085f546001600160c01b031690565b6001600160c01b03161461032e5760405162461bcd60e51b815260040161015f906107c6565b60018260405161033e91906107fb565b908152604051908190036020019020805461035890610816565b1590506103a75760405162461bcd60e51b815260206004820152601f60248201527f636572746966696361746520686173206265656e207265676973746572656400604482015260640161015f565b6040805180820182528281526001602082018190529151909182916103cd9086906107fb565b908152604051908190036020019020815181906103ea908261089c565b50602091909101516001909101805460ff19169115159190911790556040517f8a65131a45e6179fb02f1b6dcd89d4c8316826486f47d467822161f57472ce36906104389085908590610958565b60405180910390a1505050565b5f60018260405161045691906107fb565b9081526040519081900360200190206001015460ff1692915050565b336104845f546001600160c01b031690565b6001600160c01b0316146104aa5760405162461bcd60e51b815260040161015f906107c6565b5f80546040516001600160c01b03909116907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0908390a35f80546001600160c01b0319169055565b336105045f546001600160c01b031690565b6001600160c01b03161461052a5760405162461bcd60e51b815260040161015f906107c6565b6001600160c01b03811661058f5760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b606482015260840161015f565b5f80546040516001600160c01b03808516939216917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e091a35f80546001600160c01b0319166001600160c01b0392909216919091179055565b634e487b7160e01b5f52604160045260245ffd5b5f67ffffffffffffffff80841115610616576106166105e8565b604051601f8501601f19908116603f0116810190828211818310171561063e5761063e6105e8565b81604052809350858152868686011115610656575f80fd5b858560208301375f602087830101525050509392505050565b5f82601f83011261067e575f80fd5b61068d838335602085016105fc565b9392505050565b5f602082840312156106a4575f80fd5b813567ffffffffffffffff8111156106ba575f80fd5b6106c68482850161066f565b949350505050565b5f5b838110156106e85781810151838201526020016106d0565b50505f910152565b5f81518084526107078160208601602086016106ce565b601f01601f19169290920160200192915050565b602081525f61068d60208301846106f0565b5f806040838503121561073e575f80fd5b823567ffffffffffffffff80821115610755575f80fd5b6107618683870161066f565b93506020850135915080821115610776575f80fd5b508301601f81018513610787575f80fd5b610796858235602084016105fc565b9150509250929050565b5f602082840312156107b0575f80fd5b81356001600160c01b038116811461068d575f80fd5b6020808252818101527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604082015260600190565b5f825161080c8184602087016106ce565b9190910192915050565b600181811c9082168061082a57607f821691505b60208210810361084857634e487b7160e01b5f52602260045260245ffd5b50919050565b601f821115610897575f81815260208120601f850160051c810160208610156108745750805b601f850160051c820191505b8181101561089357828155600101610880565b5050505b505050565b815167ffffffffffffffff8111156108b6576108b66105e8565b6108ca816108c48454610816565b8461084e565b602080601f8311600181146108fd575f84156108e65750858301515b5f19600386901b1c1916600185901b178555610893565b5f85815260208120601f198616915b8281101561092b5788860151825594840194600190910190840161090c565b508582101561094857878501515f19600388901b60f8161c191681555b5050505050600190811b01905550565b604081525f61096a60408301856106f0565b828103602084015261097c81856106f0565b9594505050505056fea26469706673582212208fc5bba62a0f245a9837d650773219820eaea38cefdedfa25121675d31f292f064736f6c637822302e382e32312d63692e323032342e332e312b636f6d6d69742e31383065353661320053";

    private static final String RELAY_BYTE_CODE = "608060405234801561000f575f80fd5b505f80546001600160c01b031916339081178255604051909182917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0908290a35061105e8061005d5f395ff3fe608060405234801561000f575f80fd5b50600436106100a6575f3560e01c8063715018a61161006e578063715018a61461013f5780637c55fade146101475780637f51cc8e1461015a57806386441cab1461016d5780638da5cb5b14610180578063f2fde38b1461019a575f80fd5b806314006cdc146100aa578063142e1542146100bf578063165caccc146100d2578063597239a7146100fb5780636d9c9c8c1461011e575b5f80fd5b6100bd6100b8366004610b70565b6101ad565b005b6100bd6100cd366004610bd0565b610273565b6100e56100e0366004610bd0565b6103e6565b6040516100f29190610c57565b60405180910390f35b61010e610109366004610bd0565b610495565b60405190151581526020016100f2565b61013161012c366004610bd0565b6104ca565b6040516100f2929190610c70565b6100bd610643565b6100bd610155366004610cb8565b6106c3565b6100bd610168366004610d27565b610852565b6100e561017b366004610bd0565b6109b2565b5f546040516001600160c01b0390911681526020016100f2565b6100bd6101a8366004610da9565b6109dd565b335f9081526001602052604090205460ff1661020a5760405162461bcd60e51b815260206004820152601760248201527663616c6c6572206973206e6f74207468652072656c617960481b60448201526064015b60405180910390fd5b8060048360405161021b9190610dc2565b908152602001604051809103902090816102359190610e63565b507f97723fe192b9591747fb1064c77f80cb117d42ad304cfa0fc4ac4996080e24da8282604051610267929190610c70565b60405180910390a15050565b336102855f546001600160c01b031690565b6001600160c01b0316146102ab5760405162461bcd60e51b815260040161020190610f1f565b6002816040516102bb9190610dc2565b9081526040519081900360200190206001015460ff600160c01b909104166103255760405162461bcd60e51b815260206004820152601c60248201527f636572746966696361746520686173206265656e207265766f6b6564000000006044820152606401610201565b5f6002826040516103369190610dc2565b908152602001604051809103902060010160186101000a81548160ff0219169083151502179055505f60015f6002846040516103729190610dc2565b9081526040805160209281900383019020600101546001600160c01b031683529082019290925281015f20805460ff191692151592909217909155517fe1c8d7ceb03da4f2671106dbdf4c255241fbaaf5280b996f72d9598293585e55906103db908390610c57565b60405180910390a150565b60606002826040516103f89190610dc2565b908152604051908190036020019020805461041290610ddd565b80601f016020809104026020016040519081016040528092919081815260200182805461043e90610ddd565b80156104895780601f1061046057610100808354040283529160200191610489565b820191905f5260205f20905b81548152906001019060200180831161046c57829003601f168201915b50505050509050919050565b5f6002826040516104a69190610dc2565b9081526040519081900360200190206001015460ff600160c01b9091041692915050565b60608060026003846040516104df9190610dc2565b9081526040519081900360200181206104f791610f54565b90815260405190819003602001812090600390610515908690610dc2565b908152602001604051809103902060010181805461053290610ddd565b80601f016020809104026020016040519081016040528092919081815260200182805461055e90610ddd565b80156105a95780601f10610580576101008083540402835291602001916105a9565b820191905f5260205f20905b81548152906001019060200180831161058c57829003601f168201915b505050505091508080546105bc90610ddd565b80601f01602080910402602001604051908101604052809291908181526020018280546105e890610ddd565b80156106335780601f1061060a57610100808354040283529160200191610633565b820191905f5260205f20905b81548152906001019060200180831161061657829003601f168201915b5050505050905091509150915091565b336106555f546001600160c01b031690565b6001600160c01b03161461067b5760405162461bcd60e51b815260040161020190610f1f565b5f80546040516001600160c01b03909116907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0908390a35f80546001600160c01b0319169055565b336106d55f546001600160c01b031690565b6001600160c01b0316146106fb5760405162461bcd60e51b815260040161020190610f1f565b60028360405161070b9190610dc2565b908152604051908190036020019020805461072590610ddd565b1590506107745760405162461bcd60e51b815260206004820152601f60248201527f636572746966696361746520686173206265656e2072656769737465726564006044820152606401610201565b604080516060810182528381526001600160c01b0383166020820152600181830152905181906002906107a8908790610dc2565b908152604051908190036020019020815181906107c59082610e63565b50602082810151600192830180546040958601511515600160c01b026001600160c81b03199091166001600160c01b039384161717905585165f90815290829052829020805460ff19169091179055517f629214db2fae816a05137427c69ecf7270236ae18e57484fb53231a3a9d99338906108449086908690610c70565b60405180910390a150505050565b335f9081526001602052604090205460ff166108aa5760405162461bcd60e51b815260206004820152601760248201527663616c6c6572206973206e6f74207468652072656c617960481b6044820152606401610201565b6002826040516108ba9190610dc2565b9081526040519081900360200190206001015460ff600160c01b909104166109245760405162461bcd60e51b815260206004820152601d60248201527f72656c617920686173206e6f74206265656e20726567697374657265640000006044820152606401610201565b6040805180820182528381526020810183905290518190600390610949908790610dc2565b908152604051908190036020019020815181906109669082610e63565b506020820151600182019061097b9082610e63565b509050507f1652309d3348162b0844b8ee3f6e17ce29d29b92794a3fa2bd7f0dfd76ed952284848460405161084493929190610fc6565b60606004826040516109c49190610dc2565b9081526020016040518091039020805461041290610ddd565b336109ef5f546001600160c01b031690565b6001600160c01b031614610a155760405162461bcd60e51b815260040161020190610f1f565b6001600160c01b038116610a7a5760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b6064820152608401610201565b5f80546040516001600160c01b03808516939216917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e091a35f80546001600160c01b0319166001600160c01b0392909216919091179055565b634e487b7160e01b5f52604160045260245ffd5b5f82601f830112610af6575f80fd5b813567ffffffffffffffff80821115610b1157610b11610ad3565b604051601f8301601f19908116603f01168101908282118183101715610b3957610b39610ad3565b81604052838152866020858801011115610b51575f80fd5b836020870160208301375f602085830101528094505050505092915050565b5f8060408385031215610b81575f80fd5b823567ffffffffffffffff80821115610b98575f80fd5b610ba486838701610ae7565b93506020850135915080821115610bb9575f80fd5b50610bc685828601610ae7565b9150509250929050565b5f60208284031215610be0575f80fd5b813567ffffffffffffffff811115610bf6575f80fd5b610c0284828501610ae7565b949350505050565b5f5b83811015610c24578181015183820152602001610c0c565b50505f910152565b5f8151808452610c43816020860160208601610c0a565b601f01601f19169290920160200192915050565b602081525f610c696020830184610c2c565b9392505050565b604081525f610c826040830185610c2c565b8281036020840152610c948185610c2c565b95945050505050565b80356001600160c01b0381168114610cb3575f80fd5b919050565b5f805f60608486031215610cca575f80fd5b833567ffffffffffffffff80821115610ce1575f80fd5b610ced87838801610ae7565b94506020860135915080821115610d02575f80fd5b50610d0f86828701610ae7565b925050610d1e60408501610c9d565b90509250925092565b5f805f60608486031215610d39575f80fd5b833567ffffffffffffffff80821115610d50575f80fd5b610d5c87838801610ae7565b94506020860135915080821115610d71575f80fd5b610d7d87838801610ae7565b93506040860135915080821115610d92575f80fd5b50610d9f86828701610ae7565b9150509250925092565b5f60208284031215610db9575f80fd5b610c6982610c9d565b5f8251610dd3818460208701610c0a565b9190910192915050565b600181811c90821680610df157607f821691505b602082108103610e0f57634e487b7160e01b5f52602260045260245ffd5b50919050565b601f821115610e5e575f81815260208120601f850160051c81016020861015610e3b5750805b601f850160051c820191505b81811015610e5a57828155600101610e47565b5050505b505050565b815167ffffffffffffffff811115610e7d57610e7d610ad3565b610e9181610e8b8454610ddd565b84610e15565b602080601f831160018114610ec4575f8415610ead5750858301515b5f19600386901b1c1916600185901b178555610e5a565b5f85815260208120601f198616915b82811015610ef257888601518255948401946001909101908401610ed3565b5085821015610f0f57878501515f19600388901b60f8161c191681555b5050505050600190811b01905550565b6020808252818101527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604082015260600190565b5f808354610f6181610ddd565b60018281168015610f795760018114610f8e57610fba565b60ff1984168752821515830287019450610fba565b875f526020805f205f5b85811015610fb15781548a820152908401908201610f98565b50505082870194505b50929695505050505050565b606081525f610fd86060830186610c2c565b8281036020840152610fea8186610c2c565b90508281036040840152610ffe8185610c2c565b969550505050505056fea2646970667358221220a2ae62a1f46f63c3615ba3bd88d4f189082448e5e682f3d2d3bc311b2241d5aa64736f6c637822302e382e32312d63692e323032342e332e312b636f6d6d69742e31383065353661320053";

    private static final String DOMAIN_NAME_BYTE_CODE = "608060405234801561000f575f80fd5b505f80546001600160c01b031916339081178255604051909182917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0908290a350610c298061005d5f395ff3fe608060405234801561000f575f80fd5b5060043610610090575f3560e01c8063715018a611610063578063715018a6146101085780638da5cb5b14610110578063b3b471a91461012a578063d3139e641461013d578063f2fde38b14610150575f80fd5b8063142e154214610094578063165caccc146100a95780635446c2bc146100d2578063597239a7146100e5575b5f80fd5b6100a76100a236600461087e565b610163565b005b6100bc6100b736600461087e565b610365565b6040516100c99190610905565b60405180910390f35b6100bc6100e036600461087e565b610414565b6100f86100f336600461087e565b610426565b60405190151581526020016100c9565b6100a7610453565b5f546040516001600160c01b0390911681526020016100c9565b6100a7610138366004610917565b6104d3565b6100f861014b36600461087e565b6106cb565b6100a761015e3660046109ac565b6106dc565b336101755f546001600160c01b031690565b6001600160c01b0316146101a45760405162461bcd60e51b815260040161019b906109d2565b60405180910390fd5b6001816040516101b49190610a07565b9081526040519081900360200190206002015460ff166102165760405162461bcd60e51b815260206004820152601c60248201527f636572746966696361746520686173206265656e207265766f6b656400000000604482015260640161019b565b5f6001826040516102279190610a07565b9081526020016040518091039020600101805461024390610a22565b80601f016020809104026020016040519081016040528092919081815260200182805461026f90610a22565b80156102ba5780601f10610291576101008083540402835291602001916102ba565b820191905f5260205f20905b81548152906001019060200180831161029d57829003601f168201915b505050505090505f6001836040516102d29190610a07565b9081526040519081900360200181206002908101805493151560ff19909416939093179092555f9190610306908490610a07565b908152604051908190036020018120600201805492151560ff19909316929092179091557fba6537b750db426cda2b0139624b91610f24adeed9b971849fc12c8ef2ff4d4b906103599084908490610a5a565b60405180910390a15050565b60606001826040516103779190610a07565b908152604051908190036020019020805461039190610a22565b80601f01602080910402602001604051908101604052809291908181526020018280546103bd90610a22565b80156104085780601f106103df57610100808354040283529160200191610408565b820191905f5260205f20905b8154815290600101906020018083116103eb57829003601f168201915b50505050509050919050565b60606002826040516103779190610a07565b5f6001826040516104379190610a07565b9081526040519081900360200190206002015460ff1692915050565b336104655f546001600160c01b031690565b6001600160c01b03161461048b5760405162461bcd60e51b815260040161019b906109d2565b5f80546040516001600160c01b03909116907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0908390a35f80546001600160c01b0319169055565b336104e55f546001600160c01b031690565b6001600160c01b03161461050b5760405162461bcd60e51b815260040161019b906109d2565b60018360405161051b9190610a07565b908152604051908190036020019020805461053590610a22565b1590508015610567575060028260405161054f9190610a07565b9081526040519081900360200190206002015460ff16155b6105b35760405162461bcd60e51b815260206004820152601f60248201527f636572746966696361746520686173206265656e207265676973746572656400604482015260640161019b565b604080516060810182528281526020810184905260018183018190529151909182916105e0908790610a07565b908152604051908190036020019020815181906105fd9082610ad5565b50602082015160018201906106129082610ad5565b506040918201516002918201805460ff1916911515919091179055905182919061063d908690610a07565b9081526040519081900360200190208151819061065a9082610ad5565b506020820151600182019061066f9082610ad5565b50604091820151600291909101805460ff1916911515919091179055517f36085e2858a299d9f3287f90d02c44bf965cd705d90bb89ae538c1b8badb7020906106bd90869086908690610b91565b60405180910390a150505050565b5f6002826040516104379190610a07565b336106ee5f546001600160c01b031690565b6001600160c01b0316146107145760405162461bcd60e51b815260040161019b906109d2565b6001600160c01b0381166107795760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b606482015260840161019b565b5f80546040516001600160c01b03808516939216917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e091a35f80546001600160c01b0319166001600160c01b0392909216919091179055565b634e487b7160e01b5f52604160045260245ffd5b5f67ffffffffffffffff80841115610800576108006107d2565b604051601f8501601f19908116603f01168101908282118183101715610828576108286107d2565b81604052809350858152868686011115610840575f80fd5b858560208301375f602087830101525050509392505050565b5f82601f830112610868575f80fd5b610877838335602085016107e6565b9392505050565b5f6020828403121561088e575f80fd5b813567ffffffffffffffff8111156108a4575f80fd5b6108b084828501610859565b949350505050565b5f5b838110156108d25781810151838201526020016108ba565b50505f910152565b5f81518084526108f18160208601602086016108b8565b601f01601f19169290920160200192915050565b602081525f61087760208301846108da565b5f805f60608486031215610929575f80fd5b833567ffffffffffffffff80821115610940575f80fd5b61094c87838801610859565b94506020860135915080821115610961575f80fd5b61096d87838801610859565b93506040860135915080821115610982575f80fd5b508401601f81018613610993575f80fd5b6109a2868235602084016107e6565b9150509250925092565b5f602082840312156109bc575f80fd5b81356001600160c01b0381168114610877575f80fd5b6020808252818101527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604082015260600190565b5f8251610a188184602087016108b8565b9190910192915050565b600181811c90821680610a3657607f821691505b602082108103610a5457634e487b7160e01b5f52602260045260245ffd5b50919050565b604081525f610a6c60408301856108da565b8281036020840152610a7e81856108da565b95945050505050565b601f821115610ad0575f81815260208120601f850160051c81016020861015610aad5750805b601f850160051c820191505b81811015610acc57828155600101610ab9565b5050505b505050565b815167ffffffffffffffff811115610aef57610aef6107d2565b610b0381610afd8454610a22565b84610a87565b602080601f831160018114610b36575f8415610b1f5750858301515b5f19600386901b1c1916600185901b178555610acc565b5f85815260208120601f198616915b82811015610b6457888601518255948401946001909101908401610b45565b5085821015610b8157878501515f19600388901b60f8161c191681555b5050505050600190811b01905550565b606081525f610ba360608301866108da565b8281036020840152610bb581866108da565b90508281036040840152610bc981856108da565b969550505050505056fea26469706673582212200bafec11e5e6315f6ff401be25ad4e06ff63c64bdf431ee64226c6202f3e393b64736f6c637822302e382e32312d63692e323032342e332e312b636f6d6d69742e31383065353661320053";

    private static final Logger logger = LoggerFactory.getLogger(VcInternalBiz.class);

    @Value("${issue.decrypt.public-key}")
    private String decodePublicKey;

    @Autowired
    private ApiKeyService apiKeyService;
    @Autowired
    private VcRecordService vcRecordService;
    @Autowired
    private VcAuditService vcAuditService;
    @Autowired
    private RedisUtil redisUtil;
    @Autowired
    private VcRootService vcRootService;

    public DataResp<ApiKeyRespDto> init() throws Exception {
        DataResp<ApiKeyRespDto> dataResp = new DataResp<>();
        //parsing private-key

        try {
            String superNodeBidPrivateKey = decryptPrivateKey(encryptSuperNodeBidPrivateKey);
            String issuerBidPrivateKey = decryptPrivateKey(encryptIssuerBidPrivateKey);

            PrivateKeyManager superNodePrivateKeyManager = createPrivateKeyManager(superNodeBidPrivateKey);
            PrivateKeyManager issuerPrivateKeyManager = createPrivateKeyManager(issuerBidPrivateKey);

            Integer databaseIndex = 1;
            ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyDomain(databaseIndex);
            if (!Tools.isNull(apiKeyDomain) && apiKeyDomain.getInitTag().equals(databaseIndex)) {
                throw new APIException(ExceptionEnum.PLATFORM_REPEAT_INIT);
            }

            byte[] cert = createRootVc(superNodePrivateKeyManager, issuerPrivateKeyManager);
            saveVcRoot(cert);

            ApiKeyRespDto apiKeyRespDto = createApiKey(issuerPrivateKeyManager);
            dataResp.setData(apiKeyRespDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("platform init error: {}", e.getMessage());
            dataResp.buildSysExceptionField();
        }
        return dataResp;
    }

    private BIFContractCreateRequest createContractRequest(PrivateKeyManager issuerPrivateKeyManager, String byteCode, String contractName) {
        BIFContractCreateRequest request = new BIFContractCreateRequest();
        request.setSenderAddress(issuerPrivateKeyManager.getEncAddress());
        request.setPrivateKey(issuerPrivateKeyManager.getEncPrivateKey());
        request.setInitBalance(0L);
        request.setPayload(byteCode);
        request.setRemarks("create contract for " + contractName);
        request.setType(1);
        request.setFeeLimit(50000000L);
        request.setGasPrice(1L);
        return request;
    }

    private String decryptPrivateKey(String encryptPrivateKey) {
        try {
            return ConfigTools.decrypt(decodePublicKey, encryptPrivateKey);
        } catch (Exception e) {
            throw new APIException(ExceptionEnum.FAILED_TO_DECRYPT_PRIVATE);
        }
    }

    private PrivateKeyManager createPrivateKeyManager(String privateKey) {
        try {
            return new PrivateKeyManager(privateKey);
        } catch (EncException e) {
            throw new APIException(ExceptionEnum.PRIVATE_KEY_IS_INVALID);
        }
    }

    private byte[] createRootVc(PrivateKeyManager superNodePrivateKeyManager, PrivateKeyManager issuerPrivateKeyManager) {
        // create root vc
        BIDpublicKeyOperation[] biDpublicKeyOperation = new BIDpublicKeyOperation[1];
        biDpublicKeyOperation[0] = new BIDpublicKeyOperation();
        biDpublicKeyOperation[0].setType(issuerPrivateKeyManager.getKeyType());
        biDpublicKeyOperation[0].setPublicKeyHex(issuerPrivateKeyManager.getEncPublicKey());
        BIDDocumentOperation bidDocumentOperation = new BIDDocumentOperation();
        bidDocumentOperation.setPublicKey(biDpublicKeyOperation);

        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                KeyPairEntity.getBidAndKeyPair().getEncAddress(),
                new ObjectIdentity(ObjectIdentityType.BID, superNodePrivateKeyManager.getEncAddress().getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new BCDNSTrustRootCredentialSubject(
                        "root_verifiable_credential",
                        new ObjectIdentity(ObjectIdentityType.BID, issuerPrivateKeyManager.getEncAddress().getBytes()),
                        JsonUtils.toJSONString(bidDocumentOperation).getBytes()
                )
        );

        byte[] msg = certificate.getEncodedToSign();
        byte[] sign = superNodePrivateKeyManager.sign(msg);
        SignAlgoEnum signAlg;
        KeyType keyType = superNodePrivateKeyManager.getKeyType();
        if (keyType.equals(KeyType.SM2)) {
            signAlg = SignAlgoEnum.SM3_WITH_SM2;
        } else if (keyType.equals(KeyType.ED25519)) {
            signAlg = SignAlgoEnum.ED25519;
            } else {
                throw new APIException(ExceptionEnum.KEYTYPE_ERROR);
        } else {
            signAlg = "";
        }
        certificate.setProof(
                new AbstractCrossChainCertificate.IssueProof(
                        HashAlgoEnum.SM3,
                        SM3.create().digest(certificate.getEncodedToSign()),
                        signAlg,
                        sign
                )
        );

        return certificate.encode();
    }

    private void saveVcRoot(byte[] cert) {
        VcRootDomain vcRootDomain = new VcRootDomain();
        vcRootDomain.setVcRoot(cert);
        vcRootService.insert(vcRootDomain);
    }

    private ApiKeyRespDto createApiKey(PrivateKeyManager issuerPrivateKeyManager) {
        String apiKey = AppUtils.getAppId();
        String secret = AppUtils.getAppSecret(apiKey);
        ApiKeyDomain apiKeyDomain = new ApiKeyDomain();
        apiKeyDomain.setApiKey(apiKey);
        apiKeyDomain.setApiSecret(secret);
        apiKeyDomain.setIssuerPrivateKey(encryptIssuerBidPrivateKey);
        apiKeyDomain.setIssuerId(issuerPrivateKeyManager.getEncAddress());
        apiKeyDomain.setInitTag(1);
        apiKeyService.insert(apiKeyDomain);

        ApiKeyRespDto apiKeyRespDto = new ApiKeyRespDto();
        apiKeyRespDto.setApiKey(apiKey);
        apiKeyRespDto.setApiSecret(secret);
        apiKeyRespDto.setIssuerId(issuerPrivateKeyManager.getEncAddress());
        return apiKeyRespDto;
    }

    private String getPTCInput(AbstractCrossChainCertificate certificate) {
        return StrUtil.format("{\"function\":\"addCertificate(string,bytes)\",\"args\":\"'{}','{}'\"}", certificate.getId(), "0x" + HexUtil.encodeHexStr(certificate.encode()));
    }

    private String getRelayInput(AbstractCrossChainCertificate certificate) {
        String relayAddress = BIDHelper.encAddress(BIDHelper.getKeyTypeFromPublicKey(CrossChainCertificateUtil.getPublicKeyFromCrossChainCertificate(certificate)),
                CrossChainCertificateUtil.getRawPublicKeyFromCrossChainCertificate(certificate));
        return StrUtil.format("{\"function\":\"addCertificate(string,bytes,address)\",\"args\":\"'{}','{}',{}\"}", certificate.getId(), "0x" + HexUtil.encodeHexStr(certificate.encode()), relayAddress);
    }

    private String getDomainNameInput(AbstractCrossChainCertificate certificate) {
        DomainNameCredentialSubject domainNameCredentialSubject = DomainNameCredentialSubject.decode(certificate.getCredentialSubject());
        CrossChainDomain crossChainDomain = domainNameCredentialSubject.getDomainName();
        return StrUtil.format("{\"function\":\"addCertificate(string,string,bytes)\",\"args\":\"'{}','{}','{}'\"}",
                certificate.getId(), crossChainDomain.getDomain(), "0x" + HexUtil.encodeHexStr(certificate.encode()));
    }

    private String auditTxSubmit(AbstractCrossChainCertificate certificate, String issuerPrivateKey, String issuerId, VcRecordDomain domain) {
        byte credentialType = domain.getCredentialType().byteValue();
        String targetContract = "";
        String input = "";
        switch (CrossChainCertificateTypeEnum.valueOf(credentialType)) {
            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                targetContract = ptcContractAddress;
                input = getPTCInput(certificate);
                break;
            case RELAYER_CERTIFICATE:
                targetContract = relayContractAddress;
                input = getRelayInput(certificate);
                break;
            case DOMAIN_NAME_CERTIFICATE:
                targetContract = domainNameContractAddress;
                input = getDomainNameInput(certificate);
                break;
            default:
                logger.error("templateId error");
                break;
        }

        if (targetContract.isEmpty()) throw new APIException(ExceptionEnum.PARAME_ERROR);

        BIFContractInvokeRequest request = new BIFContractInvokeRequest();
        request.setSenderAddress(issuerId);
        request.setPrivateKey(issuerPrivateKey);
        request.setContractAddress(targetContract);
        request.setBIFAmount(0L);
        request.setGasPrice(1L);
        request.setRemarks("contract invoke");
        request.setInput(input);
        request.setFeeLimit(20000000L);

        String txHash = "";
        BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
        BIFContractInvokeResponse response = sdk.getBIFContractService().contractInvoke(request);
        if (ExceptionEnum.SUCCESS.getErrorCode().equals(response.getErrorCode())) {
            txHash = response.getResult().getHash();
        } else {
            throw new APIException(ExceptionEnum.PARAME_ERROR);
        }
        return txHash;
    }

    public AbstractCrossChainCertificate buildPTCVc(String issuerPrivateKey, String issuerId, String vcId, VcRecordDomain domain) {
        AbstractCrossChainCertificate cert = CrossChainCertificateFactory.createCrossChainCertificate(domain.getContent());
        PTCCredentialSubject ptcCredentialSubject = PTCCredentialSubject.decode(cert.getCredentialSubject());
        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                vcId,
                new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new PTCCredentialSubject(
                        ptcCredentialSubject.getVersion(),
                        ptcCredentialSubject.getName(),
                        ptcCredentialSubject.getType(),
                        ptcCredentialSubject.getApplicant(),
                        ptcCredentialSubject.getSubjectInfo()
                )
        );

        logger.error("paicha: {}", issuerPrivateKey);
        logger.info("paicha: {}", issuerPrivateKey);
        PrivateKeyManager privateKeyManager = new PrivateKeyManager(issuerPrivateKey);
        byte[] msg = certificate.getEncodedToSign();
        byte[] sign = privateKeyManager.sign(msg);
        SignAlgoEnum signAlg;
        KeyType keyType = privateKeyManager.getKeyType();
        if (keyType.equals(KeyType.SM2)) {
            signAlg = SignAlgoEnum.SM3_WITH_SM2;
        } else if (keyType.equals(KeyType.ED25519)) {
            signAlg = SignAlgoEnum.ED25519;
        } else {
            throw new APIException(ExceptionEnum.KEYTYPE_ERROR);
        }
        certificate.setProof(
                new AbstractCrossChainCertificate.IssueProof(
                        HashAlgoEnum.SM3,
                        SM3.create().digest(certificate.getEncodedToSign()),
                        signAlg,
                        sign
                )
        );
        return certificate;
    }

    public AbstractCrossChainCertificate buildRelayVc(String issuerPrivateKey, String issuerId, String vcId, VcRecordDomain domain) {
        AbstractCrossChainCertificate cert = CrossChainCertificateFactory.createCrossChainCertificate(domain.getContent());
        RelayerCredentialSubject relayerCredentialSubject = RelayerCredentialSubject.decode(cert.getCredentialSubject());
        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                vcId,
                new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new RelayerCredentialSubject(
                        relayerCredentialSubject.getVersion(),
                        relayerCredentialSubject.getName(),
                        relayerCredentialSubject.getApplicant(),
                        relayerCredentialSubject.getSubjectInfo()
                )
        );

        PrivateKeyManager privateKeyManager = new PrivateKeyManager(issuerPrivateKey);
        byte[] msg = certificate.getEncodedToSign();
        byte[] sign = privateKeyManager.sign(msg);
        SignAlgoEnum signAlg;
        KeyType keyType = privateKeyManager.getKeyType();
        if (keyType.equals(KeyType.SM2)) {
            signAlg = SignAlgoEnum.SM3_WITH_SM2;
        } else if (keyType.equals(KeyType.ED25519)) {
            signAlg = SignAlgoEnum.ED25519;
        } else {
            throw new APIException(ExceptionEnum.KEYTYPE_ERROR);
        }
        certificate.setProof(
                new AbstractCrossChainCertificate.IssueProof(
                        HashAlgoEnum.SM3,
                        SM3.create().digest(certificate.getEncodedToSign()),
                        signAlg,
                        sign
                )
        );
        return certificate;
    }

    public AbstractCrossChainCertificate buildDomainNameVc(String issuerPrivateKey, String issuerId, String vcId, VcRecordDomain domain) {
        AbstractCrossChainCertificate cert = CrossChainCertificateFactory.createCrossChainCertificate(domain.getContent());
        DomainNameCredentialSubject domainNameCredentialSubject = DomainNameCredentialSubject.decode(cert.getCredentialSubject());
        AbstractCrossChainCertificate certificate = CrossChainCertificateFactory.createCrossChainCertificate(
                CrossChainCertificateV1.MY_VERSION,
                vcId,
                new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes()),
                DateUtil.currentSeconds(),
                DateUtil.offsetDay(new Date(), 365).getTime() / 1000,
                new DomainNameCredentialSubject(
                        domainNameCredentialSubject.getVersion(),
                        domainNameCredentialSubject.getDomainNameType(),
                        domainNameCredentialSubject.getParentDomainSpace(),
                        domainNameCredentialSubject.getDomainName(),
                        domainNameCredentialSubject.getApplicant(),
                        domainNameCredentialSubject.getSubject()
                )
        );

        PrivateKeyManager privateKeyManager = new PrivateKeyManager(issuerPrivateKey);
        byte[] msg = certificate.getEncodedToSign();
        byte[] sign = privateKeyManager.sign(msg);
        SignAlgoEnum signAlg;
        KeyType keyType = privateKeyManager.getKeyType();
        if (keyType.equals(KeyType.SM2)) {
            signAlg = SignAlgoEnum.SM3_WITH_SM2;
        } else if (keyType.equals(KeyType.ED25519)) {
            signAlg = SignAlgoEnum.ED25519;
        } else {
            throw new APIException(ExceptionEnum.KEYTYPE_ERROR);
        }
        certificate.setProof(
                new AbstractCrossChainCertificate.IssueProof(
                        HashAlgoEnum.SM3,
                        SM3.create().digest(certificate.getEncodedToSign()),
                        signAlg,
                        sign
                )
        );
        return certificate;
    }

    private AbstractCrossChainCertificate createVc(String issuerPrivateKey, String issuerId, VcRecordDomain domain, String vcId) {
        //create root vc
        AbstractCrossChainCertificate abstractCrossChainCertificate = null;
        Integer credentialType = domain.getCredentialType();
        switch (CrossChainCertificateTypeEnum.valueOf(credentialType.byteValue())) {
            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                abstractCrossChainCertificate = buildPTCVc(issuerPrivateKey, issuerId, vcId, domain);
                break;
            case RELAYER_CERTIFICATE:
                abstractCrossChainCertificate = buildRelayVc(issuerPrivateKey, issuerId, vcId, domain);
                break;
            case DOMAIN_NAME_CERTIFICATE:
                abstractCrossChainCertificate = buildDomainNameVc(issuerPrivateKey, issuerId, vcId, domain);
                break;
            default:
                break;
        }

        return abstractCrossChainCertificate;
    }

    private byte[] getVcOwnerId(VcRecordDomain domain) {
        byte[] vcOwnerId = null;
        Integer credentialType = domain.getCredentialType();
        AbstractCrossChainCertificate cert = CrossChainCertificateFactory.createCrossChainCertificate(domain.getContent());
        switch (CrossChainCertificateTypeEnum.valueOf(credentialType.byteValue())) {
            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                PTCCredentialSubject ptcCredentialSubject = PTCCredentialSubject.decode(cert.getCredentialSubject());
                vcOwnerId = ptcCredentialSubject.getApplicant().encode();
                break;
            case RELAYER_CERTIFICATE:
                RelayerCredentialSubject relayerCredentialSubject = RelayerCredentialSubject.decode(cert.getCredentialSubject());
                vcOwnerId = relayerCredentialSubject.getApplicant().encode();
                break;
            case DOMAIN_NAME_CERTIFICATE:
                DomainNameCredentialSubject domainNameCredentialSubject = DomainNameCredentialSubject.decode(cert.getCredentialSubject());
                vcOwnerId = domainNameCredentialSubject.getApplicant().encode();
                break;
            default:
                break;
        }
        return vcOwnerId;
    }

    public DataResp<VcIssueAuditRespDto> vcAudit(String accessToken, VcIssueAuditReqDto vcIssueAuditReqDto) {
        DataResp<VcIssueAuditRespDto> vcIssusAuditRespDtoDataResp = new DataResp<>();
        try {
            //check access token
            Map<String, String> paramMap = JwtUtil.decode(accessToken);
            if (paramMap == null) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            String issuerId = paramMap.get(Constants.ISSUER_ID);
            String token = redisUtil.get(issuerId);
            if (!token.equals(accessToken)) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            //deal request
            String applyNo = vcIssueAuditReqDto.getApplyNo();
            Integer status = vcIssueAuditReqDto.getStatus();
            String reason = vcIssueAuditReqDto.getReason();

            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord(applyNo);
            if (Tools.isNull(vcRecordDomain)) throw new APIException(ExceptionEnum.CREDENTIAL_APPLY_NOT_EXIST);
            if (!Tools.isNull(vcRecordDomain) && !StatusEnum.APPLYING.getCode().equals(vcRecordDomain.getStatus())) {
                throw new APIException(ExceptionEnum.CREDENTIAL_AUDITED);
            }

            VcAuditDomain vcAuditDomain = new VcAuditDomain();
            VcIssueAuditRespDto vcIssueAuditRespDto = new VcIssueAuditRespDto();
            String txHash;
            String vcId;
            AbstractCrossChainCertificate abstractCrossChainCertificate;
            if (StatusEnum.AUDIT_PASS.getCode().equals(status)) {
                ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyDomain(1);
                String encryptIssuerBidPrivateKey = apiKeyDomain.getIssuerPrivateKey();
                String issuerPrivateKey = ConfigTools.decrypt(decodePublicKey, encryptIssuerBidPrivateKey);
                //create vc
                KeyPairEntity keyPairEntity = KeyPairEntity.getBidAndKeyPair();
                vcId = keyPairEntity.getEncAddress();
                abstractCrossChainCertificate = createVc(issuerPrivateKey, issuerId, vcRecordDomain, vcId);
                if (Tools.isNull(abstractCrossChainCertificate)) {
                    throw new APIException(ExceptionEnum.CREDENTIAL_BUILD_ERROR);
                }
                //submit to on-chain
                txHash = auditTxSubmit(abstractCrossChainCertificate, issuerPrivateKey, issuerId, vcRecordDomain);
                if (txHash.isEmpty()) {
                    throw new APIException(ExceptionEnum.SUBMIT_TX_ERROR);
                }
                vcAuditDomain.setVcId(vcId);
                byte[] vcOwnerId = getVcOwnerId(vcRecordDomain);
                vcAuditDomain.setVcOwnerId(vcOwnerId);
                vcAuditDomain.setReason(reason);
            } else if (StatusEnum.AUDIT_REJECT.getCode().equals(status)) {
                vcId = "";
                txHash = "";
                abstractCrossChainCertificate = null;
                vcAuditDomain.setReason(reason);
            } else {
                throw new APIException(ExceptionEnum.PARAME_ERROR);
            }

            ObjectIdentity objectIdentity = new ObjectIdentity(ObjectIdentityType.BID, issuerId.getBytes());
            vcAuditDomain.setApplyNo(applyNo);
            vcAuditDomain.setAuditId(objectIdentity.encode());
            vcAuditDomain.setStatus(status);
            vcAuditDomain.setCreateTime(DateUtil.currentSeconds());

            byte[] vcData = Tools.isNull(abstractCrossChainCertificate) ? null : abstractCrossChainCertificate.encode();
            vcAuditService.insertAudit(vcAuditDomain);
            vcRecordDomain.setStatus(status);
            vcRecordDomain.setVcId(vcId);
            vcRecordDomain.setVcData(vcData);
            vcRecordDomain.setUpdateTime(DateUtil.currentSeconds());
            vcRecordService.updateAuditPassStatus(vcRecordDomain);
            vcIssueAuditRespDto.setTxHash(txHash);
            vcIssusAuditRespDtoDataResp.setData(vcIssueAuditRespDto);
            vcIssusAuditRespDtoDataResp.buildSuccessField();
        } catch (JWTVerificationException e) {
            vcIssusAuditRespDtoDataResp.buildCommonField(ExceptionEnum.SYS_ERROR.getErrorCode(), "failed to decode access token");
        } catch (APIException e) {
            vcIssusAuditRespDtoDataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("audit error: {}", e.getMessage());
            vcIssusAuditRespDtoDataResp.buildCommonField(ExceptionEnum.SYS_ERROR.getErrorCode(), e.getMessage());
        }
        return vcIssusAuditRespDtoDataResp;
    }

    public DataResp<VcApplyListRespDto> queryList(String accessToken, VcApplyListReqDto reqDto) {
        DataResp<VcApplyListRespDto> dataResp = new DataResp<>();
        try {
            //check access token
            Map<String, String> paramMap = JwtUtil.decode(accessToken);
            if (paramMap == null) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            String issuerId = paramMap.get(Constants.ISSUER_ID);
            String token = redisUtil.get(issuerId);
            if (!token.equals(accessToken)) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            reqDto.setStartNum((reqDto.getPageStart() - 1) * reqDto.getPageSize());
            if (reqDto.getStatus() != null && reqDto.getStatus().length == 0) {
                reqDto.setStatus(null);
            }
            List<VcRecordListDomain> vcRecordDomain = vcRecordService.queryList(reqDto);
            List<VcApplyListRespDto.IssueListDTO> issueListDTOList = buildVcList(vcRecordDomain);
            int total = vcRecordService.queryListCount(reqDto);
            VcApplyListRespDto respDto = new VcApplyListRespDto();
            respDto.setDataList(issueListDTOList);
            respDto.getPage().setPageSize(reqDto.getPageSize());
            respDto.getPage().setPageStart(reqDto.getPageStart());
            respDto.getPage().setPageTotal(total);
            dataResp.setData(respDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("get query list error: {}", e.getMessage());
            dataResp.buildCommonField(ExceptionEnum.SYS_ERROR.getErrorCode(), e.getMessage());
        }
        return dataResp;
    }

    private List<VcApplyListRespDto.IssueListDTO> buildVcList(List<VcRecordListDomain> vcRecordDomain) {
        ArrayList<VcApplyListRespDto.IssueListDTO> issueListDTOList = new ArrayList<>();
        for (VcRecordListDomain vcr : vcRecordDomain) {
            VcApplyListRespDto.IssueListDTO dto = new VcApplyListRespDto.IssueListDTO();
            BeanUtils.copyProperties(vcr, dto);
            dto.setCreateTime(vcr.getCreateTime());
            dto.setAuditTime(vcr.getAuditTime());
            issueListDTOList.add(dto);
        }
        return issueListDTOList;
    }

    public DataResp<VcApplyDetailRespDto> queryDetail(String accessToken, VcApplyDetailReqDto reqDto) {
        DataResp<VcApplyDetailRespDto> dataResp = new DataResp<>();
        try {
            //check access token
            Map<String, String> paramMap = JwtUtil.decode(accessToken);
            if (paramMap == null) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            String issuerId = paramMap.get(Constants.ISSUER_ID);
            String token = redisUtil.get(issuerId);
            if (!token.equals(accessToken)) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            if (!reqDto.getApplyNo().isEmpty()) {
                if (reqDto.getApplyNo().length() != 32) {
                    throw new APIException(ExceptionEnum.PARAME_ERROR);
                }
            }

            if (!reqDto.getCredentialId().isEmpty()) {
                if (!reqDto.getCredentialId().startsWith("did:bid")) {
                    throw new APIException(ExceptionEnum.PARAME_ERROR);
                }
            }

            VcRecordDomain vcRecordDomain = vcRecordService.queryDetail(reqDto);
            if (!Tools.isNull(vcRecordDomain)) {
                VcApplyDetailRespDto dto = new VcApplyDetailRespDto();
                if (!vcRecordDomain.getStatus().equals(StatusEnum.APPLYING.getCode())) {
                    VcAuditDomain vcAuditDomain = vcAuditService.getAuditDomain(vcRecordDomain.getApplyNo());
                    if (!Tools.isNull(vcAuditDomain)) {
                        dto.setAuditId(vcAuditDomain.getAuditId());
                        dto.setAuditTime(vcAuditDomain.getCreateTime());
                        dto.setAuditRemark(vcAuditDomain.getReason());
                    }
                }

                dto.setApplyNo(vcRecordDomain.getApplyNo());
                dto.setApplyTime(vcRecordDomain.getCreateTime() != 0 ? vcRecordDomain.getCreateTime() : null);
                dto.setStatus(vcRecordDomain.getStatus().toString());
                dto.setContent(vcRecordDomain.getContent());
                dto.setApplyUser(vcRecordDomain.getUserId());
                dataResp.setData(dto);
                dataResp.buildSuccessField();
            } else {
                dataResp.buildCommonField(ExceptionEnum.CREDENTIAL_APPLY_NOT_EXIST.getErrorCode(), ExceptionEnum.CREDENTIAL_APPLY_NOT_EXIST.getMessage());
            }
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("query apply detail error: {}", e.getMessage());
            dataResp.buildCommonField(ExceptionEnum.SYS_ERROR.getErrorCode(), e.getMessage());
        }
        return dataResp;
    }

    private String revokeTxSubmit(String credentialId, Integer credentialType, String issuerPrivateKey, String issuerId) {
        String targetContract;
        String input = StrUtil.format("{\"function\":\"revokeCertificate(string)\",\"args\":\"'{}'\"}", credentialId);
        switch (CrossChainCertificateTypeEnum.valueOf(credentialType.byteValue())) {
            case PROOF_TRANSFORMATION_COMPONENT_CERTIFICATE:
                targetContract = ptcContractAddress;
                break;
            case RELAYER_CERTIFICATE:
                targetContract = relayContractAddress;
                break;
            case DOMAIN_NAME_CERTIFICATE:
                targetContract = domainNameContractAddress;
                break;
            default:
                throw new APIException(ExceptionEnum.PARAME_ERROR);
        }

        if (targetContract.isEmpty()) throw new APIException(ExceptionEnum.PARAME_ERROR);

        BIFContractInvokeRequest request = new BIFContractInvokeRequest();
        request.setSenderAddress(issuerId);
        request.setPrivateKey(issuerPrivateKey);
        request.setContractAddress(targetContract);
        request.setBIFAmount(0L);
        request.setGasPrice(1L);
        request.setRemarks("contract invoke");
        request.setInput(input);
        request.setFeeLimit(20000000L);

        String txHash = "";
        BIFSDK sdk = BIFSDK.getInstance(sdkUrl);
        BIFContractInvokeResponse response = sdk.getBIFContractService().contractInvoke(request);
        if (ExceptionEnum.SUCCESS.getErrorCode().equals(response.getErrorCode())) {
            txHash = response.getResult().getHash();
        } else {
            throw new APIException(ExceptionEnum.PARAME_ERROR);
        }
        return txHash;
    }

    public DataResp<VcRevocationRespDto> revocationVc(String accessToken, VcRevocationReqDto reqDto) {
        DataResp<VcRevocationRespDto> dataResp = new DataResp<>();
        try {
            //check access token
            Map<String, String> paramMap = JwtUtil.decode(accessToken);
            if (paramMap == null) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            String issuerId = paramMap.get(Constants.ISSUER_ID);
            String token = redisUtil.get(issuerId);
            if (!token.equals(accessToken)) {
                throw new APIException(ExceptionEnum.ACCESS_TOKEN_INVALID);
            }

            String credentialId = reqDto.getCredentialId();
            VcRecordDomain vcRecordDomain = vcRecordService.getVcRecord4VcId(credentialId);
            VcRevocationRespDto respDto = new VcRevocationRespDto();
            String txHash;
            if (Tools.isNull(vcRecordDomain)) {
                throw new APIException(ExceptionEnum.CREDENTIAL_NOT_EXIST);
            }

            if (vcRecordDomain.getStatus().equals(StatusEnum.REVOKE.getCode())) {
                throw new APIException(ExceptionEnum.CREDENTIAL_IS_REVOKE);
            }

            ApiKeyDomain apiKeyDomain = apiKeyService.getApiKeyDomain(1);
            String encryptIssuerBidPrivateKey = apiKeyDomain.getIssuerPrivateKey();
            String issuerPrivateKey = ConfigTools.decrypt(decodePublicKey, encryptIssuerBidPrivateKey);

            txHash = revokeTxSubmit(credentialId, vcRecordDomain.getCredentialType(), issuerPrivateKey, issuerId);
            if (txHash.isEmpty()) {
                throw new APIException(ExceptionEnum.SUBMIT_TX_ERROR);
            }
            vcRecordDomain.setStatus(StatusEnum.REVOKE.getCode());
            vcRecordDomain.setUpdateTime(DateUtil.currentSeconds());
            vcRecordService.updateRevokeStatus(vcRecordDomain);

            respDto.setTxHash(txHash);
            dataResp.setData(respDto);
            dataResp.buildSuccessField();
        } catch (APIException e) {
            dataResp.buildAPIExceptionField(e);
        } catch (Exception e) {
            logger.error("revocation vc error:{}", e.getMessage());
            dataResp.buildCommonField(ExceptionEnum.SYS_ERROR.getErrorCode(), e.getMessage());
        }
        return dataResp;
    }
}

