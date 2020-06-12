package handler

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/trisacrypto/trisa/model/sqlliteModel"

	"github.com/trisacrypto/trisa/dao/sqllite"

	"github.com/golang/protobuf/ptypes"
	log "github.com/sirupsen/logrus"
	pb "github.com/trisacrypto/trisa/proto/trisa/protocol/v1alpha1"
	querykyc "github.com/trisacrypto/trisa/proto/trisa/querykyc/v1alpha1"
	querytxn "github.com/trisacrypto/trisa/proto/trisa/querytxn/v1alpha1"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func NewDemoHandler() *Demo {
	return &Demo{}
}

type Demo struct {
}

func (d *Demo) HandleRequest(ctx context.Context, id string, req *pb.TransactionData) (*pb.TransactionData, error) {

	if HasClientSideFromContext(ctx) {
		identityType, _ := ptypes.AnyMessageName(req.Identity)
		var identityData ptypes.DynamicAny
		ptypes.UnmarshalAny(req.Identity, &identityData)

		log.WithFields(log.Fields{
			"identity-type": identityType,
			"identity":      fmt.Sprintf("%v", identityData),
		}).Infof("received transaction confirmation for %s", id)
		return nil, fmt.Errorf("EOL")
	}

	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("no peer found")
	}

	tlsAuth, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("unexpected peer transport credentials")
	}

	if len(tlsAuth.State.VerifiedChains) == 0 || len(tlsAuth.State.VerifiedChains[0]) == 0 {
		return nil, fmt.Errorf("could not verify peer certificate")
	}

	// Extract identity
	identityType, _ := ptypes.AnyMessageName(req.Identity)
	var identityData ptypes.DynamicAny
	ptypes.UnmarshalAny(req.Identity, &identityData)

	// Extract network information
	networkType, _ := ptypes.AnyMessageName(req.Data)
	var networkData ptypes.DynamicAny
	ptypes.UnmarshalAny(req.Data, &networkData)
	cn := tlsAuth.State.VerifiedChains[0][0].Subject.CommonName
	log.WithFields(log.Fields{
		"identity-type": identityType,
		"network-type":  networkType,
		"identity":      fmt.Sprintf("%v", identityData),
		"network":       fmt.Sprintf("%v", networkData),
	}).Infof("received transaction %s from %s", id, cn)

	switch networkType {
	case "trisa.querykyc.v1alpha1.Data":
		data := networkData.String()
		fmt.Printf("data:%v\n", data)
		curr := GetKeyVal(data, "currency")
		address := GetKeyVal(data, "address")
		amount := GetKeyVal(data, "amount")
		name := GetKeyVal(data, "name")
		walletAddress := GetKeyVal(data, "wallet_address")
		id := GetKeyVal(data, "id")
		date := GetKeyVal(data, "date")
		identifyInfo := GetKeyVal(data, "identify_info")
		count := GetKeyVal(data, "count")
		kycInfo, err := sqllite.KycListCollectionCol.Select(walletAddress)
		if err != nil {
			return nil, fmt.Errorf("kyc not found")
		}
		fmt.Printf("currency:%s address:%s amount:%s name:%s wallteAddress:%s id:%s date:%s ident:%s\n", curr, address, amount, name, walletAddress, id, date, identifyInfo)
		amoutFloat, _ := strconv.ParseFloat(amount, 64)
		countInt, _ := strconv.ParseInt(count, 10, 64)

		txn := new(sqlliteModel.TblTxnList)
		txn.Date = date
		txn.Amount = amoutFloat
		txn.Currency = curr
		txn.Count = countInt
		txn.ID = id
		txn.SenderAddress = address
		txn.SenderDate = date
		txn.SenderId = id
		txn.SenderIdentifyInfo = identifyInfo
		txn.SenderName = name
		txn.SenderWalletAddress = walletAddress

		txn.RecieverAddress = kycInfo.Address
		txn.RecieverDate = kycInfo.Date
		txn.RecieverId = kycInfo.Id
		txn.RecieverIdentifyInfo = kycInfo.IdentifyInfo
		txn.RecieverName = kycInfo.Name
		txn.RecieverWalletAddress = kycInfo.WalletAddress

		err = sqllite.TxnListCollectionCol.Insert(txn)
		if err != nil {
			fmt.Printf("insert err:%s\n", err)
			return nil, err
		}

		// Generate demo response
		identityResp := &querykyc.Data{
			Currency:      curr,
			Address:       kycInfo.Address,
			Amount:        amoutFloat,
			Name:          kycInfo.Name,
			WalletAddress: kycInfo.WalletAddress,
			Id:            kycInfo.Id,
			Date:          kycInfo.Date,
			IdentifyInfo:  kycInfo.IdentifyInfo,
		}
		identityRespSer, _ := ptypes.MarshalAny(identityResp)

		tData := &pb.TransactionData{
			Identity: identityRespSer,
		}

		// Extract identity
		identityType, _ = ptypes.AnyMessageName(identityRespSer)

		log.WithFields(log.Fields{
			"identity-type": identityType,
			"identity":      fmt.Sprintf("%v", identityResp),
		}).Infof("sent transaction response for %s to %s", id, cn)

		return tData, nil
	case "trisa.synctxn.v1alpha1.Data":
		data := networkData.String()
		fmt.Printf("data:%v\n", data)
		key := GetKeyVal(data, "key")
		txnInfo, err := sqllite.TxnListCollectionCol.SelectByKey(key)
		if err != nil {
			return nil, fmt.Errorf("txn not found:%s", err)
		}

		date := GetKeyVal(data, "date")
		amount := GetKeyVal(data, "amount")
		currency := GetKeyVal(data, "currency")
		count := GetKeyVal(data, "count")
		id := GetKeyVal(data, "id")
		hash := GetKeyVal(data, "hash")
		amoutFloat, _ := strconv.ParseFloat(amount, 64)
		countInt, _ := strconv.ParseInt(count, 10, 64)

		txnInfo.Date = date
		txnInfo.Amount = amoutFloat
		txnInfo.Count = countInt
		txnInfo.ID = id
		txnInfo.Currency = currency
		txnInfo.Hash = hash
		err = sqllite.TxnListCollectionCol.Update(txnInfo)
		if err != nil {
			return nil, fmt.Errorf("update txn error:%s", err)
		}

		// Generate demo response
		identityResp := &querytxn.RspMsg{
			RespCode: "00",
			RespDesc: "success",
		}
		identityRespSer, _ := ptypes.MarshalAny(identityResp)

		tData := &pb.TransactionData{
			Identity: identityRespSer,
		}

		// Extract identity
		identityType, _ = ptypes.AnyMessageName(identityRespSer)

		log.WithFields(log.Fields{
			"identity-type": identityType,
			"identity":      fmt.Sprintf("%v", identityResp),
		}).Infof("sent transaction response for %s to %s", id, cn)

		return tData, nil
	default:
		fmt.Printf("unknow networkData:%s\n", cn)
		return nil, fmt.Errorf("Invalid request")
	}
}

func GetKeyVal(sour, key string) string {
	pos := strings.Index(sour, key)
	if pos < 0 {
		return ""
	}
	// fmt.Printf("key:%s\n", key)

	keyLen := len(key)

	left := strings.Index(sour[pos:], " ")
	//	fmt.Printf("pos:%d left:%d\n", pos, left)

	if sour[pos+keyLen+1] == '"' {
		return sour[pos+keyLen+2 : pos+left-1]
	}
	return sour[pos+keyLen+1 : pos+left]

}
