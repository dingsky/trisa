package handler

import (
	"context"
	"fmt"
	"strings"

	"github.com/golang/protobuf/ptypes"
	log "github.com/sirupsen/logrus"
	be "github.com/trisacrypto/trisa/proto/trisa/identity/be/v1alpha1"
	pb "github.com/trisacrypto/trisa/proto/trisa/protocol/v1alpha1"
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
		address := GetKeyVal(data, "shanghai")
		amount := GetKeyVal(data, "shanghai")
		name := GetKeyVal(data, "name")
		walletAddress := GetKeyVal(data, "wallet_address")
		id := GetKeyVal(data, "id")
		date := GetKeyVal(data, "date")
		identifyInfo := GetKeyVal(date, "identify_info")

		fmt.Printf("currency:%s , address:=%s amount:%s name:%s wallteAddress:%s id:%s date:%s ident:%s\n", curr, address, amount, name, walletAddress, id, date, identifyInfo)
	default:
		fmt.Printf("unknow networkData:%s\n", cn)
		return nil, fmt.Errorf("Invalid request")
	}

	// Generate demo response
	identityResp := &be.Identity{
		FirstName:      "Jane",
		LastName:       "Foe",
		NationalNumber: "109-800211-69",
		CityOfBirth:    "Zwevezele",
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
}

func GetKeyVal(sour, key string) string {
	pos := strings.Index(sour, key)
	if pos < 0 {
		return ""
	}

	keyLen := len(key)

	left := strings.Index(sour[pos:], " ")

	if sour[pos+keyLen+2] == '"' {
		return sour[pos+keyLen+2 : left-1]
	}
	return sour[pos+keyLen+1 : left]

}
