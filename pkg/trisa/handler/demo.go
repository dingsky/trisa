package handler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/golang/protobuf/ptypes"
	log "github.com/sirupsen/logrus"
	be "github.com/trisacrypto/trisa/proto/trisa/identity/be/v1alpha1"
	pb "github.com/trisacrypto/trisa/proto/trisa/protocol/v1alpha1"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type queryKycReq struct {
	DestUrl   string    `json:"dest_url,omitempty"`
	Currency  string    `json:"currency,omitempty"`
	Net       string    `json:"net,omitempty"`
	Address   string    `json:"address,omitempty"`
	Amount    float64   `json:"amount,omitempty"`
	SenderKyc senderKyc `json:"sender_kyc,omitempty"`
}

type senderKyc struct {
	Name          string `json:"name,omitempty"`
	WalletAddress string `json:"wallet_address,omitempty"`
	Id            string `json:"id,omitempty"`
	Date          string `json:"date,omitempty"`
	IdentifyInfo  string `json:"identify_info,omitempty"`
}

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

	queryKyc := new(queryKycReq)
	switch cn {
	case "trisa.querykyc.v1alpha1.Data":
		if err := json.Unmarshal([]byte(id), queryKyc); err != nil {
			return nil, fmt.Errorf("json Unmarshal faied")
		}
		fmt.Printf("req:%v", queryKyc)
	default:
		fmt.Printf("unknow networkData:%s", cn)
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
