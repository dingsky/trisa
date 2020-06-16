package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trisacrypto/trisa/dao/sqllite"
	"github.com/trisacrypto/trisa/model/sqlliteModel"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jinzhu/copier"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/trisacrypto/trisa/pkg/trisa/config"
	"github.com/trisacrypto/trisa/pkg/trisa/handler"
	"github.com/trisacrypto/trisa/pkg/trisa/server"
	"github.com/trisacrypto/trisa/pkg/trisa/trust"
	bitcoin "github.com/trisacrypto/trisa/proto/trisa/data/bitcoin/v1alpha1"
	us "github.com/trisacrypto/trisa/proto/trisa/identity/us/v1alpha1"
	pb "github.com/trisacrypto/trisa/proto/trisa/protocol/v1alpha1"
	querykyc "github.com/trisacrypto/trisa/proto/trisa/querykyc/v1alpha1"
	synctxn "github.com/trisacrypto/trisa/proto/trisa/synctxn/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type queryKycRsp struct {
	RespCode    string  `json:"resp_code,omitempty"`
	RespDesc    string  `json:"resp_desc,omitempty"`
	Key         string  `json:"key,omitempty"`
	RecieverKyc KycInfo `json:"reciever_kyc,omitempty"`
}

type queryKycReq struct {
	Currency         string  `json:"currency,omitempty"`
	Net              string  `json:"net,omitempty"`
	Address          string  `json:"address,omitempty"`
	Amount           float64 `json:"amount,omitempty"`
	TxnId            string  `json:"txn_id,omitempty"`
	Count            int64   `json:"count,omitempty"`
	TxnDate          string  `json:"txn_date,omitempty"`
	SenderWalletAddr string  `json:"sender_wallet_address,omitempty"`
}

type queryTxnReq struct {
	Hash string `json:"hash,omitempty"`
}

type queryTxnRsp struct {
	RespCode    string     `json:"resp_code,omitempty"`
	RespDesc    string     `json:"resp_desc,omitempty"`
	SenderKyc   KycInfo    `json:"sender_kyc,omitempty"`
	RecieverKyc KycInfo    `json:"reciever_kyc,omitempty"`
	TxnInfo     TxnInfoDef `json:"txn_info,omitempty"`
}

type queryKycList struct {
	RespCode string                     `json:"resp_code,omitempty"`
	RespDesc string                     `json:"resp_desc,omitempty"`
	KycList  []*sqlliteModel.TblKycList `json:"kyc_list,omitempty"`
}

type queryTxnList struct {
	RespCode string                     `json:"resp_code,omitempty"`
	RespDesc string                     `json:"resp_desc,omitempty"`
	TxnList  []*sqlliteModel.TblTxnList `json:"txn_list,omitempty"`
}

type syncTxnReq struct {
	Key  string `json:"key,omitempty"`
	Hash string `json:"hash,omitempty"`
}

type syncTxnRsp struct {
	RespCode string `json:"resp_code,omitempty"`
	RespDesc string `json:"resp_desc,omitempty"`
}

type TxnInfoDef struct {
	Id       string  `json:"id,omitempty"`
	Hash     string  `json:"hash,omitempty"`
	Currency string  `json:"currency,omitempty"`
	Count    int64   `json:"net,omitempty"`
	Amount   float64 `json:"amount,omitempty"`
	Date     string  `json:"date,omitempty"`
}

type KycInfo struct {
	Name          string `json:"name,omitempty"`
	WalletAddress string `json:"wallet_address,omitempty"`
	Id            string `json:"id,omitempty"`
	Date          string `json:"date,omitempty"`
	IdentifyInfo  string `json:"identify_info,omitempty"`
	Address       string `json:"address,omitempty"`
}

type queryVaspReq struct {
	Currency string `json:"currency,omitempty"`
	Net      string `json:"net,omitempty"`
	Address  string `json:"address,omitempty"`
}

type queryVaspRsp struct {
	RespCode string `json:"resp_code,omitempty"`
	RespDesc string `json:"resp_desc,omitempty"`
	Name     string `json:"name,omitempty"`
	Address  string `json:"address,omitempty"`
	Type     string `json:"type,omitempty"`
	Url      string `json:"url,omitempty"`
}

type bindKycReq struct {
	Currency string  `json:"currency,omitempty"`
	Net      string  `json:"net,omitempty"`
	Kyc      KycInfo `json:"kyc,omitempty"`
}

type bindKycRsp struct {
	RespCode string `json:"resp_code,omitempty"`
	RespDesc string `json:"resp_desc,omitempty"`
}

type bindAddressReq struct {
	ID       string `json:"id,omitempty"`
	Currency string `json:"currency,omitempty"`
	Net      string `json:"net,omitempty"`
	Address  string `json:"address,omitempty"`
}

type bindAddressRsp struct {
	RespCode string `json:"resp_code,omitempty"`
	RespDesc string `json:"resp_desc,omitempty"`
}

func NewServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start VASP TRISA server",
		Run:   runServerCmd,
	}

	return cmd
}

func runServerCmd(cmd *cobra.Command, args []string) {

	c, err := config.FromFile(configFile)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	chain, err := ioutil.ReadFile(c.TLS.TrustChainFile)
	if err != nil {
		log.Fatalf("load trust chain: %v", err)
	}
	tp := trust.NewProvider(chain)

	crt, err := tls.LoadX509KeyPair(c.TLS.CertificateFile, c.TLS.PrivateKeyFile)
	if err != nil {
		log.Fatalf("load x509 key pair: %v", err)
	}

	baseTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.CurveP521,
			tls.CurveP384,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	handler := handler.NewDemoHandler()
	pServer := server.New(handler, crt, tp.GetCertPool())

	errs := make(chan error, 2)

	go func() {

		r := mux.NewRouter()

		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Type", "application/json")
			out, _ := json.Marshal(struct {
				Hello string
			}{
				Hello: "World",
			})
			w.Write(out)
		})

		r.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
			ctx, _ := context.WithTimeout(context.Background(), 2*time.Second)
			out, _ := json.Marshal(mTLSConnectionTest(
				ctx,
				r.URL.Query(),
				crt,
				tp.GetCertPool(),
			))
			w.Write(out)
		})

		r.HandleFunc("/query_kyc", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")

			// 读请求报文
			reqMsg, err := ioutil.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("read http err"))
				fmt.Printf("read http err\n")
				return
			}
			fmt.Printf("req msg:%s\n", reqMsg)

			// 解包
			req := new(queryKycReq)
			err = json.Unmarshal(reqMsg, req)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json Unmarshal error"))
				fmt.Printf("json Unmarshal error:%s", err)
				return
			}

			kyc, err := sqllite.KycListCollectionCol.Select(req.Currency, req.Net, req.SenderWalletAddr)
			if err != nil {
				fmt.Printf("unknow KYC error:%s", err)
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte("unknow KYC"))
				return
			}

			url := c.Server.TrisaCenterUrl + "/v0/api/trisacenter/get_vasp"
			queryVaspReq := new(queryVaspReq)
			queryVaspReq.Currency = req.Currency
			queryVaspReq.Net = req.Net
			queryVaspReq.Address = req.Address
			queryVaspReqMsg, err := json.Marshal(queryVaspReq)
			if err != nil {
				fmt.Printf("json KYC Marsharl:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json KYC Marsharl error"))
				return
			}
			respM, err := http.Post(url, "application/json", strings.NewReader(string(queryVaspReqMsg)))
			if err != nil {
				fmt.Printf("http post error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("http post error"))
				return
			}

			body, err := ioutil.ReadAll(respM.Body)
			if err != nil {
				fmt.Printf("http read error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("http read error"))
				return
			}
			defer respM.Body.Close()

			queryVaspRsp := new(queryVaspRsp)
			err = json.Unmarshal(body, queryVaspRsp)
			if err != nil {
				fmt.Printf("json unmarshal error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json unmarshal error"))
				return
			}

			identity, _ := ptypes.MarshalAny(&querykyc.Data{
				Currency: req.Currency,
				Net:      req.Net,
				Address:  req.Address,
			})

			data, _ := ptypes.MarshalAny(&querykyc.Data{
				Currency:      req.Currency,
				Net:           req.Net,
				Address:       req.Address,
				Amount:        req.Amount,
				Name:          kyc.Name,
				WalletAddress: kyc.WalletAddress,
				Id:            kyc.KycId,
				Date:          kyc.Date,
				IdentifyInfo:  kyc.IdentifyInfo,
				TxnId:         req.TxnId,
				Count:         req.Count,
				TxnDate:       req.TxnDate,
			})

			tData := &pb.TransactionData{
				Identity: identity,
				Data:     data,
			}

			fmt.Printf("url:%s\n", queryVaspRsp.Url)
			resp, err := pServer.SendRequest(r.Context(), queryVaspRsp.Url, uuid.New().String(), tData)
			if err != nil {
				fmt.Printf("send request error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("send request error"))
				return
			}
			fmt.Printf("last resp:%s", resp)

			txn := new(sqlliteModel.TblTxnList)
			txn.Net = req.Net
			txn.Date = req.TxnDate
			txn.Amount = req.Amount
			txn.Currency = req.Currency
			txn.Count = req.Count
			txn.TxnID = req.TxnId
			txn.SenderAddress = kyc.Address
			txn.SenderDate = kyc.Date
			txn.SenderId = kyc.KycId
			txn.SenderIdentifyInfo = kyc.IdentifyInfo
			txn.SenderName = kyc.Name
			txn.SenderWalletAddress = kyc.WalletAddress

			txn.RecieverAddress = GetKeyVal(resp, "address")
			txn.RecieverDate = GetKeyVal(resp, "date")
			txn.RecieverId = GetKeyVal(resp, "id")
			txn.RecieverIdentifyInfo = GetKeyVal(resp, "identify_info")
			txn.RecieverName = GetKeyVal(resp, "name")
			txn.RecieverWalletAddress = GetKeyVal(resp, "wallet_address")
			txn.Key = GetKeyVal(resp, "key")

			err = sqllite.TxnListCollectionCol.Insert(txn)
			if err != nil {
				fmt.Printf("insert db error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("insert db error"))
				return
			}

			rsp := new(queryKycRsp)
			rsp.RespDesc = "success"
			rsp.RespCode = "0000"
			rsp.RecieverKyc.Name = GetKeyVal(resp, "name")
			rsp.RecieverKyc.Id = GetKeyVal(resp, "id")
			rsp.RecieverKyc.IdentifyInfo = GetKeyVal(resp, "identify_info")
			rsp.RecieverKyc.Date = GetKeyVal(resp, "date")
			rsp.RecieverKyc.WalletAddress = GetKeyVal(resp, "wallet_address")
			rsp.Key = GetKeyVal(resp, "key")
			rspMsg, _ := json.Marshal(rsp)

			w.WriteHeader(http.StatusOK)
			w.Write(rspMsg)
		})

		r.HandleFunc("/check_address", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")

			// 读请求报文
			reqMsg, err := ioutil.ReadAll(r.Body)
			if err != nil {
				fmt.Printf("read request error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("read requesterror"))
				return
			}
			fmt.Printf("req msg:%s\n", reqMsg)

			url := c.Server.TrisaCenterUrl + "/v0/api/trisacenter/check_address"
			respM, err := http.Post(url, "application/json", strings.NewReader(string(reqMsg)))
			if err != nil {
				fmt.Printf("http post error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("http post error"))
				return
			}

			body, err := ioutil.ReadAll(respM.Body)
			if err != nil {
				fmt.Printf("http read error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("http read error"))
				return
			}
			defer respM.Body.Close()
			fmt.Printf("resp Msg:%s", body)

			w.WriteHeader(http.StatusOK)
			w.Write(body)
		})

		r.HandleFunc("/bind_kyc", func(w http.ResponseWriter, r *http.Request) {

			w.Header().Set("Access-Control-Allow-Origin", "*")

			// 读请求报文
			reqMsg, err := ioutil.ReadAll(r.Body)
			if err != nil {
				fmt.Printf("read request error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("read request error"))
				return
			}
			fmt.Printf("req msg:%s\n", reqMsg)

			req := new(bindKycReq)
			err = json.Unmarshal(reqMsg, req)
			if err != nil {
				fmt.Printf("json unmarshal error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json unmarshal error"))
				return
			}

			url := c.Server.TrisaCenterUrl + "/v0/api/trisacenter/bind_address"
			bindAddr := new(bindAddressReq)
			bindAddr.ID = c.Server.TrisaCustomerId
			bindAddr.Address = req.Kyc.WalletAddress
			bindAddr.Net = req.Net
			bindAddr.Currency = req.Currency
			reqq, _ := json.Marshal(bindAddr)
			respM, err := http.Post(url, "application/json", strings.NewReader(string(reqq)))
			if err != nil {
				fmt.Printf("http post error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("http post error"))
				return
			}
			defer respM.Body.Close()
			body, err := ioutil.ReadAll(respM.Body)
			if err != nil {
				fmt.Printf("read rsp error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("read rsp error"))
				return
			}
			fmt.Printf("==========body:%s\n", body)

			kycInfo := new(sqlliteModel.TblKycList)
			kycInfo.WalletAddress = req.Kyc.WalletAddress
			kycInfo.Currency = req.Currency
			kycInfo.Net = req.Net
			kycInfo.Address = req.Kyc.Address
			kycInfo.Name = req.Kyc.Name
			kycInfo.IdentifyInfo = req.Kyc.IdentifyInfo
			kycInfo.KycId = req.Kyc.Id
			err = sqllite.KycListCollectionCol.Delete(kycInfo.Currency, kycInfo.Net, kycInfo.WalletAddress)
			if err != nil {
				fmt.Printf("double bind KYC delete the old\n")
			}
			err = sqllite.KycListCollectionCol.Insert(kycInfo)
			if err != nil {
				fmt.Printf("insert kyc error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("insert kyc error"))
				return
			}

			rsp := new(bindKycRsp)
			rsp.RespCode = "0000"
			rsp.RespDesc = "success"

			rtt, _ := json.Marshal(rsp)
			fmt.Printf("resp Msg:%s", rtt)

			w.WriteHeader(http.StatusOK)
			w.Write(rtt)

		})

		r.HandleFunc("/query_txn", func(w http.ResponseWriter, r *http.Request) {

			w.Header().Set("Access-Control-Allow-Origin", "*")
			// 读请求报文
			reqMsg, err := ioutil.ReadAll(r.Body)
			if err != nil {
				fmt.Printf("read request error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("read request error"))
				return
			}
			fmt.Printf("req msg:%s\n", reqMsg)

			// 解包
			req := new(queryTxnReq)
			err = json.Unmarshal(reqMsg, req)
			if err != nil {
				fmt.Printf("json Unmarshal error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json Unmarshal error"))
				return
			}

			txnInfo, err := sqllite.TxnListCollectionCol.SelectByHash(req.Hash)
			if err != nil {
				fmt.Printf("txn not found error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("txn not found"))
				return
			}

			rsp := new(queryTxnRsp)
			rsp.RespDesc = "success"
			rsp.RespCode = "0000"
			rsp.RecieverKyc.Name = txnInfo.RecieverName
			rsp.RecieverKyc.WalletAddress = txnInfo.RecieverWalletAddress
			rsp.RecieverKyc.Date = txnInfo.RecieverDate
			rsp.RecieverKyc.Id = txnInfo.RecieverId
			rsp.RecieverKyc.IdentifyInfo = txnInfo.RecieverIdentifyInfo
			rsp.SenderKyc.Name = txnInfo.SenderName
			rsp.SenderKyc.WalletAddress = txnInfo.SenderWalletAddress
			rsp.SenderKyc.Date = txnInfo.SenderDate
			rsp.SenderKyc.Id = txnInfo.SenderId
			rsp.SenderKyc.IdentifyInfo = txnInfo.SenderIdentifyInfo
			rsp.TxnInfo.Id = txnInfo.TxnID
			rsp.TxnInfo.Date = txnInfo.Date
			rsp.TxnInfo.Currency = txnInfo.Currency
			rsp.TxnInfo.Hash = txnInfo.Hash
			rsp.TxnInfo.Count = txnInfo.Count
			rsp.TxnInfo.Amount = txnInfo.Amount

			rspMsg, _ := json.Marshal(rsp)
			fmt.Printf("resp Msg:%s", rspMsg)

			w.WriteHeader(http.StatusOK)
			w.Write(rspMsg)

		})

		r.HandleFunc("/query_kyc_list", func(w http.ResponseWriter, r *http.Request) {

			w.Header().Set("Access-Control-Allow-Origin", "*")

			kycList, err := sqllite.KycListCollectionCol.SelectAll()
			if err != nil {
				fmt.Printf("kyc not found error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("kyc not found"))
				return
			}

			rsp := new(queryKycList)
			rsp.RespDesc = "success"
			rsp.RespCode = "0000"
			rsp.KycList = kycList
			rspMsg, _ := json.Marshal(rsp)
			fmt.Printf("query kyc list resp:%s", rspMsg)
			w.WriteHeader(http.StatusOK)
			w.Write(rspMsg)
		})

		r.HandleFunc("/query_txn_list", func(w http.ResponseWriter, r *http.Request) {

			w.Header().Set("Access-Control-Allow-Origin", "*")

			txnList, err := sqllite.TxnListCollectionCol.SelectAll()
			if err != nil {
				fmt.Printf("txn not found error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("txn not found"))
				return
			}

			rsp := new(queryTxnList)
			rsp.RespDesc = "success"
			rsp.RespCode = "0000"
			rsp.TxnList = txnList

			rspMsg, _ := json.Marshal(rsp)
			fmt.Printf("query txn list resp:%s", rspMsg)
			w.WriteHeader(http.StatusOK)
			w.Write(rspMsg)
		})

		r.HandleFunc("/sync_txn", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")

			// 读请求报文
			reqMsg, err := ioutil.ReadAll(r.Body)
			if err != nil {
				fmt.Printf("read request error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("read request found"))
				return
			}
			fmt.Printf("req msg:%s\n", reqMsg)

			// 解包
			req := new(syncTxnReq)
			err = json.Unmarshal(reqMsg, req)
			if err != nil {
				fmt.Printf("json Unmarshal error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json Unmarshal found"))
				return
			}

			txnInfo, err := sqllite.TxnListCollectionCol.SelectByKey(req.Key)
			if err != nil {
				fmt.Printf("txn not found error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("txn not found"))
				return
			}

			url := c.Server.TrisaCenterUrl + "/v0/api/trisacenter/get_vasp"
			queryVaspReq := new(queryVaspReq)
			queryVaspReq.Currency = txnInfo.Currency
			queryVaspReq.Net = txnInfo.Net
			queryVaspReq.Address = txnInfo.RecieverWalletAddress
			queryVaspReqMsg, err := json.Marshal(queryVaspReq)
			if err != nil {
				fmt.Printf("json Marsharl error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json Marsharl error"))
				return
			}
			respM, err := http.Post(url, "application/json", strings.NewReader(string(queryVaspReqMsg)))
			if err != nil {
				fmt.Printf("http post error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("http post error"))
				return
			}

			body, err := ioutil.ReadAll(respM.Body)
			if err != nil {
				fmt.Printf("http read error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("http read error"))
				return
			}
			defer respM.Body.Close()

			queryVaspRsp := new(queryVaspRsp)
			err = json.Unmarshal(body, queryVaspRsp)
			if err != nil {
				fmt.Printf("json unmarshal error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json unmarshal error"))
				return
			}

			identity, _ := ptypes.MarshalAny(&synctxn.ReqMsg{
				Key:  req.Key,
				Hash: req.Hash,
			})

			data, _ := ptypes.MarshalAny(&synctxn.ReqMsg{
				Key:  req.Key,
				Hash: req.Hash,
			})

			tData := &pb.TransactionData{
				Identity: identity,
				Data:     data,
			}

			resp, err := pServer.SendRequest(r.Context(), queryVaspRsp.Url, uuid.New().String(), tData)
			if err != nil {
				fmt.Printf("send request error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("send request error"))
				return
			}
			fmt.Printf("last resp:%s", resp)

			rsp := new(syncTxnRsp)
			rsp.RespDesc = "success"
			rsp.RespCode = "0000"
			rspMsg, _ := json.Marshal(rsp)
			fmt.Printf("resp Msg:%s", rspMsg)

			w.WriteHeader(http.StatusOK)
			w.Write(rspMsg)

		})

		r.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {

			firstName := r.URL.Query().Get("firstname")
			lastName := r.URL.Query().Get("lastname")
			ssn := r.URL.Query().Get("ssn")
			driverLicense := r.URL.Query().Get("driverlicense")
			state := r.URL.Query().Get("state")
			identity, _ := ptypes.MarshalAny(&us.Identity{
				FirstName:     firstName,
				LastName:      lastName,
				Ssn:           ssn,
				DriverLicense: driverLicense,
				State:         state,
			})

			data, _ := ptypes.MarshalAny(&bitcoin.Data{
				Source:      uuid.New().String(),
				Destination: uuid.New().String(),
			})

			tData := &pb.TransactionData{
				Identity: identity,
				Data:     data,
			}

			_, err := pServer.SendRequest(r.Context(), r.URL.Query().Get("target"), uuid.New().String(), tData)
			if err != nil {
				fmt.Fprintf(w, "error: %v", err)
				return
			}

			fmt.Fprint(w, ".")
		})

		srv := &http.Server{
			Addr:      c.Server.ListenAddressAdmin,
			Handler:   r,
			TLSConfig: baseTLSCfg,
		}

		log.WithFields(log.Fields{
			"component": "admin",
			"tls":       "listening",
			"port":      c.Server.ListenAddressAdmin,
		}).Info("starting TRISA admin server")

		//	errs <- srv.ListenAndServeTLS(c.TLS.CertificateFile, c.TLS.PrivateKeyFile)
		errs <- srv.ListenAndServe()
	}()

	/*go func() {

		r := mux.NewRouter()

		r.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {

			w.Header().Add("Content-Type", "application/json")
			params := r.URL.Query()
			response := &PingResponse{
				Message:  params.Get("msg"),
				ClientCN: r.TLS.PeerCertificates[0].Subject.CommonName,
				ServerCN: r.TLS.ServerName,
			}
			out, _ := json.Marshal(response)
			w.Write(out)
		})

		mTLSCfg := &tls.Config{}
		copier.Copy(&mTLSCfg, &baseTLSCfg)

		mTLSCfg.ClientAuth = tls.RequireAndVerifyClientCert
		mTLSCfg.ClientCAs = tp.GetCertPool()

		srv := &http.Server{
			Addr:      c.Server.ListenAddress,
			Handler:   r,
			TLSConfig: mTLSCfg,
		}

		log.WithFields(log.Fields{
			"component": "service",
			"tls":       "listening",
			"port":      c.Server.ListenAddress,
		}).Info("starting TRISA server")

		errs <- srv.ListenAndServeTLS(c.TLS.CertificateFile, c.TLS.PrivateKeyFile)

	}()*/

	go func() {
		lis, err := net.Listen("tcp", c.Server.ListenAddress)
		if err != nil {
			errs <- err
		}

		mTLSCfg := &tls.Config{}
		copier.Copy(&mTLSCfg, &baseTLSCfg)

		mTLSCfg.ClientAuth = tls.RequireAndVerifyClientCert
		mTLSCfg.ClientCAs = tp.GetCertPool()

		tc := credentials.NewTLS(mTLSCfg)
		s := grpc.NewServer(grpc.Creds(tc))
		pb.RegisterTrisaPeer2PeerServer(s, pServer)

		log.WithFields(log.Fields{
			"component": "grpc",
			"tls":       "listening",
			"port":      c.Server.ListenAddress,
		}).Info("starting TRISA server")

		errs <- s.Serve(lis)
	}()

	log.Fatalf("terminated %v", <-errs)
}

type PingResponse struct {
	Status   string `json:"status,omitempty"`
	Message  string `json:"message,omitempty"`
	ServerCN string `json:"server_cn,omitempty"`
	ClientCN string `json:"client_cn,omitempty"`
}

func mTLSConnectionTest(ctx context.Context, params url.Values, crt tls.Certificate, certPool *x509.CertPool) *PingResponse {

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{crt},
				RootCAs:      certPool,
			},
		},
	}

	url := fmt.Sprintf("https://%s/ping?msg=%s", params.Get("target"), params.Get("msg"))

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return responseFailure(err)
	}

	res, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return responseFailure(err)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return responseFailure(err)
	}

	out := &PingResponse{}
	json.Unmarshal(body, out)

	return out
}

func responseFailure(err error) *PingResponse {
	return &PingResponse{
		Message: "something went wrong",
		Status:  err.Error(),
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
