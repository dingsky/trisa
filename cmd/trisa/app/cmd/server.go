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

type createTxnReq struct {
	Id          string  `json:"id,omitempty"`
	Name        string  `json:"name,omitempty"`
	TxnTime     string  `json:"txn_time,omitempty"`
	Type        string  `json:"type,omitempty"`
	FromAddress string  `json:"from_address,omitempty"`
	ToAddress   string  `json:"to_address,omitempty"`
	Currency    string  `json:"currency,omitempty"`
	Amount      float64 `json:"amount,omitempty"`
	Count       float64 `json:"count,omitempty"`
	Hash        string  `json:"hash,omitempty"`
}

type createTxnRsp struct {
	RespCode string `json:"resp_code,omitempty"`
	RespDesc string `json:"resp_desc,omitempty"`
	Key      string `json:"key,omitempty"`
}

type queryKycListReq struct {
	Id        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Type      string `json:"type,omitempty"`
	Currency  string `json:"currency,omitempty"`
	TimeStart string `json:"time_start,omitempty"`
	TimeEnd   string `json:"time_end,omitempty"`
}

type queryKycListRsp struct {
	RespCode string     `json:"resp_code,omitempty"`
	RespDesc string     `json:"resp_desc,omitempty"`
	KycList  []*KycList `json:"kyc_list,omitempty"`
}

type queryKycDetailReq struct {
	Currency      string `json:"currency,omitempty"`
	WalletAddress string `json:"wallet_address,omitempty"`
}

type queryKycDetailRsp struct {
	RespCode      string `json:"resp_code,omitempty"`
	RespDesc      string `json:"resp_desc,omitempty"`
	Id            string `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	Type          string `json:"type,omitempty"`
	Date          string `json:"date,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
	Address       string `json:"address,omitempty"`
	Currency      string `json:"currency,omitempty"`
	WalletAddress string `json:"wallet_address,omitempty"`
	CreateTime    string `json:"create_time,omitempty"`
}

type KycList struct {
	Id            string `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	Type          string `json:"type,omitempty"`
	Currency      string `json:"currency,omitempty"`
	WalletAddress string `json:"wallet_address,omitempty"`
	CreateTime    string `json:"create_time,omitempty"`
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

type baseRsp struct {
	RespCode string `json:"resp_code,omitempty"`
	RespDesc string `json:"resp_desc,omitempty"`
}

type queryTxnListReq struct {
	Id             string  `json:"id,omitempty"`
	Name           string  `json:"name,omitempty"`
	Type           string  `json:"type,omitempty"`
	FromAddress    string  `json:"from_address,omitempty"`
	ToAddress      string  `json:"to_address,omitempty"`
	Currency       string  `json:"currency,omitempty"`
	MinAmount      float64 `json:"min_amount,omitempty"`
	MaxAmount      float64 `json:"max_amount,omitempty"`
	MinCount       float64 `json:"min_count,omitempty"`
	MaxCount       float64 `json:"max_count,omitempty"`
	MinTotalAmount float64 `json:"min_total_amount,omitempty"`
	MaxTotalAmount float64 `json:"max_total_amount,omitempty"`
	StartTime      string  `json:"start_time,omitempty"`
	EndTime        string  `json:"end_time,omitempty"`
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

type actionReq struct {
	Key       string `json:"key,omitempty"`
	Operation string `json:"operation,omitempty"`
}

type actionRsp struct {
	RespCode string `json:"resp_code,omitempty"`
	RespDesc string `json:"resp_desc,omitempty"`
}

type TxnInfoDef struct {
	Id       string  `json:"id,omitempty"`
	Hash     string  `json:"hash,omitempty"`
	Currency string  `json:"currency,omitempty"`
	Count    float64 `json:"net,omitempty"`
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
	Id            string `json:"id,omitempty"`
	Name          string `json:"name,omitempty"`
	Type          string `json:"type,omitempty"`
	Date          string `json:"date,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
	Address       string `json:"address,omitempty"`
	Currency      string `json:"currency,omitempty"`
	//	Net      string `json:"net,omitempty"`
	WalletAddress string `json:"wallet_address,omitempty"`
	IdentifyInfo  string `json:"identify_info,omitempty"`
}

type bindKycRsp struct {
	RespCode string `json:"resp_code,omitempty"`
	RespDesc string `json:"resp_desc,omitempty"`
}

type bindAddressReq struct {
	ID       string `json:"id,omitempty"`
	Currency string `json:"currency,omitempty"`
	//	Net      string `json:"net,omitempty"`
	Address string `json:"address,omitempty"`
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

var gCenterUrl string
var gPSever *server.Server

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
	gPSever = pServer

	errs := make(chan error, 2)
	gCenterUrl = c.Server.TrisaCenterUrl

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

		r.HandleFunc("/create_txn", func(w http.ResponseWriter, r *http.Request) {
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
			req := new(createTxnReq)
			err = json.Unmarshal(reqMsg, req)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json Unmarshal error"))
				fmt.Printf("json Unmarshal error:%s", err)
				return
			}

			txn := new(sqlliteModel.TblTxnList)
			txn.CusId = req.Id
			txn.Name = req.Name
			txn.TxnTime = req.TxnTime
			txn.Type = req.Type
			txn.SenderWalletAddress = req.FromAddress
			txn.RecieverWalletAddress = req.ToAddress
			txn.Currency = req.Currency
			txn.Amount = req.Amount
			txn.Count = req.Count
			txn.Hash = req.Hash
			txn.KeyRet = uuid.New().String()

			err = sqllite.TxnListCollectionCol.Insert(txn)
			if err != nil {
				fmt.Printf("insert db error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("insert db error"))
				return
			}

			rsp := new(createTxnRsp)
			rsp.RespDesc = "success"
			rsp.RespCode = "0000"
			rsp.Key = txn.KeyRet
			rspMsg, _ := json.Marshal(rsp)
			fmt.Printf("rspMsg:%s", rspMsg)

			w.WriteHeader(http.StatusOK)
			w.Write(rspMsg)
			go func() {
				flushTxn(r, req, txn.KeyRet)
			}()
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
			if respM.StatusCode != 200 {
				fmt.Printf("http error:%s", err)
				w.WriteHeader(respM.StatusCode)
				w.Write([]byte("not found"))
				return
			}
			fmt.Printf("resp Msg:%s", body)

			w.WriteHeader(http.StatusOK)
			w.Write(body)
		})

		r.HandleFunc("/query_txn_list", func(w http.ResponseWriter, r *http.Request) {

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
			req := new(queryTxnListReq)
			err = json.Unmarshal(reqMsg, req)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json Unmarshal error"))
				fmt.Printf("json Unmarshal error:%s", err)
				return
			}

			query := new(sqlliteModel.TblTxnList)
			query.CusId = req.Id
			query.Name = req.Name
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

		r.HandleFunc("/action", func(w http.ResponseWriter, r *http.Request) {

			w.Header().Set("Access-Control-Allow-Origin", "*")
			reqMsg, err := ioutil.ReadAll(r.Body)
			if err != nil {
				fmt.Printf("read request error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("read requesterror"))
				return
			}
			fmt.Printf("action req msg:%s\n", reqMsg)

			req := new(actionReq)
			err = json.Unmarshal(reqMsg, req)
			if err != nil {
				fmt.Printf("json unmarshal error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("read requesterror"))
				return
			}

			txn := new(sqlliteModel.TblTxnList)
			txn.Status = req.Operation
			err = sqllite.TxnListCollectionCol.UpdateByKeyRet(req.Key, txn)
			if err != nil {
				fmt.Printf("txn not found error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("txn not found"))
				return
			}

			rsp := new(queryTxnList)
			rsp.RespDesc = "success"
			rsp.RespCode = "0000"
			rspMsg, _ := json.Marshal(rsp)
			fmt.Printf("action txn list resp:%s", rspMsg)
			w.WriteHeader(http.StatusOK)
			w.Write(rspMsg)
		})

		r.HandleFunc("/query_txn_detail", func(w http.ResponseWriter, r *http.Request) {

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

		r.HandleFunc("/add_kyc", func(w http.ResponseWriter, r *http.Request) {

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
			bindAddr.Address = req.WalletAddress
			// bindAddr.Net = req.Net
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
			kycInfo.WalletAddress = req.WalletAddress
			kycInfo.Currency = req.Currency
			kycInfo.Type = req.Type
			kycInfo.CertificateID = req.CertificateID
			kycInfo.Address = req.Address
			kycInfo.Name = req.Name
			kycInfo.IdentifyInfo = req.IdentifyInfo
			kycInfo.KycId = req.Id
			kycInfo.Date = req.Date
			kycInfo.CreateTime = time.Now()
			kycInfo.UpdateTime = time.Now()
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

		r.HandleFunc("/query_kyc_list", func(w http.ResponseWriter, r *http.Request) {

			w.Header().Set("Access-Control-Allow-Origin", "*")
			// 读请求报文
			reqMsg, err := ioutil.ReadAll(r.Body)
			if err != nil {
				fmt.Printf("read request error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("read request error"))
				return
			}
			fmt.Printf("query kyc list req msg:%s\n", reqMsg)

			// 解包
			req := new(queryKycListReq)
			err = json.Unmarshal(reqMsg, req)
			if err != nil {
				fmt.Printf("json Unmarshal error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json Unmarshal error"))
				return
			}

			kycList, err := sqllite.KycListCollectionCol.SelectAll(req.Id, req.Name, req.Type, req.Currency, req.TimeStart, req.TimeEnd)
			if err != nil {
				fmt.Printf("kyc not found error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("kyc not found"))
				return
			}

			rsp := new(queryKycListRsp)
			rsp.RespDesc = "success"
			rsp.RespCode = "0000"

			rsp.KycList = make([]*KycList, 0)
			for _, record := range kycList {
				kyc := new(KycList)
				kyc.Id = record.KycId
				kyc.Name = record.Name
				kyc.Type = record.Type
				kyc.Currency = record.Currency
				kyc.WalletAddress = record.WalletAddress
				kyc.CreateTime = record.CreateTime.Format("2006-01-02 15:03:04")
				rsp.KycList = append(rsp.KycList, kyc)
			}
			rspMsg, _ := json.Marshal(rsp)
			fmt.Printf("query kyc list resp:%s", rspMsg)
			w.WriteHeader(http.StatusOK)
			w.Write(rspMsg)
		})

		r.HandleFunc("/query_kyc_detail", func(w http.ResponseWriter, r *http.Request) {

			w.Header().Set("Access-Control-Allow-Origin", "*")
			// 读请求报文
			reqMsg, err := ioutil.ReadAll(r.Body)
			if err != nil {
				fmt.Printf("read request error:%s\n", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("read request error"))
				return
			}
			fmt.Printf("query kyc detail req msg:%s\n", reqMsg)

			// 解包
			req := new(queryKycDetailReq)
			err = json.Unmarshal(reqMsg, req)
			if err != nil {
				fmt.Printf("json Unmarshal error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("json Unmarshal error"))
				return
			}

			kycInfo, err := sqllite.KycListCollectionCol.Select(req.Currency, req.WalletAddress)
			if err != nil {
				fmt.Printf("kyc not found error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("kyc not found"))
				return
			}

			rsp := new(queryKycDetailRsp)
			rsp.RespDesc = "success"
			rsp.RespCode = "0000"

			rsp.Currency = kycInfo.Currency
			rsp.Name = kycInfo.Name
			rsp.WalletAddress = kycInfo.WalletAddress
			rsp.Address = kycInfo.Address
			rsp.Id = kycInfo.KycId
			rsp.Date = kycInfo.Date
			rsp.Type = kycInfo.Type
			rsp.CertificateID = kycInfo.CertificateID
			rsp.CreateTime = kycInfo.CreateTime.Format("2006-01-02 15:03:04")

			rspMsg, _ := json.Marshal(rsp)
			fmt.Printf("query kyc detail resp:%s", rspMsg)
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
			//	queryVaspReq.Net = txnInfo.Net
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

			txnInfo.Hash = req.Hash
			err = sqllite.TxnListCollectionCol.Update(req.Key, txnInfo)
			if err != nil {
				fmt.Printf("update db error:%s", err)
				w.WriteHeader(http.StatusBadGateway)
				w.Write([]byte("update db error"))
				return
			}

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

const (
	txnFail           = "F"
	gap               = 5
	checkAddressOK    = "0"
	exchangeCaOK      = "1"
	SecurityConnectOK = "2"
	SendKycOK         = "3"
	RecKycOK          = "4"
)

func flushTxn(r *http.Request, req *createTxnReq, key string) {
	// 判断提现地址是否在Trisa体系内
	time.Sleep(time.Second * gap)
	txn := new(sqlliteModel.TblTxnList)
	err := checkAddress(req.Currency, req.ToAddress)
	if err != nil {
		txn.Status = txnFail
		sqllite.TxnListCollectionCol.UpdateByKeyRet(key, txn)
		return
	}
	txn.Status = checkAddressOK
	sqllite.TxnListCollectionCol.UpdateByKeyRet(key, txn)

	//CA证书交换
	time.Sleep(time.Second * gap)
	destUrl, err := getDestVasp(req.Currency, req.ToAddress)
	if err != nil {
		txn.Status = txnFail
		sqllite.TxnListCollectionCol.UpdateByKeyRet(key, txn)
		return
	}
	txn.Status = exchangeCaOK
	sqllite.TxnListCollectionCol.UpdateByKeyRet(key, txn)

	//加密通道构建
	time.Sleep(time.Second * gap)
	txn.Status = SecurityConnectOK
	sqllite.TxnListCollectionCol.UpdateByKeyRet(key, txn)

	//发送Kyc
	time.Sleep(time.Second * gap)
	txnr, err := exchangeKyc(r, req, destUrl)
	if err != nil {
		txn.Status = txnFail
		sqllite.TxnListCollectionCol.UpdateByKeyRet(key, txn)
	}
	txn.Status = SendKycOK
	sqllite.TxnListCollectionCol.UpdateByKeyRet(key, txn)

	//接收kyc
	time.Sleep(time.Second * gap)
	txnr.Status = RecKycOK
	sqllite.TxnListCollectionCol.UpdateByKeyRet(key, txnr)
}

type checkAddressReq struct {
	Currency string `json:"currency,omitempty"`
	Net      string `json:"net,omitempty"`
	Address  string `json:"address,omitempty"`
}

func checkAddress(currency, address string) error {
	url := gCenterUrl + "/v0/api/trisacenter/check_address"
	req := new(checkAddressReq)
	req.Currency = currency
	req.Address = address
	reqMsg, _ := json.Marshal(req)
	respM, err := http.Post(url, "application/json", strings.NewReader(string(reqMsg)))
	if err != nil {
		fmt.Printf("http post error:%s", err)
		return err
	}

	body, err := ioutil.ReadAll(respM.Body)
	if err != nil {
		fmt.Printf("http read error:%s", err)
		return err
	}
	defer respM.Body.Close()
	if respM.StatusCode != 200 {
		fmt.Printf("http error:%s", err)
		return err
	}
	fmt.Printf("resp Msg:%s", body)
	return nil
}

func getDestVasp(currency, address string) (string, error) {
	url := gCenterUrl + "/v0/api/trisacenter/get_vasp"
	queryVaspReq := new(queryVaspReq)
	queryVaspReq.Currency = currency
	queryVaspReq.Address = address
	queryVaspReqMsg, _ := json.Marshal(queryVaspReq)
	respM, err := http.Post(url, "application/json", strings.NewReader(string(queryVaspReqMsg)))
	if err != nil {
		fmt.Printf("http post error:%s", err)
		return "", err
	}

	body, err := ioutil.ReadAll(respM.Body)
	if err != nil {
		fmt.Printf("http read error:%s", err)
		return "", err
	}
	defer respM.Body.Close()

	queryVaspRsp := new(queryVaspRsp)
	err = json.Unmarshal(body, queryVaspRsp)
	if err != nil {
		fmt.Printf("json unmarshal error:%s", err)
		return "", err
	}
	return queryVaspRsp.Url, nil
}

func exchangeKyc(r *http.Request, req *createTxnReq, url string) (*sqlliteModel.TblTxnList, error) {
	identity, _ := ptypes.MarshalAny(&querykyc.Data{
		Currency: req.Currency,
		Net:      "",
		Address:  req.ToAddress,
	})

	kyc, err := sqllite.KycListCollectionCol.Select(req.Currency, req.FromAddress)
	if err != nil {
		fmt.Printf("query kyc not found err:%s\n", err)
		return nil, err
	}

	data, _ := ptypes.MarshalAny(&querykyc.Data{
		Currency:      req.Currency,
		Net:           "",
		Address:       req.ToAddress,
		Amount:        req.Amount,
		Name:          kyc.Name,
		WalletAddress: kyc.WalletAddress,
		Id:            kyc.KycId,
		Date:          kyc.Date,
		IdentifyInfo:  kyc.IdentifyInfo,
		TxnId:         req.Id,
		Count:         req.Count,
		TxnDate:       req.TxnTime,
	})

	tData := &pb.TransactionData{
		Identity: identity,
		Data:     data,
	}

	fmt.Printf("url:%s\n", url)
	resp, err := gPSever.SendRequest(r.Context(), url, uuid.New().String(), tData)
	if err != nil {
		fmt.Printf("send request error:%s", err)
		return nil, err
	}
	fmt.Printf("last resp:%s", resp)

	txn := new(sqlliteModel.TblTxnList)
	txn.CusId = req.Id
	txn.Name = req.Name
	txn.TxnTime = req.TxnTime
	txn.Type = req.Type
	txn.SenderWalletAddress = req.FromAddress
	txn.RecieverWalletAddress = req.ToAddress
	txn.Currency = req.Currency
	txn.Amount = req.Amount
	txn.Count = req.Count
	txn.Hash = req.Hash
	txn.KeyRet = uuid.New().String()

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

	return txn, nil
}
