package sqllite

import (
	"testing"
	"time"

	"github.com/trisacrypto/trisa/model/sqlliteModel"

	"gitlab.devops.wx/blockchains/baseutil/log"
)

const (
	testAddressId = "12345678"
	testAddress   = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
	testAddress1  = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
	testNet       = "bitcoin"
	testCurrency  = "btc"
)

func TestInsertAddressList(t *testing.T) {
	address := new(sqlliteModel.TblAddressList)
	address.ServID = testAddressId
	address.Address = testAddress
	address.Net = testNet
	address.Currency = testCurrency
	address.CreateTime = time.Now()
	address.UpdateTime = time.Now()

	if err := AddressListCollectionCol.Insert(address); err != nil {
		log.Errorf("Insert error:%s", err)
		t.Fail()
		return
	}
	log.Infof("Insert OK data is %v", address)
}

func TestUpdateAddressList(t *testing.T) {
	address := new(sqlliteModel.TblAddressList)
	address.ServID = testAddressId
	address.Address = testAddress1
	address.Net = testNet
	address.Currency = testCurrency
	address.UpdateTime = time.Now()

	if err := AddressListCollectionCol.Update(address); err != nil {
		log.Errorf("Update error:%s", err)
		t.Fail()
		return
	}
	log.Infof("Update OK data is %v", address)
}

func TestDeleteAddressList(t *testing.T) {

	if err := AddressListCollectionCol.Delete(testAddressId); err != nil {
		log.Errorf("Delete error:%s", err)
		t.Fail()
		return
	}
	log.Infof("Delete OK")
}

func TestSelectAddressList(t *testing.T) {

	address, err := AddressListCollectionCol.Select(testAddressId)
	if err != nil {
		log.Errorf("Select error:%s", err)
		t.Fail()
		return
	}
	log.Infof("Select OK result is %v", address)
}

func TestSelectAddressListByAddress(t *testing.T) {

	address, err := AddressListCollectionCol.SelectByAddress(testAddress)
	if err != nil {
		log.Errorf("Select error:%s", err)
		t.Fail()
		return
	}
	log.Infof("Select OK result is %v", address)
}
