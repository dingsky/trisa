package sqllite

import (
	"testing"
	"time"

	"github.com/trisacrypto/trisa/model/sqlliteModel"

	"gitlab.devops.wx/blockchains/baseutil/log"
)

const (
	testId   = "12345678"
	testType = "business"
	testUrl  = "127.0.0.1:8888"
	testUrl1 = "127.0.0.1:8889"
	testCity = "shanghai"
)

func TestInsertServList(t *testing.T) {
	serv := new(sqlliteModel.TblServList)
	serv.ID = testId
	serv.Type = testType
	serv.Address = testCity
	serv.Url = testUrl
	serv.CreateTime = time.Now()
	serv.UpdateTime = time.Now()

	if err := ServListCollectionCol.Insert(serv); err != nil {
		log.Errorf("Insert error:%s", err)
		t.Fail()
		return
	}
	log.Infof("Insert OK data is %v", serv)
}

func TestUpdateServList(t *testing.T) {
	serv := new(sqlliteModel.TblServList)
	serv.ID = testId
	serv.Type = testType
	serv.Address = testCity
	serv.Url = testUrl1
	serv.UpdateTime = time.Now()

	if err := ServListCollectionCol.Update(serv); err != nil {
		log.Errorf("Update error:%s", err)
		t.Fail()
		return
	}
	log.Infof("Update OK data is %v", serv)
}

func TestDeleteServList(t *testing.T) {

	if err := ServListCollectionCol.Delete(testId); err != nil {
		log.Errorf("Delete error:%s", err)
		t.Fail()
		return
	}
	log.Infof("Delete OK")
}

func TestSelectServList(t *testing.T) {

	serv, err := ServListCollectionCol.Select(testId)
	if err != nil {
		log.Errorf("Select error:%s", err)
		t.Fail()
		return
	}
	log.Infof("Select OK result is %v", serv)
}
