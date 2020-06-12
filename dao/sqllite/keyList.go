package sqllite

import (
	"github.com/trisacrypto/trisa/model/sqlliteModel"
)

type kycListCollection struct {
}

var KycListCollectionCol = new(kycListCollection)

func (a *kycListCollection) Insert(serv *sqlliteModel.TblKycList) error {
	return Database.Create(serv).Error
}

func (a *kycListCollection) Delete(currency, net, address string) error {
	serv := new(sqlliteModel.TblKycList)
	return Database.Where("currency = ? net = ? wallet_address = ?", currency, net, address).Delete(serv).Error
}

func (a *kycListCollection) Update(serv *sqlliteModel.TblKycList) error {
	return Database.Save(serv).Error
}

func (a *kycListCollection) Select(currency, net, address string) (*sqlliteModel.TblKycList, error) {
	serv := new(sqlliteModel.TblKycList)
	result := Database.Where("currency = ? net = ? wallet_address = ?", currency, net, address).First(serv)
	return serv, result.Error
}
