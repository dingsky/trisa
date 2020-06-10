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

func (a *kycListCollection) Delete(address string) error {
	serv := new(sqlliteModel.TblKycList)
	return Database.Where("wallet_address = ?", address).Delete(serv).Error
}

func (a *kycListCollection) Update(serv *sqlliteModel.TblKycList) error {
	return Database.Save(serv).Error
}

func (a *kycListCollection) Select(wallet_address string) (*sqlliteModel.TblKycList, error) {
	serv := new(sqlliteModel.TblKycList)
	result := Database.Where("wallet_address = ?", wallet_address).First(serv)
	return serv, result.Error
}
