package handlers

import (
	"net/http"

	"github.com/adharshmk96/stk-auth/pkg/entities/ds"

	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk/gsk"
)

func (h *adminHandler) GetAccountList(gc *gsk.Context) {
	limit := gc.QueryParam("limit")
	offset := gc.QueryParam("offset")

	limitInt, offsetInt, err := transport.ParseLimitAndOffset(limit, offset)
	if err != nil {
		gc.Status(400).JSONResponse(gsk.Map{
			"error": err.Error(),
		})
		return
	}

	accountList, err := h.authService.GetAccountList(limitInt, offsetInt)
	if err != nil {
		gc.Status(500).JSONResponse(gsk.Map{
			"error": "internal server error",
		})
		return
	}
	accountCount, err := h.authService.GetTotalAccountsCount()
	if err != nil {
		gc.Status(500).JSONResponse(gsk.Map{
			"error": "internal server error",
		})
	}

	accountListRespone := transport.AccountListResponse{
		Data:  make([]transport.AccountResponse, len(accountList)),
		Total: accountCount,
	}
	for i, account := range accountList {
		accountListRespone.Data[i] = transport.AccountResponse{
			ID:        account.ID.String(),
			Username:  account.Username,
			Email:     account.Email,
			CreatedAt: account.CreatedAt,
			UpdatedAt: account.UpdatedAt,
		}
	}

	if err != nil {
		gc.Status(500).JSONResponse(gsk.Map{
			"error": "internal server error",
		})
		return
	}

	gc.Status(200).JSONResponse(accountListRespone)
}

func (h *adminHandler) GetAccountDetails(gc *gsk.Context) {
	accountID := gc.QueryParam("uid")
	if accountID == "" {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_USER_ID,
		})
		return
	}

	parsedAccountID, err := ds.ParseAccountId(accountID)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_USER_ID,
		})
		return
	}

	account, err := h.authService.GetAccountDetails(parsedAccountID)
	if err != nil {
		transport.HandleGetAccountError(err, gc)
		return
	}

	response := transport.AccountResponse{
		ID:        account.ID.String(),
		Username:  account.Username,
		Email:     account.Email,
		CreatedAt: account.CreatedAt,
		UpdatedAt: account.UpdatedAt,
	}

	gc.Status(http.StatusOK).JSONResponse(response)
}

func (h *adminHandler) CreateGroup(gc *gsk.Context) {
	var group *ds.Group

	err := gc.DecodeJSONBody(&group)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_BODY,
		})
		return
	}

	createdGroup, err := h.authService.CreateGroup(group)
	if err != nil {
		transport.HandleCreateGroupError(err, gc)
		return
	}

	response := transport.GroupResponse{
		ID:          createdGroup.ID,
		Name:        createdGroup.Name,
		Description: createdGroup.Description,
		CreatedAt:   createdGroup.CreatedAt,
		UpdatedAt:   createdGroup.UpdatedAt,
	}

	gc.Status(http.StatusCreated).JSONResponse(response)
}
