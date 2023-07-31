package handlers

import (
	"net/http"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk/gsk"
)

func (h *authenticationHandler) GetUserList(gc *gsk.Context) {
	limit := gc.QueryParam("limit")
	offset := gc.QueryParam("offset")

	limitInt, offsetInt, err := transport.ParseLimitAndOffset(limit, offset)
	if err != nil {
		gc.Status(400).JSONResponse(gsk.Map{
			"error": err.Error(),
		})
		return
	}

	userList, err := h.userService.GetUserList(limitInt, offsetInt)
	if err != nil {
		gc.Status(500).JSONResponse(gsk.Map{
			"error": "internal server error",
		})
		return
	}
	userCount, err := h.userService.GetTotalUsersCount()
	if err != nil {
		gc.Status(500).JSONResponse(gsk.Map{
			"error": "internal server error",
		})
	}

	userListRespone := transport.UserListResponse{
		Data:  make([]transport.UserResponse, len(userList)),
		Total: userCount,
	}
	for i, user := range userList {
		userListRespone.Data[i] = transport.UserResponse{
			ID:        user.ID.String(),
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		}
	}

	if err != nil {
		gc.Status(500).JSONResponse(gsk.Map{
			"error": "internal server error",
		})
		return
	}

	gc.Status(200).JSONResponse(userListRespone)
}

func (h *authenticationHandler) CreateGroup(gc *gsk.Context) {
	var group *entities.Group

	err := gc.DecodeJSONBody(&group)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_BODY,
		})
		return
	}

	createdGroup, err := h.userService.CreateGroup(group)
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

func (h *authenticationHandler) GetUserDetails(gc *gsk.Context) {
	gc.Status(http.StatusNotImplemented).JSONResponse(gsk.Map{
		"message": "not implemented",
	})
}
